package dev.hydro.j2c.preprocess;

import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Strips debug metadata and encrypts string/numeric constants in residual Java bytecode
 * (startup classes, <init>/<clinit> stubs, interfaces, @NotNative/partial methods, and HLoader)
 * so virtually zero readable secrets remain anywhere in class constant pools.
 */
public final class JavaPreHardener implements Opcodes {

    public static void stripDebugInfo(ClassNode cn) {
        cn.sourceFile = null;
        cn.sourceDebug = null;
        if (cn.methods == null) return;
        for (MethodNode mn : cn.methods) {
            mn.localVariables = null;
            mn.parameters = null;
            if ((mn.access & (ACC_PRIVATE | ACC_SYNTHETIC)) == (ACC_PRIVATE | ACC_SYNTHETIC)) {
                mn.signature = null;
            }
            if (mn.instructions != null) {
                for (AbstractInsnNode cur = mn.instructions.getFirst(); cur != null; ) {
                    AbstractInsnNode next = cur.getNext();
                    if (cur instanceof LineNumberNode) {
                        mn.instructions.remove(cur);
                    }
                    cur = next;
                }
            }
        }
    }

    public static void hardenResidualBytecode(ClassNode cn, Random rng) {
        if (cn == null || cn.methods == null || (cn.access & (ACC_ANNOTATION | ACC_MODULE)) != 0) return;

        boolean isInterface = (cn.access & ACC_INTERFACE) != 0;
        int classVer = cn.version & 0xFFFF;
        int decAccess = (isInterface && classVer < V9)
                ? (ACC_PUBLIC | ACC_STATIC | ACC_SYNTHETIC)
                : (ACC_PRIVATE | ACC_STATIC | ACC_SYNTHETIC);

        String decName = generateUniqueMethodName(cn, "d_", rng);
        int clsSalt = rng.nextInt() | 1;
        boolean encodedAnyString = false;

        for (MethodNode mn : new ArrayList<>(cn.methods)) {
            if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) continue;
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (mn.instructions.size() > 3500) continue;

            for (AbstractInsnNode cur = mn.instructions.getFirst(); cur != null; ) {
                AbstractInsnNode next = cur.getNext();
                int op = cur.getOpcode();

                if (cur instanceof LdcInsnNode ldc) {
                    if (ldc.cst instanceof String s && !s.isEmpty() && s.length() < 16384) {
                        int callKey = rng.nextInt();
                        String scrambled = scrambleString(s, callKey, clsSalt);
                        InsnList rep = new InsnList();
                        rep.add(new LdcInsnNode(scrambled));
                        rep.add(pushInt(callKey));
                        rep.add(new MethodInsnNode(INVOKESTATIC, cn.name, decName, "(Ljava/lang/String;I)Ljava/lang/String;", isInterface));
                        mn.instructions.insertBefore(cur, rep);
                        mn.instructions.remove(cur);
                        encodedAnyString = true;
                    } else if (ldc.cst instanceof Integer iv) {
                        int k = rng.nextInt();
                        InsnList rep = new InsnList();
                        rep.add(pushInt(iv ^ k));
                        rep.add(pushInt(k));
                        rep.add(new InsnNode(IXOR));
                        mn.instructions.insertBefore(cur, rep);
                        mn.instructions.remove(cur);
                    } else if (ldc.cst instanceof Long lv) {
                        long k = rng.nextLong();
                        InsnList rep = new InsnList();
                        rep.add(new LdcInsnNode(lv ^ k));
                        rep.add(new LdcInsnNode(k));
                        rep.add(new InsnNode(LXOR));
                        mn.instructions.insertBefore(cur, rep);
                        mn.instructions.remove(cur);
                    }
                } else if (cur instanceof IntInsnNode iin && (op == BIPUSH || op == SIPUSH)) {
                    int k = rng.nextInt();
                    InsnList rep = new InsnList();
                    rep.add(pushInt(iin.operand ^ k));
                    rep.add(pushInt(k));
                    rep.add(new InsnNode(IXOR));
                    mn.instructions.insertBefore(cur, rep);
                    mn.instructions.remove(cur);
                } else if (op >= ICONST_2 && op <= ICONST_5) {
                    int val = op - ICONST_0;
                    int k = rng.nextInt();
                    InsnList rep = new InsnList();
                    rep.add(pushInt(val ^ k));
                    rep.add(pushInt(k));
                    rep.add(new InsnNode(IXOR));
                    mn.instructions.insertBefore(cur, rep);
                    mn.instructions.remove(cur);
                }
                cur = next;
            }
            if (mn.maxStack > 0) mn.maxStack += 4;
        }

        if (encodedAnyString) {
            cn.methods.add(buildStringDecoderMethod(decName, decAccess, clsSalt));
        }
    }

    private static String scrambleString(String plain, int key, int clsSalt) {
        char[] out = plain.toCharArray();
        for (int i = 0; i < out.length; i++) {
            int mask = (key ^ (clsSalt + i * 131)) & 0xFFFF;
            out[i] = (char) (out[i] ^ mask);
        }
        return new String(out);
    }

    private static MethodNode buildStringDecoderMethod(String name, int access, int clsSalt) {
        MethodNode mv = new MethodNode(access, name, "(Ljava/lang/String;I)Ljava/lang/String;", null, null);
        mv.visitCode();
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
        mv.visitVarInsn(ASTORE, 2);
        mv.visitInsn(ICONST_0);
        mv.visitVarInsn(ISTORE, 3);

        Label lCheck = new Label(), lDone = new Label();
        mv.visitLabel(lCheck);
        mv.visitVarInsn(ILOAD, 3);
        mv.visitVarInsn(ALOAD, 2);
        mv.visitInsn(ARRAYLENGTH);
        mv.visitJumpInsn(IF_ICMPGE, lDone);

        mv.visitVarInsn(ALOAD, 2);
        mv.visitVarInsn(ILOAD, 3);
        mv.visitInsn(DUP2);
        mv.visitInsn(CALOAD);
        mv.visitVarInsn(ILOAD, 1);
        mv.visitLdcInsn(clsSalt);
        mv.visitVarInsn(ILOAD, 3);
        mv.visitIntInsn(SIPUSH, 131);
        mv.visitInsn(IMUL);
        mv.visitInsn(IADD);
        mv.visitInsn(IXOR);
        mv.visitLdcInsn(0xFFFF);
        mv.visitInsn(IAND);
        mv.visitInsn(IXOR);
        mv.visitInsn(I2C);
        mv.visitInsn(CASTORE);

        mv.visitIincInsn(3, 1);
        mv.visitJumpInsn(GOTO, lCheck);

        mv.visitLabel(lDone);
        mv.visitTypeInsn(NEW, "java/lang/String");
        mv.visitInsn(DUP);
        mv.visitVarInsn(ALOAD, 2);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
        mv.visitInsn(ARETURN);
        mv.visitMaxs(6, 4);
        mv.visitEnd();
        return mv;
    }

    private static AbstractInsnNode pushInt(int v) {
        if (v >= -1 && v <= 5) return new InsnNode(ICONST_0 + v);
        if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) return new IntInsnNode(BIPUSH, v);
        if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) return new IntInsnNode(SIPUSH, v);
        return new LdcInsnNode(v);
    }

    private static String generateUniqueMethodName(ClassNode cn, String prefix, Random rng) {
        Set<String> used = Set.of();
        if (cn.methods != null) {
            used = new java.util.HashSet<>();
            for (MethodNode m : cn.methods) used.add(m.name);
        }
        String candidate;
        do {
            candidate = prefix + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFFFL, 36);
        } while (used.contains(candidate));
        return candidate;
    }
}
