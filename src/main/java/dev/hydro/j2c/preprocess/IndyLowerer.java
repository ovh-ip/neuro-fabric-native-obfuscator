package dev.hydro.j2c.preprocess;

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.JSRInlinerAdapter;
import org.objectweb.asm.tree.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Normalizes JSR/RET subroutines and lowers non-StringConcat invokedynamic / condy
 * instructions into synthetic class-local helper methods so MethodHandles.lookup() retains
 * exact nest/class privileges while the calling method and lambda target bodies become native C++.
 */
public final class IndyLowerer {

    public static void lowerClass(ClassNode cn, Set<MethodNode> nonNativeHelpers, Set<MethodNode> eligibleFilter) {
        boolean isInterface = (cn.access & Opcodes.ACC_INTERFACE) != 0;
        int helperAccess = (isInterface && (cn.version & 0xFFFF) < Opcodes.V9)
                ? (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC)
                : (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC);

        List<MethodNode> generatedHelpers = new ArrayList<>();
        int indySeq = 0;
        int condySeq = 0;
        int polySeq = 0;

        for (int mIdx = 0; mIdx < cn.methods.size(); mIdx++) {
            MethodNode mn = cn.methods.get(mIdx);
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if (eligibleFilter != null && !eligibleFilter.contains(mn)) continue;

            // Inline legacy JSR/RET if present
            if (hasJsr(mn)) {
                MethodNode inlined = new MethodNode(mn.access, mn.name, mn.desc, mn.signature,
                        mn.exceptions != null ? mn.exceptions.toArray(new String[0]) : null);
                inlined.visibleAnnotations = mn.visibleAnnotations;
                inlined.invisibleAnnotations = mn.invisibleAnnotations;
                inlined.visibleParameterAnnotations = mn.visibleParameterAnnotations;
                inlined.invisibleParameterAnnotations = mn.invisibleParameterAnnotations;
                inlined.annotationDefault = mn.annotationDefault;
                JSRInlinerAdapter adapter = new JSRInlinerAdapter(inlined, mn.access, mn.name, mn.desc, mn.signature,
                        mn.exceptions != null ? mn.exceptions.toArray(new String[0]) : null);
                mn.accept(adapter);
                cn.methods.set(mIdx, inlined);
                if (eligibleFilter != null) eligibleFilter.add(inlined);
                mn = inlined;
            }

            if (nonNativeHelpers.contains(mn)) continue;

            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    if (!isStringConcat(indy)) {
                        String helperName = "$hy_i_" + (indySeq++);
                        MethodNode helper = new MethodNode(helperAccess, helperName, indy.desc, null, null);
                        Type mt = Type.getMethodType(indy.desc);
                        int slot = 0;
                        for (Type arg : mt.getArgumentTypes()) {
                            helper.instructions.add(new VarInsnNode(arg.getOpcode(Opcodes.ILOAD), slot));
                            slot += arg.getSize();
                        }
                        helper.instructions.add(new InvokeDynamicInsnNode(indy.name, indy.desc, indy.bsm, indy.bsmArgs));
                        helper.instructions.add(new InsnNode(mt.getReturnType().getOpcode(Opcodes.IRETURN)));
                        helper.maxStack = Math.max(4, slot + 2);
                        helper.maxLocals = Math.max(1, slot);
                        generatedHelpers.add(helper);
                        nonNativeHelpers.add(helper);

                        mn.instructions.set(insn, new MethodInsnNode(
                                Opcodes.INVOKESTATIC, cn.name, helperName, indy.desc, isInterface));
                    }
                } else if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof ConstantDynamic cd) {
                    String helperName = "$hy_c_" + (condySeq++);
                    Type retType = Type.getType(cd.getDescriptor());
                    String helperDesc = "()" + cd.getDescriptor();
                    MethodNode helper = new MethodNode(helperAccess, helperName, helperDesc, null, null);
                    helper.instructions.add(new LdcInsnNode(cd));
                    helper.instructions.add(new InsnNode(retType.getOpcode(Opcodes.IRETURN)));
                    helper.maxStack = Math.max(2, retType.getSize());
                    helper.maxLocals = 0;
                    generatedHelpers.add(helper);
                    nonNativeHelpers.add(helper);

                    mn.instructions.set(insn, new MethodInsnNode(
                            Opcodes.INVOKESTATIC, cn.name, helperName, helperDesc, isInterface));
                } else if (insn instanceof MethodInsnNode mi && isPolymorphicSignatureCall(mi)) {
                    String helperName = "$hy_mh_" + (polySeq++);
                    Type mt = Type.getMethodType(mi.desc);
                    Type[] origArgs = mt.getArgumentTypes();
                    Type[] fullArgs = new Type[origArgs.length + 1];
                    fullArgs[0] = Type.getObjectType(mi.owner);
                    System.arraycopy(origArgs, 0, fullArgs, 1, origArgs.length);
                    String helperDesc = Type.getMethodDescriptor(mt.getReturnType(), fullArgs);

                    MethodNode helper = new MethodNode(helperAccess, helperName, helperDesc, null, null);
                    int slot = 0;
                    for (Type arg : fullArgs) {
                        helper.instructions.add(new VarInsnNode(arg.getOpcode(Opcodes.ILOAD), slot));
                        slot += arg.getSize();
                    }
                    helper.instructions.add(new MethodInsnNode(mi.getOpcode(), mi.owner, mi.name, mi.desc, false));
                    helper.instructions.add(new InsnNode(mt.getReturnType().getOpcode(Opcodes.IRETURN)));
                    helper.maxStack = Math.max(4, slot + 2);
                    helper.maxLocals = Math.max(1, slot);
                    generatedHelpers.add(helper);
                    nonNativeHelpers.add(helper);

                    mn.instructions.set(insn, new MethodInsnNode(
                            Opcodes.INVOKESTATIC, cn.name, helperName, helperDesc, isInterface));
                }
                insn = next;
            }
        }
        cn.methods.addAll(generatedHelpers);
    }

    public static boolean isStringConcat(InvokeDynamicInsnNode indy) {
        return indy.bsm != null
                && "java/lang/invoke/StringConcatFactory".equals(indy.bsm.getOwner())
                && ("makeConcatWithConstants".equals(indy.bsm.getName()) || "makeConcat".equals(indy.bsm.getName()));
    }

    private static boolean isPolymorphicSignatureCall(MethodInsnNode mi) {
        if (mi.getOpcode() != Opcodes.INVOKEVIRTUAL) return false;
        if ("java/lang/invoke/MethodHandle".equals(mi.owner)) {
            return "invoke".equals(mi.name) || "invokeExact".equals(mi.name) || "invokeBasic".equals(mi.name);
        }
        return "java/lang/invoke/VarHandle".equals(mi.owner);
    }

    private static boolean hasJsr(MethodNode mn) {
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getOpcode() == Opcodes.JSR || insn.getOpcode() == Opcodes.RET) return true;
        }
        return false;
    }
}
