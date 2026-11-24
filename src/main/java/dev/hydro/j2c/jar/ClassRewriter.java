package dev.hydro.j2c.jar;

import dev.hydro.j2c.config.ObfuscationConfig;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Rewrites Java ClassNodes after J2C/VM compilation:
 * - Converts compiled methods to ACC_NATIVE and strips their bytecode
 * - Wraps/creates <clinit> to call HLoader.r(ThisClass.class, classId)
 * - Generates the per-build randomized HLoader bootstrap class (embedded encrypted DLL or external DLL)
 * - Uses a hierarchy-aware ClassWriter so missing Minecraft/Fabric classpath types never crash frame computation
 */
public final class ClassRewriter implements Opcodes {

    public static final class SafeClassWriter extends ClassWriter {
        private final Map<String, ClassNode> classMap;

        public SafeClassWriter(int flags, Map<String, ClassNode> classMap) {
            super(flags);
            this.classMap = classMap;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            if ("java/lang/Object".equals(type1) || "java/lang/Object".equals(type2)) return "java/lang/Object";
            if (type1.equals(type2)) return type1;

            Set<String> parents1 = new LinkedHashSet<>();
            String cur = type1;
            while (cur != null) {
                parents1.add(cur);
                ClassNode cn = classMap.get(cur);
                if (cn != null) {
                    cur = cn.superName;
                } else {
                    try {
                        Class<?> c = Class.forName(cur.replace('/', '.'), false, ClassRewriter.class.getClassLoader());
                        Class<?> sc = c.getSuperclass();
                        cur = sc != null ? sc.getName().replace('.', '/') : null;
                    } catch (Throwable t) {
                        cur = null;
                    }
                }
            }
            cur = type2;
            while (cur != null) {
                if (parents1.contains(cur)) return cur;
                ClassNode cn = classMap.get(cur);
                if (cn != null) {
                    cur = cn.superName;
                } else {
                    try {
                        Class<?> c = Class.forName(cur.replace('/', '.'), false, ClassRewriter.class.getClassLoader());
                        Class<?> sc = c.getSuperclass();
                        cur = sc != null ? sc.getName().replace('.', '/') : null;
                    } catch (Throwable t) {
                        cur = null;
                    }
                }
            }
            return "java/lang/Object";
        }
    }

    public static void makeMethodNative(MethodNode mn) {
        mn.access = (mn.access & ~ACC_ABSTRACT) | ACC_NATIVE;
        mn.instructions = new InsnList();
        mn.tryCatchBlocks = new ArrayList<>();
        mn.localVariables = null;
        mn.parameters = null;
        mn.maxStack = 0;
        mn.maxLocals = 0;
    }

    public static void injectClassRegistration(ClassNode cn, int classId, String loaderInternalName, String regMethodName) {
        MethodNode clinit = null;
        for (MethodNode m : cn.methods) {
            if ("<clinit>".equals(m.name) && "()V".equals(m.desc)) {
                clinit = m;
                break;
            }
        }
        InsnList prefix = new InsnList();
        prefix.add(new LdcInsnNode(Type.getObjectType(cn.name)));
        prefix.add(new LdcInsnNode(classId));
        prefix.add(new MethodInsnNode(INVOKESTATIC, loaderInternalName, regMethodName, "(Ljava/lang/Class;I)V", false));

        if (clinit == null) {
            clinit = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(prefix);
            clinit.instructions.add(new InsnNode(RETURN));
            clinit.maxStack = 2;
            clinit.maxLocals = 0;
            cn.methods.add(clinit);
        } else {
            clinit.instructions.insert(prefix);
            clinit.maxStack = Math.max(clinit.maxStack, 2);
        }
    }

    public static byte[] writeClass(ClassNode cn, Map<String, ClassNode> classMap) {
        try {
            ClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, classMap);
            cn.accept(cw);
            return cw.toByteArray();
        } catch (Throwable t) {
            // Fallback to COMPUTE_MAXS if a strange unmodified third-party frame edge occurs
            ClassWriter cw = new SafeClassWriter(ClassWriter.COMPUTE_MAXS, classMap);
            cn.accept(cw);
            return cw.toByteArray();
        }
    }

    /**
     * Generates the compact randomized HLoader class that loads the .dll from natives/ (or external path)
     * and invokes native verification + .fucked DefineClass unpacking.
     */
    public static byte[] generateLoaderClass(
            String loaderInternalName,
            String regMethodName,
            String verifyMethodName,
            String bootMethodName,
            String embeddedResPath,
            long dllKeySeed,
            ObfuscationConfig config) {

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC, loaderInternalName, null, "java/lang/Object", null);

        // public static native void r(Class<?> cls, int id)
        cw.visitMethod(ACC_PUBLIC | ACC_STATIC | ACC_NATIVE, regMethodName, "(Ljava/lang/Class;I)V", null, null).visitEnd();
        // private static native void v(ClassLoader cl)
        cw.visitMethod(ACC_PRIVATE | ACC_STATIC | ACC_NATIVE, verifyMethodName, "(Ljava/lang/ClassLoader;)V", null, null).visitEnd();

        // public static void b() {} - triggers <clinit> safely from @Mixin trampolines
        MethodVisitor bmv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, bootMethodName, "()V", null, null);
        bmv.visitCode();
        bmv.visitInsn(RETURN);
        bmv.visitMaxs(0, 0);
        bmv.visitEnd();

        // static initializer
        MethodVisitor mv = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        Label tryStart = new Label(), tryEnd = new Label(), tryHandler = new Label();
        mv.visitTryCatchBlock(tryStart, tryEnd, tryHandler, "java/lang/Throwable");

        mv.visitLabel(tryStart);
        if (config.isEmbedDll()) {
            // InputStream in = HLoader.class.getResourceAsStream("/" + embeddedResPath);
            mv.visitLdcInsn(Type.getObjectType(loaderInternalName));
            mv.visitLdcInsn("/" + embeddedResPath);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false);
            mv.visitVarInsn(ASTORE, 0); // in

            mv.visitVarInsn(ALOAD, 0);
            Label notNullIn = new Label();
            mv.visitJumpInsn(IFNONNULL, notNullIn);
            mv.visitTypeInsn(NEW, "java/lang/UnsatisfiedLinkError");
            mv.visitInsn(DUP);
            mv.visitLdcInsn("Missing native payload");
            mv.visitMethodInsn(INVOKESPECIAL, "java/lang/UnsatisfiedLinkError", "<init>", "(Ljava/lang/String;)V", false);
            mv.visitInsn(ATHROW);

            mv.visitLabel(notNullIn);
            // byte[] buf = in.readAllBytes(); in.close();
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/InputStream", "readAllBytes", "()[B", false);
            mv.visitVarInsn(ASTORE, 1); // buf
            mv.visitVarInsn(ALOAD, 0);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/InputStream", "close", "()V", false);

            if (config.isEncryptEmbeddedDll()) {
                mv.visitLdcInsn(dllKeySeed);
                mv.visitVarInsn(LSTORE, 2);
                mv.visitInsn(ICONST_0);
                mv.visitVarInsn(ISTORE, 4);
                Label loopCheck = new Label(), loopBody = new Label();
                mv.visitJumpInsn(GOTO, loopCheck);

                mv.visitLabel(loopBody);
                mv.visitVarInsn(LLOAD, 2);
                mv.visitLdcInsn(6364136223846793005L);
                mv.visitInsn(LMUL);
                mv.visitLdcInsn(1442695040888963407L);
                mv.visitInsn(LADD);
                mv.visitVarInsn(LSTORE, 2);

                mv.visitVarInsn(ALOAD, 1);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitInsn(DUP2);
                mv.visitInsn(BALOAD);
                mv.visitVarInsn(LLOAD, 2);
                mv.visitIntInsn(BIPUSH, 56);
                mv.visitInsn(LUSHR);
                mv.visitInsn(L2I);
                mv.visitInsn(IXOR);
                mv.visitInsn(I2B);
                mv.visitInsn(BASTORE);
                mv.visitIincInsn(4, 1);

                mv.visitLabel(loopCheck);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitVarInsn(ALOAD, 1);
                mv.visitInsn(ARRAYLENGTH);
                mv.visitJumpInsn(IF_ICMPLT, loopBody);
            }

            // File tmp = File.createTempFile("hy_", ".dll"); tmp.deleteOnExit();
            mv.visitLdcInsn("hy_");
            mv.visitLdcInsn(".dll");
            mv.visitMethodInsn(INVOKESTATIC, "java/io/File", "createTempFile", "(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;", false);
            mv.visitVarInsn(ASTORE, 5);
            mv.visitVarInsn(ALOAD, 5);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "deleteOnExit", "()V", false);

            // FileOutputStream fos = new FileOutputStream(tmp); fos.write(buf); fos.close();
            mv.visitTypeInsn(NEW, "java/io/FileOutputStream");
            mv.visitInsn(DUP);
            mv.visitVarInsn(ALOAD, 5);
            mv.visitMethodInsn(INVOKESPECIAL, "java/io/FileOutputStream", "<init>", "(Ljava/io/File;)V", false);
            mv.visitVarInsn(ASTORE, 6);
            mv.visitVarInsn(ALOAD, 6);
            mv.visitVarInsn(ALOAD, 1);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/FileOutputStream", "write", "([B)V", false);
            mv.visitVarInsn(ALOAD, 6);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/FileOutputStream", "close", "()V", false);

            // System.load(tmp.getAbsolutePath());
            mv.visitVarInsn(ALOAD, 5);
            mv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "load", "(Ljava/lang/String;)V", false);
        } else {
            // Load external DLL path (resolved relative to JAR directory if relative, or absolute)
            String dllSpec = (config.getExternalDllPath() != null && !config.getExternalDllPath().isBlank())
                    ? config.getExternalDllPath()
                    : config.getOutputDll().getFileName().toString();
            mv.visitLdcInsn(dllSpec);
            mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "resolveExt", "(Ljava/lang/String;)Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "load", "(Ljava/lang/String;)V", false);
        }

        // Call verify(HLoader.class.getClassLoader())
        mv.visitLdcInsn(Type.getObjectType(loaderInternalName));
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, verifyMethodName, "(Ljava/lang/ClassLoader;)V", false);

        mv.visitLabel(tryEnd);
        mv.visitInsn(RETURN);

        mv.visitLabel(tryHandler);
        mv.visitVarInsn(ASTORE, 0);
        mv.visitTypeInsn(NEW, "java/lang/ExceptionInInitializerError");
        mv.visitInsn(DUP);
        mv.visitVarInsn(ALOAD, 0);
        mv.visitMethodInsn(INVOKESPECIAL, "java/lang/ExceptionInInitializerError", "<init>", "(Ljava/lang/Throwable;)V", false);
        mv.visitInsn(ATHROW);
        mv.visitMaxs(4, 8);
        mv.visitEnd();

        if (!config.isEmbedDll()) {
            MethodVisitor rmv = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "resolveExt", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
            rmv.visitCode();
            // File f = new File(path); if (f.isAbsolute() || f.exists()) return f.getAbsolutePath();
            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitVarInsn(ALOAD, 0);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
            rmv.visitVarInsn(ASTORE, 1);
            rmv.visitVarInsn(ALOAD, 1);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "isAbsolute", "()Z", false);
            Label retAbs = new Label(), checkExists = new Label();
            rmv.visitJumpInsn(IFNE, retAbs);
            rmv.visitVarInsn(ALOAD, 1);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            rmv.visitJumpInsn(IFNE, retAbs);

            // Try relative to JAR code source parent
            Label tryCsStart = new Label(), tryCsEnd = new Label(), tryCsCatch = new Label();
            rmv.visitTryCatchBlock(tryCsStart, tryCsEnd, tryCsCatch, "java/lang/Throwable");
            rmv.visitLabel(tryCsStart);
            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitLdcInsn(Type.getObjectType(loaderInternalName));
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getProtectionDomain", "()Ljava/security/ProtectionDomain;", false);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/security/ProtectionDomain", "getCodeSource", "()Ljava/security/CodeSource;", false);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/security/CodeSource", "getLocation", "()Ljava/net/URL;", false);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/net/URL", "toURI", "()Ljava/net/URI;", false);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/net/URI;)V", false);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getParentFile", "()Ljava/io/File;", false);
            rmv.visitVarInsn(ASTORE, 2);
            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitVarInsn(ALOAD, 2);
            rmv.visitVarInsn(ALOAD, 0);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/io/File;Ljava/lang/String;)V", false);
            rmv.visitVarInsn(ASTORE, 3);
            rmv.visitVarInsn(ALOAD, 3);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            rmv.visitJumpInsn(IFEQ, tryCsEnd);
            rmv.visitVarInsn(ALOAD, 3);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            rmv.visitInsn(ARETURN);
            rmv.visitLabel(tryCsEnd);
            rmv.visitJumpInsn(GOTO, retAbs);
            rmv.visitLabel(tryCsCatch);
            rmv.visitInsn(POP);

            rmv.visitLabel(retAbs);
            rmv.visitVarInsn(ALOAD, 1);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            rmv.visitInsn(ARETURN);
            rmv.visitMaxs(4, 4);
            rmv.visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    public static byte[] encryptDllPayload(byte[] raw, long keySeed) {
        byte[] enc = Arrays.copyOf(raw, raw.length);
        long state = keySeed;
        for (int i = 0; i < enc.length; i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            enc[i] ^= (byte) (state >>> 56);
        }
        return enc;
    }

    /**
     * Encrypts a .class payload into an opaque headerless .fucked blob matching C++ decrypt_fucked_inplace.
     */
    public static byte[] encryptFuckedClass(byte[] raw, long fileSeed) {
        byte[] out = new byte[raw.length];
        long st = dev.hydro.j2c.crypto.CryptoEngine.splitMix64(fileSeed ^ 0xF0C7D0C7A1B2C3D4L);
        for (int i = 0; i < raw.length; i++) {
            st = dev.hydro.j2c.crypto.CryptoEngine.splitMix64(st + (long) i * 0x9E3779B97F4A7C15L);
            int k = (int) ((st >>> ((i & 7) * 8)) & 0xFF);
            int rot = (int) ((st >>> 56) & 7);
            int x = (raw[i] & 0xFF) ^ k;
            int r = ((x << rot) | (x >>> (8 - rot))) & 0xFF;
            out[i] = (byte) (r ^ ((i * 73 + (int) fileSeed) & 0xFF));
        }
        return out;
    }
}
