package dev.hydro.j2c.jar;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.preprocess.JavaPreHardener;
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
        InsnList prefix = new InsnList();
        prefix.add(new LdcInsnNode(Type.getObjectType(cn.name)));
        prefix.add(new LdcInsnNode(classId));
        prefix.add(new MethodInsnNode(INVOKESTATIC, loaderInternalName, regMethodName, "(Ljava/lang/Class;I)V", false));
        prependToClinit(cn, prefix, 2);
    }

    /**
     * Ensures entrypoint/API stub classes that keep 0 native methods (e.g. in -a annotation mode
     * or when excluded) still trigger HLoader.&lt;clinit&gt; before referencing any .fucked classes.
     */
    public static void injectLoaderBoot(ClassNode cn, String loaderInternalName, String bootMethodName) {
        InsnList prefix = new InsnList();
        prefix.add(new MethodInsnNode(INVOKESTATIC, loaderInternalName, bootMethodName, "()V", false));
        prependToClinit(cn, prefix, 1);
    }

    private static void prependToClinit(ClassNode cn, InsnList prefix, int minStack) {
        MethodNode clinit = null;
        for (MethodNode m : cn.methods) {
            if ("<clinit>".equals(m.name) && "()V".equals(m.desc)) {
                clinit = m;
                break;
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(prefix);
            clinit.instructions.add(new InsnNode(RETURN));
            clinit.maxStack = minStack;
            clinit.maxLocals = 0;
            cn.methods.add(clinit);
        } else {
            clinit.instructions.insert(prefix);
            clinit.maxStack = Math.max(clinit.maxStack, minStack);
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
            String libBaseName,
            String embeddedResPath,
            long dllKeySeed,
            ObfuscationConfig config) {
        return generateLoaderClass(loaderInternalName, regMethodName, verifyMethodName, bootMethodName,
                libBaseName, embeddedResPath, dllKeySeed, config, new Random(dllKeySeed));
    }

    public static byte[] generateLoaderClass(
            String loaderInternalName,
            String regMethodName,
            String verifyMethodName,
            String bootMethodName,
            String libBaseName,
            String embeddedResPath,
            long dllKeySeed,
            ObfuscationConfig config,
            Random rng) {

        ClassNode cw = new ClassNode();
        cw.visit(V17, ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC, loaderInternalName, null, "java/lang/Object", null);

        // public static native void r(Class<?> cls, int id)
        cw.visitMethod(ACC_PUBLIC | ACC_STATIC | ACC_NATIVE, regMethodName, "(Ljava/lang/Class;I)V", null, null).visitEnd();
        // private static native void v(ClassLoader cl)
        cw.visitMethod(ACC_PRIVATE | ACC_STATIC | ACC_NATIVE, verifyMethodName, "(Ljava/lang/ClassLoader;)V", null, null).visitEnd();

        // public static void b() {} - triggers <clinit> safely from @Mixin / Main trampolines
        MethodVisitor bmv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, bootMethodName, "()V", null, null);
        bmv.visitCode();
        bmv.visitInsn(RETURN);
        bmv.visitMaxs(0, 0);
        bmv.visitEnd();

        emitPlatformHelpers(cw, loaderInternalName);

        // static initializer
        MethodVisitor mv = cw.visitMethod(ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();
        Label tryStart = new Label(), tryEnd = new Label(), tryHandler = new Label();
        mv.visitTryCatchBlock(tryStart, tryEnd, tryHandler, "java/lang/Throwable");

        mv.visitLabel(tryStart);
        if (config.isEmbedDll()) {
            // InputStream in = openPayload(libBaseName, embeddedResPath);
            mv.visitLdcInsn(libBaseName);
            mv.visitLdcInsn(embeddedResPath);
            mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "openPayload", "(Ljava/lang/String;Ljava/lang/String;)Ljava/io/InputStream;", false);
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
                mv.visitLdcInsn(0x9E3779B97F4A7C15L);
                mv.visitInsn(LADD);
                mv.visitInsn(DUP2);
                mv.visitVarInsn(LSTORE, 2);
                mv.visitInsn(DUP2);
                mv.visitIntInsn(BIPUSH, 30);
                mv.visitInsn(LUSHR);
                mv.visitInsn(LXOR);
                mv.visitLdcInsn(0xBF58476D1CE4E5B9L);
                mv.visitInsn(LMUL);
                mv.visitInsn(DUP2);
                mv.visitIntInsn(BIPUSH, 27);
                mv.visitInsn(LUSHR);
                mv.visitInsn(LXOR);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitIntInsn(BIPUSH, 7);
                mv.visitInsn(IAND);
                mv.visitInsn(ICONST_3);
                mv.visitInsn(ISHL);
                mv.visitInsn(LUSHR);
                mv.visitInsn(L2I);
                mv.visitVarInsn(ISTORE, 7);

                mv.visitVarInsn(ALOAD, 1);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitInsn(DUP2);
                mv.visitInsn(BALOAD);
                mv.visitVarInsn(ILOAD, 7);
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

            // File tmp = File.createTempFile("hy_", nativeExt(osTag())); tmp.deleteOnExit();
            mv.visitLdcInsn("hy_");
            mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "osTag", "()Ljava/lang/String;", false);
            mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "nativeExt", "(Ljava/lang/String;)Ljava/lang/String;", false);
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
            // Load external native library path (with OS-specific name fallback next to JAR)
            String dllSpec = (config.getExternalDllPath() != null && !config.getExternalDllPath().isBlank())
                    ? config.getExternalDllPath()
                    : config.getOutputDll().getFileName().toString();
            mv.visitLdcInsn(dllSpec);
            mv.visitLdcInsn(libBaseName);
            mv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "resolveExt", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
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
            MethodVisitor rmv = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "resolveExt", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", null, null);
            rmv.visitCode();
            // File f = new File(spec); if (f.isAbsolute() || f.exists()) return f.getAbsolutePath();
            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitVarInsn(ALOAD, 0);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
            rmv.visitVarInsn(ASTORE, 2);
            rmv.visitVarInsn(ALOAD, 2);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "isAbsolute", "()Z", false);
            Label retAbs = new Label();
            rmv.visitJumpInsn(IFNE, retAbs);
            rmv.visitVarInsn(ALOAD, 2);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            rmv.visitJumpInsn(IFNE, retAbs);

            // Try relative to JAR code source parent (spec first, then OS-specific nativeFileName)
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
            rmv.visitVarInsn(ASTORE, 3);

            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitVarInsn(ALOAD, 3);
            rmv.visitVarInsn(ALOAD, 0);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/io/File;Ljava/lang/String;)V", false);
            rmv.visitVarInsn(ASTORE, 4);
            rmv.visitVarInsn(ALOAD, 4);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            Label tryOsLib = new Label();
            rmv.visitJumpInsn(IFEQ, tryOsLib);
            rmv.visitVarInsn(ALOAD, 4);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            rmv.visitInsn(ARETURN);

            rmv.visitLabel(tryOsLib);
            rmv.visitTypeInsn(NEW, "java/io/File");
            rmv.visitInsn(DUP);
            rmv.visitVarInsn(ALOAD, 3);
            rmv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "osTag", "()Ljava/lang/String;", false);
            rmv.visitVarInsn(ALOAD, 1);
            rmv.visitMethodInsn(INVOKESTATIC, loaderInternalName, "nativeFileName", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
            rmv.visitMethodInsn(INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/io/File;Ljava/lang/String;)V", false);
            rmv.visitVarInsn(ASTORE, 4);
            rmv.visitVarInsn(ALOAD, 4);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "exists", "()Z", false);
            rmv.visitJumpInsn(IFEQ, tryCsEnd);
            rmv.visitVarInsn(ALOAD, 4);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            rmv.visitInsn(ARETURN);

            rmv.visitLabel(tryCsEnd);
            rmv.visitJumpInsn(GOTO, retAbs);
            rmv.visitLabel(tryCsCatch);
            rmv.visitInsn(POP);

            rmv.visitLabel(retAbs);
            rmv.visitVarInsn(ALOAD, 2);
            rmv.visitMethodInsn(INVOKEVIRTUAL, "java/io/File", "getAbsolutePath", "()Ljava/lang/String;", false);
            rmv.visitInsn(ARETURN);
            rmv.visitMaxs(5, 6);
            rmv.visitEnd();
        }

        cw.visitEnd();
        JavaPreHardener.hardenResidualBytecode(cw, rng);
        return writeClass(cw, Collections.emptyMap());
    }

    private static void emitPlatformHelpers(ClassVisitor cw, String loaderInternalName) {
        // osTag() -> "windows" | "macos" | "linux"
        MethodVisitor om = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "osTag", "()Ljava/lang/String;", null, null);
        om.visitCode();
        om.visitLdcInsn("os.name");
        om.visitLdcInsn("");
        om.visitMethodInsn(INVOKESTATIC, "java/lang/System", "getProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
        om.visitFieldInsn(GETSTATIC, "java/util/Locale", "ROOT", "Ljava/util/Locale;");
        om.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "toLowerCase", "(Ljava/util/Locale;)Ljava/lang/String;", false);
        om.visitVarInsn(ASTORE, 0);
        om.visitVarInsn(ALOAD, 0);
        om.visitLdcInsn("win");
        om.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", false);
        Label notWin = new Label();
        om.visitJumpInsn(IFEQ, notWin);
        om.visitLdcInsn("windows");
        om.visitInsn(ARETURN);
        om.visitLabel(notWin);
        om.visitVarInsn(ALOAD, 0);
        om.visitLdcInsn("mac");
        om.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", false);
        Label retMac = new Label();
        om.visitJumpInsn(IFNE, retMac);
        om.visitVarInsn(ALOAD, 0);
        om.visitLdcInsn("darwin");
        om.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z", false);
        Label retLin = new Label();
        om.visitJumpInsn(IFEQ, retLin);
        om.visitLabel(retMac);
        om.visitLdcInsn("macos");
        om.visitInsn(ARETURN);
        om.visitLabel(retLin);
        om.visitLdcInsn("linux");
        om.visitInsn(ARETURN);
        om.visitMaxs(2, 1);
        om.visitEnd();

        // archTag() -> "x86_64" | "arm64" | "x86" | raw
        MethodVisitor am = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "archTag", "()Ljava/lang/String;", null, null);
        am.visitCode();
        am.visitLdcInsn("os.arch");
        am.visitLdcInsn("");
        am.visitMethodInsn(INVOKESTATIC, "java/lang/System", "getProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
        am.visitFieldInsn(GETSTATIC, "java/util/Locale", "ROOT", "Ljava/util/Locale;");
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "toLowerCase", "(Ljava/util/Locale;)Ljava/lang/String;", false);
        am.visitVarInsn(ASTORE, 0);
        am.visitLdcInsn("amd64");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label isX64 = new Label(), chkArm = new Label();
        am.visitJumpInsn(IFNE, isX64);
        am.visitLdcInsn("x86_64");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        am.visitJumpInsn(IFEQ, chkArm);
        am.visitLabel(isX64);
        am.visitLdcInsn("x86_64");
        am.visitInsn(ARETURN);

        am.visitLabel(chkArm);
        am.visitLdcInsn("aarch64");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label isArm = new Label(), chkX86 = new Label();
        am.visitJumpInsn(IFNE, isArm);
        am.visitLdcInsn("arm64");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        am.visitJumpInsn(IFEQ, chkX86);
        am.visitLabel(isArm);
        am.visitLdcInsn("arm64");
        am.visitInsn(ARETURN);

        am.visitLabel(chkX86);
        am.visitLdcInsn("x86");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label isX86 = new Label(), retRaw = new Label();
        am.visitJumpInsn(IFNE, isX86);
        am.visitLdcInsn("i386");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        am.visitJumpInsn(IFNE, isX86);
        am.visitLdcInsn("i686");
        am.visitVarInsn(ALOAD, 0);
        am.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        am.visitJumpInsn(IFEQ, retRaw);
        am.visitLabel(isX86);
        am.visitLdcInsn("x86");
        am.visitInsn(ARETURN);

        am.visitLabel(retRaw);
        am.visitVarInsn(ALOAD, 0);
        am.visitInsn(ARETURN);
        am.visitMaxs(2, 1);
        am.visitEnd();

        // nativeExt(String os) -> ".dll" | ".dylib" | ".so"
        MethodVisitor em = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "nativeExt", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        em.visitCode();
        em.visitLdcInsn("windows");
        em.visitVarInsn(ALOAD, 0);
        em.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label notW = new Label();
        em.visitJumpInsn(IFEQ, notW);
        em.visitLdcInsn(".dll");
        em.visitInsn(ARETURN);
        em.visitLabel(notW);
        em.visitLdcInsn("macos");
        em.visitVarInsn(ALOAD, 0);
        em.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label retSo = new Label();
        em.visitJumpInsn(IFEQ, retSo);
        em.visitLdcInsn(".dylib");
        em.visitInsn(ARETURN);
        em.visitLabel(retSo);
        em.visitLdcInsn(".so");
        em.visitInsn(ARETURN);
        em.visitMaxs(2, 1);
        em.visitEnd();

        // nativeFileName(String os, String baseName)
        MethodVisitor fm = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "nativeFileName", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", null, null);
        fm.visitCode();
        fm.visitLdcInsn("windows");
        fm.visitVarInsn(ALOAD, 0);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "equals", "(Ljava/lang/Object;)Z", false);
        Label fnNotWin = new Label();
        fm.visitJumpInsn(IFEQ, fnNotWin);
        fm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        fm.visitInsn(DUP);
        fm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
        fm.visitVarInsn(ALOAD, 1);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        fm.visitLdcInsn(".dll");
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        fm.visitInsn(ARETURN);
        fm.visitLabel(fnNotWin);
        fm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        fm.visitInsn(DUP);
        fm.visitLdcInsn("lib");
        fm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
        fm.visitVarInsn(ALOAD, 1);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        fm.visitVarInsn(ALOAD, 0);
        fm.visitMethodInsn(INVOKESTATIC, loaderInternalName, "nativeExt", "(Ljava/lang/String;)Ljava/lang/String;", false);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        fm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        fm.visitInsn(ARETURN);
        fm.visitMaxs(3, 2);
        fm.visitEnd();

        // openPayload(String baseName, String fallbackResPath) -> InputStream
        MethodVisitor pm = cw.visitMethod(ACC_PRIVATE | ACC_STATIC, "openPayload", "(Ljava/lang/String;Ljava/lang/String;)Ljava/io/InputStream;", null, null);
        pm.visitCode();
        pm.visitMethodInsn(INVOKESTATIC, loaderInternalName, "osTag", "()Ljava/lang/String;", false);
        pm.visitVarInsn(ASTORE, 2); // os
        pm.visitMethodInsn(INVOKESTATIC, loaderInternalName, "archTag", "()Ljava/lang/String;", false);
        pm.visitVarInsn(ASTORE, 3); // arch
        pm.visitVarInsn(ALOAD, 2);
        pm.visitVarInsn(ALOAD, 0);
        pm.visitMethodInsn(INVOKESTATIC, loaderInternalName, "nativeFileName", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
        pm.visitVarInsn(ASTORE, 4); // fn

        // 1. /natives/<os>-<arch>/<fn>
        emitConcat4AndGetRes(pm, loaderInternalName, "/natives/", 2, "-", 3, "/", 4);
        pm.visitVarInsn(ASTORE, 5);
        pm.visitVarInsn(ALOAD, 5);
        Label c2 = new Label();
        pm.visitJumpInsn(IFNULL, c2);
        pm.visitVarInsn(ALOAD, 5);
        pm.visitInsn(ARETURN);

        // 2. /natives/<os>/<fn>
        pm.visitLabel(c2);
        pm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        pm.visitInsn(DUP);
        pm.visitLdcInsn("/natives/");
        pm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
        pm.visitVarInsn(ALOAD, 2);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitLdcInsn("/");
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitVarInsn(ALOAD, 4);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        pm.visitLdcInsn(Type.getObjectType(loaderInternalName));
        pm.visitInsn(SWAP);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false);
        pm.visitVarInsn(ASTORE, 5);
        pm.visitVarInsn(ALOAD, 5);
        Label c3 = new Label();
        pm.visitJumpInsn(IFNULL, c3);
        pm.visitVarInsn(ALOAD, 5);
        pm.visitInsn(ARETURN);

        // 3. /natives/<fn>
        pm.visitLabel(c3);
        pm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        pm.visitInsn(DUP);
        pm.visitLdcInsn("/natives/");
        pm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
        pm.visitVarInsn(ALOAD, 4);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        pm.visitLdcInsn(Type.getObjectType(loaderInternalName));
        pm.visitInsn(SWAP);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false);
        pm.visitVarInsn(ASTORE, 5);
        pm.visitVarInsn(ALOAD, 5);
        Label c4 = new Label();
        pm.visitJumpInsn(IFNULL, c4);
        pm.visitVarInsn(ALOAD, 5);
        pm.visitInsn(ARETURN);

        // 4. /<fallbackResPath>
        pm.visitLabel(c4);
        pm.visitLdcInsn(Type.getObjectType(loaderInternalName));
        pm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        pm.visitInsn(DUP);
        pm.visitLdcInsn("/");
        pm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
        pm.visitVarInsn(ALOAD, 1);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false);
        pm.visitInsn(ARETURN);
        pm.visitMaxs(4, 6);
        pm.visitEnd();
    }

    private static void emitConcat4AndGetRes(
            MethodVisitor pm, String loaderInternalName,
            String s0, int var1, String s2, int var3, String s4, int var5) {
        pm.visitLdcInsn(Type.getObjectType(loaderInternalName));
        pm.visitTypeInsn(NEW, "java/lang/StringBuilder");
        pm.visitInsn(DUP);
        pm.visitLdcInsn(s0);
        pm.visitMethodInsn(INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "(Ljava/lang/String;)V", false);
        pm.visitVarInsn(ALOAD, var1);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitLdcInsn(s2);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitVarInsn(ALOAD, var3);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitLdcInsn(s4);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitVarInsn(ALOAD, var5);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false);
        pm.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false);
    }

    public static byte[] encryptDllPayload(byte[] raw, long keySeed) {
        byte[] enc = Arrays.copyOf(raw, raw.length);
        long state = keySeed;
        for (int i = 0; i < enc.length; i++) {
            state += 0x9E3779B97F4A7C15L;
            long z = (state ^ (state >>> 30)) * 0xBF58476D1CE4E5B9L;
            z ^= (z >>> 27);
            enc[i] ^= (byte) ((z >>> ((i & 7) << 3)) & 0xFF);
        }
        return enc;
    }

    /**
     * Encrypts a .class payload into an opaque headerless .fucked blob padded to random decoy-matching
     * length so file sizes never leak small vault entries.
     */
    public static byte[] encryptFuckedClass(byte[] raw, long fileSeed, long vaultSalt, int minPaddedLen, Random padRng) {
        int targetLen = raw.length < minPaddedLen
                ? minPaddedLen + padRng.nextInt(1024)
                : raw.length + padRng.nextInt(128);
        byte[] out = new byte[targetLen];
        long st = dev.hydro.j2c.crypto.CryptoEngine.splitMix64(fileSeed ^ vaultSalt);
        for (int i = 0; i < raw.length; i++) {
            st = dev.hydro.j2c.crypto.CryptoEngine.splitMix64(st + (long) i * 0x9E3779B97F4A7C15L);
            int k = (int) ((st >>> ((i & 7) * 8)) & 0xFF);
            int rot = (int) ((st >>> 56) & 7);
            int x = (raw[i] & 0xFF) ^ k;
            int r = ((x << rot) | (x >>> (8 - rot))) & 0xFF;
            out[i] = (byte) (r ^ ((i * 73 + (int) fileSeed) & 0xFF));
        }
        for (int i = raw.length; i < targetLen; i++) {
            st = dev.hydro.j2c.crypto.CryptoEngine.splitMix64(st + (long) i * 0xBF58476D1CE4E5B9L);
            out[i] = (byte) ((st >>> ((i & 7) * 8)) & 0xFF);
        }
        return out;
    }
}
