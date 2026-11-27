package dev.hydro.j2c.jar;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.*;

/**
 * Generates deeply nested garbage directories containing both valid realistic decoy .class files
 * (with opaque control flow, fake native calls, switches, and decoy strings) and indistinguishable
 * high-entropy .fucked decoy blobs to overwhelm static analysis and JAR browsing tools.
 */
public final class JunkGenerator implements Opcodes {

    private static final String[] PKG_ROOTS_FABRIC = {
            "net/minecraft/internal",
            "org/spongepowered/cache",
            "com/mojang/auth/v3",
            "io/netty/channel/shadow",
            "dev/hydro/v4/impl",
            "net/fabricmc/loom/cache",
            "org/lwjgl/system/internal",
            "com/google/common/reflect/stub"
    };

    private static final String[] PKG_ROOTS_JAVA = {
            "com/sun/internal/stub",
            "org/apache/commons/cache",
            "javax/crypto/internal/v2",
            "io/netty/channel/shadow",
            "dev/hydro/v4/impl",
            "org/slf4j/impl/bridge",
            "com/fasterxml/core/cache",
            "com/google/common/reflect/stub"
    };

    private static final String[] WORDS = {
            "Packet", "Dispatch", "Session", "Cipher", "Verify", "Context", "Pipeline",
            "Bridge", "Kernel", "Native", "Vault", "Cache", "Registry", "Resolver",
            "Codec", "Buffer", "Sync", "Hook", "Guard", "Stream", "Token", "Frame"
    };

    private static final String[] DECOY_STRINGS = {
            "Invalid signature block",
            "AES-256-GCM/NoPadding",
            "Session handshake timeout",
            "HWID mismatch detected",
            "Failed to map memory region",
            "Mixin refmap checksum error",
            "Key exchange aborted",
            "Corrupt bytecode segment",
            "PKCS5Padding integrity failed",
            "TLS certificate pinning error",
            "Native descriptor mismatch",
            "Thread context drift detected",
            "ClassLoader delegation violation",
            "Buffer alignment check failed",
            "Unexpected frame verification state",
            "JNI local reference table exhausted",
            "Symbol relocation offset invalid",
            "HMAC digest mismatch",
            "Protocol negotiation refused",
            "Module descriptor digest invalid",
            "Runtime pool lock timeout",
            "Page guard fault ignored",
            "Async dispatch queue full",
            "Shadow field lookup deferred"
    };

    public static void populateJunk(
            Map<String, byte[]> resources,
            Set<String> realClassNames,
            List<String> fuckedDirsOut,
            int totalJunkCount,
            Random rng) {
        populateJunk(resources, realClassNames, fuckedDirsOut, totalJunkCount, true, V17, rng);
    }

    public static void populateJunk(
            Map<String, byte[]> resources,
            Set<String> realClassNames,
            List<String> fuckedDirsOut,
            int totalJunkCount,
            boolean isFabricMod,
            Random rng) {
        populateJunk(resources, realClassNames, fuckedDirsOut, totalJunkCount, isFabricMod, V17, rng);
    }

    public static void populateJunk(
            Map<String, byte[]> resources,
            Set<String> realClassNames,
            List<String> fuckedDirsOut,
            int totalJunkCount,
            boolean isFabricMod,
            int classVersion,
            Random rng) {

        if (totalJunkCount <= 0) return;

        int safeClassVersion = Math.max(V1_8, classVersion);
        String[] roots = isFabricMod ? PKG_ROOTS_FABRIC : PKG_ROOTS_JAVA;
        // Build 36 deeply nested decoy directory paths
        List<String> dirs = new ArrayList<>();
        for (int i = 0; i < 36; i++) {
            String root = roots[rng.nextInt(roots.length)];
            int depth = 2 + rng.nextInt(4);
            StringBuilder dir = new StringBuilder(root);
            for (int d = 0; d < depth; d++) {
                dir.append('/').append(randomToken(rng, 2 + rng.nextInt(5)));
            }
            String dirPath = dir.toString();
            dirs.add(dirPath);
            fuckedDirsOut.add(dirPath);
        }

        int decoyClassCount = totalJunkCount / 2;
        int decoyFuckedCount = totalJunkCount - decoyClassCount;

        // 1. Valid realistic .class decoys matching dominant bytecode version & varied code patterns
        for (int i = 0; i < decoyClassCount; i++) {
            String dir = dirs.get(rng.nextInt(dirs.size()));
            String clsSimple = WORDS[rng.nextInt(WORDS.length)] + "_" + randomToken(rng, 6);
            String internalName = dir + "/" + clsSimple;
            if (realClassNames.contains(internalName) || resources.containsKey(internalName + ".class")) continue;
            resources.put(internalName + ".class", buildDecoyClass(internalName, safeClassVersion, rng));
        }

        // 2. Indistinguishable high-entropy .fucked decoy blobs spanning full range (256B..7.2KB)
        for (int i = 0; i < decoyFuckedCount; i++) {
            String dir = dirs.get(rng.nextInt(dirs.size()));
            String fname = randomToken(rng, 8 + rng.nextInt(8)) + ".fucked";
            String path = dir + "/" + fname;
            if (resources.containsKey(path)) continue;
            byte[] noise = new byte[256 + rng.nextInt(6912)];
            rng.nextBytes(noise);
            resources.put(path, noise);
        }
    }

    private static byte[] buildDecoyClass(String internalName, int classVersion, Random rng) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        cw.visit(classVersion, ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC, internalName, null, "java/lang/Object", null);

        String field1 = "f_" + randomToken(rng, 4);
        String field2 = "k_" + randomToken(rng, 4);
        cw.visitField(ACC_PRIVATE | ACC_STATIC, field1, "J", null, null).visitEnd();
        cw.visitField(ACC_PRIVATE, field2, "I", null, null).visitEnd();

        // Constructor
        MethodVisitor init = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(ALOAD, 0);
        init.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitVarInsn(ALOAD, 0);
        init.visitLdcInsn(rng.nextInt());
        init.visitFieldInsn(PUTFIELD, internalName, field2, "I");
        init.visitInsn(RETURN);
        init.visitMaxs(2, 1);
        init.visitEnd();

        // 2-4 varied decoy methods with switches, loops, bitwise mixing, and try/catch
        int mCount = 2 + rng.nextInt(3);
        int templateKind = rng.nextInt(3);
        for (int m = 0; m < mCount; m++) {
            String mname = "m_" + randomToken(rng, 5);
            int kind = (templateKind + m) % 3;
            MethodVisitor mv = cw.visitMethod(ACC_PUBLIC | ACC_STATIC, mname, "(II)J", null, null);
            mv.visitCode();

            Label tStart = new Label(), tEnd = new Label(), tCatch = new Label();
            mv.visitTryCatchBlock(tStart, tEnd, tCatch, "java/lang/Throwable");

            mv.visitLabel(tStart);
            if (kind == 1) {
                // Counting mix loop decoy
                mv.visitVarInsn(ILOAD, 0);
                mv.visitInsn(I2L);
                mv.visitLdcInsn(rng.nextLong());
                mv.visitInsn(LXOR);
                mv.visitVarInsn(LSTORE, 2);
                mv.visitInsn(ICONST_0);
                mv.visitVarInsn(ISTORE, 4);
                Label lp = new Label(), le = new Label();
                mv.visitJumpInsn(GOTO, le);
                mv.visitLabel(lp);
                mv.visitVarInsn(LLOAD, 2);
                mv.visitLdcInsn(0x9E3779B97F4A7C15L);
                mv.visitInsn(LMUL);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitInsn(I2L);
                mv.visitInsn(LXOR);
                mv.visitVarInsn(LSTORE, 2);
                mv.visitIincInsn(4, 1);
                mv.visitLabel(le);
                mv.visitVarInsn(ILOAD, 4);
                mv.visitVarInsn(ILOAD, 1);
                mv.visitIntInsn(BIPUSH, 7);
                mv.visitInsn(IAND);
                mv.visitJumpInsn(IF_ICMPLT, lp);
                mv.visitVarInsn(LLOAD, 2);
                mv.visitLabel(tEnd);
                mv.visitInsn(LRETURN);
            } else if (kind == 2) {
                // Conditional branch + string hash decoy
                mv.visitVarInsn(ILOAD, 0);
                mv.visitVarInsn(ILOAD, 1);
                mv.visitInsn(IXOR);
                mv.visitInsn(ICONST_1);
                mv.visitInsn(IAND);
                Label lElse = new Label();
                mv.visitJumpInsn(IFEQ, lElse);
                mv.visitLdcInsn(DECOY_STRINGS[rng.nextInt(DECOY_STRINGS.length)]);
                mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "length", "()I", false);
                mv.visitInsn(I2L);
                mv.visitLdcInsn(rng.nextLong());
                mv.visitInsn(LXOR);
                mv.visitInsn(LRETURN);
                mv.visitLabel(lElse);
                mv.visitVarInsn(ILOAD, 0);
                mv.visitInsn(I2L);
                mv.visitLdcInsn(0xBF58476D1CE4E5B9L);
                mv.visitInsn(LMUL);
                mv.visitLabel(tEnd);
                mv.visitInsn(LRETURN);
            } else {
                mv.visitVarInsn(ILOAD, 0);
                mv.visitLdcInsn(rng.nextInt());
                mv.visitInsn(IXOR);
                mv.visitVarInsn(ISTORE, 2);

                Label l0 = new Label(), l1 = new Label(), l2 = new Label(), ld = new Label();
                mv.visitVarInsn(ILOAD, 1);
                mv.visitInsn(ICONST_3);
                mv.visitInsn(IAND);
                mv.visitTableSwitchInsn(0, 2, ld, l0, l1, l2);

                mv.visitLabel(l0);
                mv.visitVarInsn(ILOAD, 2);
                mv.visitLdcInsn(0x45D9F3B);
                mv.visitInsn(IMUL);
                mv.visitInsn(I2L);
                mv.visitInsn(LRETURN);

                mv.visitLabel(l1);
                mv.visitVarInsn(ILOAD, 2);
                mv.visitIntInsn(BIPUSH, 7);
                mv.visitInsn(ISHL);
                mv.visitInsn(I2L);
                mv.visitLdcInsn(rng.nextLong());
                mv.visitInsn(LXOR);
                mv.visitInsn(LRETURN);

                mv.visitLabel(l2);
                mv.visitLdcInsn(DECOY_STRINGS[rng.nextInt(DECOY_STRINGS.length)]);
                mv.visitMethodInsn(INVOKEVIRTUAL, "java/lang/String", "hashCode", "()I", false);
                mv.visitInsn(I2L);
                mv.visitInsn(LRETURN);

                mv.visitLabel(ld);
                mv.visitMethodInsn(INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
                mv.visitLdcInsn(rng.nextLong());
                mv.visitInsn(LXOR);
                mv.visitLabel(tEnd);
                mv.visitInsn(LRETURN);
            }

            mv.visitLabel(tCatch);
            mv.visitInsn(POP);
            mv.visitLdcInsn(rng.nextLong());
            mv.visitInsn(LRETURN);

            mv.visitMaxs(4, 6);
            mv.visitEnd();
        }

        // Static fake native stub in some junk classes
        if (rng.nextBoolean()) {
            cw.visitMethod(ACC_PRIVATE | ACC_STATIC | ACC_NATIVE, "n_" + randomToken(rng, 5), "(J[B)I", null, null).visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static String randomToken(Random rng, int len) {
        final String alpha = "abcdefghijklmnopqrstuvwxyz0123456789";
        final String confusing = "Il1O0o";
        StringBuilder sb = new StringBuilder(len);
        boolean useConfusing = rng.nextInt(3) == 0;
        String src = useConfusing ? confusing : alpha;
        // First char must be valid Java identifier start (letter)
        sb.append(useConfusing ? "IlOo".charAt(rng.nextInt(4)) : (char) ('a' + rng.nextInt(26)));
        for (int i = 1; i < len; i++) {
            sb.append(src.charAt(rng.nextInt(src.length())));
        }
        return sb.toString();
    }
}
