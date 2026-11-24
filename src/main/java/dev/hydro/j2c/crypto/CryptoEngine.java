package dev.hydro.j2c.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Compile-time cryptographic primitives, MBA expression synthesizers, and opaque predicate
 * emitters used to prevent static recovery of strings, constants, and control flow.
 */
public final class CryptoEngine {

    private final long masterSeed;
    private final Random rng;

    public CryptoEngine(long masterSeed) {
        this.masterSeed = masterSeed;
        this.rng = new Random(masterSeed ^ 0x9E3779B97F4A7C15L);
    }

    public long getMasterSeed() {
        return masterSeed;
    }

    public static long splitMix64(long z) {
        z += 0x9E3779B97F4A7C15L;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    public static int fnv1a32(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) {
            h ^= (s.charAt(i) & 0xFF);
            h *= 0x01000193;
        }
        return h;
    }

    public static int fnv1a32LowerAscii(String s) {
        int h = 0x811c9dc5;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'A' && c <= 'Z') c = (char) (c + 32);
            h ^= (c & 0xFF);
            h *= 0x01000193;
        }
        return h;
    }

    /**
     * Encrypts UTF-8 symbol bytes (class, method, field, descriptor) using a stream key
     * derived from (entryId, masterSeed). Matches hy::decrypt_sym in hydro_runtime.cpp.
     */
    public byte[] encryptUtf8(String value, int entryId) {
        byte[] raw = value.getBytes(StandardCharsets.UTF_8);
        byte[] enc = new byte[raw.length + 1]; // include encrypted NUL terminator
        long state = splitMix64(masterSeed ^ ((long) entryId * 0xD6E8FEB86659FD93L) ^ 0xA5A55A5AF0F00F0FL);
        for (int i = 0; i < enc.length; i++) {
            byte p = (i < raw.length) ? raw[i] : 0;
            state = splitMix64(state + i * 0x9E3779B97F4A7C15L);
            byte k = (byte) ((state >>> ((i & 7) * 8)) & 0xFF);
            int rot = (int) ((state >>> 56) & 7);
            int x = (p & 0xFF) ^ (k & 0xFF);
            int r = ((x << rot) | (x >>> (8 - rot))) & 0xFF;
            enc[i] = (byte) (r ^ ((i * 31 + entryId) & 0xFF));
        }
        return enc;
    }

    /**
     * Encrypts a Java String literal as UTF-16 code units (lossless for NUL, surrogates, Unicode).
     * Matches hy::decrypt_wstr in hydro_runtime.cpp.
     */
    public short[] encryptUtf16(String value, int entryId) {
        short[] enc = new short[value.length()];
        long state = splitMix64(masterSeed ^ ((long) entryId * 0x94D049BB133111EBL) ^ 0x55AA33CC11EE7799L);
        for (int i = 0; i < value.length(); i++) {
            int p = value.charAt(i);
            state = splitMix64(state ^ (i * 0xBF58476D1CE4E5B9L));
            int k = (int) (state & 0xFFFF);
            int rot = (int) ((state >>> 48) & 15);
            int x = (p ^ k) & 0xFFFF;
            int r = ((x << rot) | (x >>> (16 - rot))) & 0xFFFF;
            enc[i] = (short) (r ^ ((i * 131 + entryId * 17) & 0xFFFF));
        }
        return enc;
    }

    /**
     * Emits an MBA-obfuscated 32-bit constant expression anchored to runtime opaque seed `_op`
     * so GCC -O2 cannot constant-fold magic constants into plain immediates.
     */
    public String mbaConst32(int value, boolean strong) {
        if (!strong) {
            int k = rng.nextInt();
            int e = value ^ k;
            return "((int32_t)((" + hex32(e) + "u ^ " + hex32(k) + "u) ^ (uint32_t)((_op ^ _op) & 1ULL)))";
        }
        int r1 = rng.nextInt();
        int r2 = rng.nextInt();
        int target = value ^ r1;
        // Identity: (a ^ b) + 2 * (a & b) == a + b
        int a = rng.nextInt();
        int b = target - a;
        int xorPart = a ^ b;
        int andPart = a & b;
        int style = rng.nextInt(3);
        // Zero invariant tied to runtime _op: ((_op | 1ULL) == 0ULL) is always false -> 0
        String z = "(uint32_t)((((_op * (_op + 1ULL)) & 1ULL) != 0ULL) ? " + hex32(r2) + "u : 0u)";
        return switch (style) {
            case 0 -> "((int32_t)(((" + hex32(xorPart) + "u + (" + hex32(andPart) + "u << 1)) ^ " + hex32(r1) + "u) ^ " + z + "))";
            case 1 -> {
                int x1 = target ^ r2;
                yield "((int32_t)(((" + hex32(x1) + "u | " + hex32(r2) + "u) - (" + hex32(x1) + "u & " + hex32(r2) + "u)) ^ " + hex32(r1) + "u ^ " + z + "))";
            }
            default -> {
                int neg = ~target;
                yield "((int32_t)(((~" + hex32(neg) + "u) ^ " + hex32(r1) + "u) + " + z + "))";
            }
        };
    }

    /**
     * Emits an MBA-obfuscated 64-bit constant anchored to runtime opaque seed `_op`.
     */
    public String mbaConst64(long value, boolean strong) {
        if (!strong) {
            long k = rng.nextLong();
            long e = value ^ k;
            return "((int64_t)((" + hex64(e) + "ULL ^ " + hex64(k) + "ULL) ^ (_op ^ _op)))";
        }
        long r1 = rng.nextLong();
        long target = value ^ r1;
        long a = rng.nextLong();
        long b = target - a;
        String z = "((((_op * (_op + 1ULL)) & 1ULL) != 0ULL) ? " + hex64(rng.nextLong()) + "ULL : 0ULL)";
        return "((int64_t)(((" + hex64(a ^ b) + "ULL + (" + hex64(a & b) + "ULL << 1)) ^ " + hex64(r1) + "ULL) ^ " + z + "))";
    }

    /**
     * Emits an opaque predicate that always evaluates to true at runtime, but cannot be
     * statically folded by GCC -O2 or Hex-Rays because `_op` is loaded from volatile entropy.
     */
    public String opaqueAlwaysTrue() {
        int kind = rng.nextInt(3);
        return switch (kind) {
            case 0 -> "(((_op * (_op + 1ULL)) & 1ULL) == 0ULL)";
            case 1 -> "(((_op | 1ULL) ^ 0ULL) != 0ULL)";
            default -> "((((_op ^ (_op + 2ULL)) | 1ULL) & 1ULL) == 1ULL)";
        };
    }

    public static String hex32(int v) {
        return "0x" + Integer.toHexString(v);
    }

    public static String hex64(long v) {
        return "0x" + Long.toHexString(v);
    }
}
