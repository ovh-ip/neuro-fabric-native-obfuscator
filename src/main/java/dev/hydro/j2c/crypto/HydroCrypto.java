package dev.hydro.j2c.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Shared pure-Java RFC 7748 X25519 + RFC 8439 ChaCha20 + HMAC-SHA256 / HKDF-SHA256
 * matching the C++20 runtime (hydro_crypto.cpp) and Spring Boot server bit-for-bit.
 */
public final class HydroCrypto {

    private HydroCrypto() {}

    private static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    public static byte[] randomBytes(int n, SecureRandom rng) {
        byte[] b = new byte[n];
        rng.nextBytes(b);
        return b;
    }

    public static byte[] clampX25519Scalar(byte[] k) {
        byte[] out = Arrays.copyOf(k, 32);
        out[0] &= (byte) 248;
        out[31] = (byte) ((out[31] & 127) | 64);
        return out;
    }

    public static byte[] x25519PublicKey(byte[] privKey) {
        byte[] base = new byte[32];
        base[0] = 9;
        return x25519(privKey, base);
    }

    private static void car25519(long[] o) {
        for (int i = 0; i < 16; i++) {
            o[i] += 65536L;
            long c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1L + 37L * (c - 1L) * (i == 15 ? 1 : 0);
            o[i] -= c << 16;
        }
    }

    private static void sel25519(long[] p, long[] q, int b) {
        long c = ~(b - 1L);
        for (int i = 0; i < 16; i++) {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void unpack25519(long[] o, byte[] n) {
        for (int i = 0; i < 16; i++) {
            o[i] = (n[2 * i] & 0xFFL) + ((n[2 * i + 1] & 0xFFL) << 8);
        }
        o[15] &= 0x7FFFL;
    }

    private static void pack25519(byte[] o, long[] n) {
        long[] t = Arrays.copyOf(n, 16);
        long[] m = new long[16];
        car25519(t);
        car25519(t);
        car25519(t);
        for (int j = 0; j < 2; j++) {
            m[0] = t[0] - 0xFFEDL;
            for (int i = 1; i < 15; i++) {
                m[i] = t[i] - 0xFFFFL - ((m[i - 1] >> 16) & 1L);
                m[i - 1] &= 0xFFFFL;
            }
            m[15] = t[15] - 0x7FFFL - ((m[14] >> 16) & 1L);
            int b = (int) ((m[15] >> 16) & 1L);
            m[14] &= 0xFFFFL;
            sel25519(t, m, 1 - b);
        }
        for (int i = 0; i < 16; i++) {
            o[2 * i] = (byte) (t[i] & 0xFF);
            o[2 * i + 1] = (byte) ((t[i] >>> 8) & 0xFF);
        }
    }

    private static void gfAdd(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
    }

    private static void gfSub(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
    }

    private static void gfMul(long[] o, long[] a, long[] b) {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                t[i + j] += a[i] * b[j];
            }
        }
        for (int i = 0; i < 15; i++) {
            t[i] += 38L * t[i + 16];
        }
        System.arraycopy(t, 0, o, 0, 16);
        car25519(o);
        car25519(o);
    }

    private static void gfSqr(long[] o, long[] a) {
        gfMul(o, a, a);
    }

    private static void inv25519(long[] o, long[] i) {
        long[] c = Arrays.copyOf(i, 16);
        for (int a = 253; a >= 0; a--) {
            gfSqr(c, c);
            if (a != 2 && a != 4) gfMul(c, c, i);
        }
        System.arraycopy(c, 0, o, 0, 16);
    }

    public static byte[] x25519(byte[] scalar, byte[] point) {
        byte[] z = clampX25519Scalar(scalar);
        long[] x = new long[16];
        unpack25519(x, point);
        long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16];
        long[] e = new long[16], f = new long[16];
        a[0] = 1;
        d[0] = 1;
        System.arraycopy(x, 0, b, 0, 16);
        long[] gf121665 = new long[16];
        gf121665[0] = 0xDB41L;
        gf121665[1] = 1L;

        for (int i = 254; i >= 0; i--) {
            int r = ((z[i >>> 3] & 0xFF) >>> (i & 7)) & 1;
            sel25519(a, b, r);
            sel25519(c, d, r);
            gfAdd(e, a, c);
            gfSub(a, a, c);
            gfAdd(c, b, d);
            gfSub(b, b, d);
            gfSqr(d, e);
            gfSqr(f, a);
            gfMul(a, c, a);
            gfMul(c, b, e);
            gfAdd(e, a, c);
            gfSub(a, a, c);
            gfSqr(b, a);
            gfSub(c, d, f);
            gfMul(a, c, gf121665);
            gfAdd(a, a, d);
            gfMul(c, c, a);
            gfMul(a, d, f);
            gfMul(d, b, x);
            gfSqr(b, e);
            sel25519(a, b, r);
            sel25519(c, d, r);
        }
        inv25519(c, c);
        gfMul(a, a, c);
        byte[] q = new byte[32];
        pack25519(q, a);
        return q;
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] hkdfSha256(byte[] salt, byte[] ikm, byte[] info, int outLen) {
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        byte[] prk = hmacSha256(effectiveSalt, ikm);
        byte[] out = new byte[outLen];
        byte[] t = new byte[0];
        int pos = 0;
        int counter = 1;
        while (pos < outLen) {
            byte[] in = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, in, 0, t.length);
            System.arraycopy(info, 0, in, t.length, info.length);
            in[in.length - 1] = (byte) counter++;
            t = hmacSha256(prk, in);
            int take = Math.min(t.length, outLen - pos);
            System.arraycopy(t, 0, out, pos, take);
            pos += take;
        }
        return out;
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        String s = hex.trim();
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("Odd hex length");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16);
            int lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid hex char");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String hex64Padded(long v) {
        return String.format("%016x", v);
    }
}
