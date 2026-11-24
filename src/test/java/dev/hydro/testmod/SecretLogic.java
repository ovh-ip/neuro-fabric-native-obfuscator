package dev.hydro.testmod;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.IntUnaryOperator;

public class SecretLogic {

    public record Vec3(double x, double y, double z) {
        public double lengthSq() {
            return x * x + y * y + z * z;
        }
    }

    private static final String STATIC_TAG;
    private final int instanceKey;
    private int syncCounter = 0;

    static {
        StringBuilder sb = new StringBuilder();
        sb.append("HY").append(2026);
        STATIC_TAG = sb.toString();
    }

    public SecretLogic(int seed) {
        super();
        // Post-super logic outlined by ConstructorOutliner into native DLL!
        int k = seed ^ 0x5A5A1234;
        this.instanceKey = k * 31 + 7;
    }

    public int getInstanceKey() {
        return instanceKey;
    }

    public static String getStaticTag() {
        return STATIC_TAG;
    }

    public static long integerAndFloatEdgeCases(int a, long b, float f, double d) {
        int ovf = Integer.MAX_VALUE + 1;
        int minDiv = Integer.MIN_VALUE / -1;
        int minRem = Integer.MIN_VALUE % -1;
        long lMinDiv = Long.MIN_VALUE / -1L;
        int f2iNan = (int) (0.0f / 0.0f);
        int d2iSat = (int) (1e30);
        long d2lNegSat = (long) (-1e30);
        int cmpNaN = ((0.0f / 0.0f) < 1.0f) ? 10 : 20; // FCMPG -> NaN -> 1 -> false -> 20
        int shift = (-16 >>> 2) + (a << 3);
        return (long) ovf + minDiv + minRem + lMinDiv + f2iNan + d2iSat + d2lNegSat + cmpNaN + shift + (long) b + (long) f + (long) d;
    }

    public static String arraysAndMultiArrays(int n) {
        boolean[] flags = new boolean[4];
        flags[0] = true;
        flags[1] = false;
        flags[2] = true;
        byte[] bytes = new byte[]{-128, -1, 0, 127};
        char[] chars = new char[]{'A', '\u0416'};
        int[][] matrix = new int[2][3];
        matrix[1][2] = n * 9;
        String[][][] cube = new String[2][1][2];
        cube[1][0][1] = "cube_" + matrix[1][2];
        return flags[0] + ":" + flags[1] + ":" + bytes[0] + ":" + bytes[3] + ":" + chars[1] + ":" + cube[1][0][1];
    }

    public static String tryCatchFinallyTest(int divisor) {
        StringBuilder trace = new StringBuilder();
        try {
            trace.append("T");
            int x = 100 / divisor;
            trace.append(x);
        } catch (ArithmeticException ex) {
            trace.append("C_ARITH");
        } catch (RuntimeException ex) {
            trace.append("C_RT");
        } finally {
            trace.append("_F");
        }
        try {
            String s = null;
            trace.append(s.length());
        } catch (NullPointerException npe) {
            trace.append("_NPE");
        }
        return trace.toString();
    }

    public static String lambdasAndStrings(List<Integer> input, int multiplier) {
        List<Integer> copy = new ArrayList<>(input);
        copy.removeIf(v -> (v & 1) == 0);
        IntUnaryOperator fn = x -> x * multiplier + 3;
        int sum = 0;
        for (int v : copy) {
            sum += fn.applyAsInt(v);
        }
        Vec3 v3 = new Vec3(3.0, 4.0, 0.0);
        String unicode = "Привет!\u0000OK";
        return "sum=" + sum + "|len=" + v3.lengthSq() + "|u=" + unicode.length() + ":" + unicode.charAt(0);
    }

    public synchronized int synchronizedAdd(int delta) {
        synchronized (this) {
            syncCounter += delta;
            return syncCounter;
        }
    }

    public static int loopLocalRefStress(int iters) {
        int acc = 0;
        for (int i = 0; i < iters; i++) {
            String s = "v" + i;
            Object[] arr = new Object[]{s};
            acc += ((String) arr[0]).length();
        }
        return acc;
    }

    public static int computeBenchmark(int rounds) {
        int h = 0x1234567;
        for (int i = 0; i < rounds; i++) {
            h = (h * 1664525) ^ (i + 1013904223);
            h = Integer.rotateLeft(h, 5);
        }
        return h;
    }
}
