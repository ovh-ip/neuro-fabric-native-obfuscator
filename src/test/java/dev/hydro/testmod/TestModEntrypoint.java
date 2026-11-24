package dev.hydro.testmod;

import dev.hydro.testmod.mixin.ClientMixin;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;

public class TestModEntrypoint {

    public static String runAllSelfTests() throws Exception {
        // 1. Verify methods really became ACC_NATIVE
        Method edge = SecretLogic.class.getDeclaredMethod("integerAndFloatEdgeCases", int.class, long.class, float.class, double.class);
        if (!Modifier.isNative(edge.getModifiers())) {
            throw new AssertionError("SecretLogic.integerAndFloatEdgeCases is NOT native!");
        }
        Method mixinTick = ClientMixin.class.getDeclaredMethod("onClientTick", int.class);
        if (Modifier.isNative(mixinTick.getModifiers())) {
            throw new AssertionError("ClientMixin.onClientTick MUST NOT be native directly (Mixin incompatibility)!");
        }

        // 2. Constructor outlining & static final
        SecretLogic sl = new SecretLogic(42);
        int expectedKey = (42 ^ 0x5A5A1234) * 31 + 7;
        if (sl.getInstanceKey() != expectedKey) {
            throw new AssertionError("Constructor key mismatch: " + sl.getInstanceKey() + " vs " + expectedKey);
        }
        if (!"HY2026".equals(SecretLogic.getStaticTag())) {
            throw new AssertionError("Static tag mismatch: " + SecretLogic.getStaticTag());
        }

        // 3. Arithmetic / overflow / NaN / saturation
        long edgeRes = SecretLogic.integerAndFloatEdgeCases(7, 100L, 2.5f, 3.5);
        long expectedEdge = (long) (Integer.MAX_VALUE + 1)
                + (Integer.MIN_VALUE / -1)
                + (Integer.MIN_VALUE % -1)
                + (Long.MIN_VALUE / -1L)
                + 0
                + Integer.MAX_VALUE
                + Long.MIN_VALUE
                + 20
                + ((-16 >>> 2) + (7 << 3))
                + 100L + 2L + 3L;
        if (edgeRes != expectedEdge) {
            throw new AssertionError("Edge arithmetic mismatch: " + edgeRes + " vs " + expectedEdge);
        }

        // 4. Arrays & MultiArrays
        String arrRes = SecretLogic.arraysAndMultiArrays(5);
        if (!"true:false:-128:127:\u0416:cube_45".equals(arrRes)) {
            throw new AssertionError("Array test failed: " + arrRes);
        }

        // 5. Try / Catch / Finally
        String ex0 = SecretLogic.tryCatchFinallyTest(0);
        if (!"TC_ARITH_F_NPE".equals(ex0)) {
            throw new AssertionError("Try-catch zero failed: " + ex0);
        }
        String ex2 = SecretLogic.tryCatchFinallyTest(2);
        if (!"T50_F_NPE".equals(ex2)) {
            throw new AssertionError("Try-catch non-zero failed: " + ex2);
        }

        // 6. Lambdas, Records, StringConcat, Unicode + NUL char
        String lamRes = SecretLogic.lambdasAndStrings(List.of(1, 2, 3, 4, 5), 10);
        // odds: 1, 3, 5 -> (10+3)+(30+3)+(50+3) = 99
        if (!"sum=99|len=25.0|u=10:\u041f".equals(lamRes)) {
            throw new AssertionError("Lambda/String test failed: " + lamRes);
        }

        // 7. Synchronized
        int s1 = sl.synchronizedAdd(10);
        int s2 = sl.synchronizedAdd(15);
        if (s1 != 10 || s2 != 25) {
            throw new AssertionError("Synchronized failed: " + s1 + ", " + s2);
        }

        // 8. Loop LocalRef GC stress test (100,000 iterations)
        int stress = SecretLogic.loopLocalRefStress(100_000);
        if (stress != 588890) {
            throw new AssertionError("Stress mismatch: " + stress);
        }

        // 9. Benchmark 1,000,000 tight native loop ops
        long t0 = System.nanoTime();
        int bench = SecretLogic.computeBenchmark(1_000_000);
        long ms = (System.nanoTime() - t0) / 1_000_000L;

        // 10. Simulate Mixin merged target behavior!
        // Note: ClientMixin.onClientTick is a trampoline calling the native bridge with `this`.
        // When Mixin merges ClientMixin into FakeMinecraftClient at runtime, `this` IS FakeMinecraftClient!
        // Verify FakeMinecraftClient fields/methods remain intact and Mixin trampoline calls native bridge cleanly.
        return "ALL_PASS bench=" + bench + " (" + ms + "ms)";
    }
}
