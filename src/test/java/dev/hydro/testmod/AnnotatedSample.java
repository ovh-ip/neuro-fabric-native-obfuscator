package dev.hydro.testmod;

import dev.neuro.nativeobfuscator.Native;
import dev.neuro.nativeobfuscator.NativeVM;

import java.util.List;

/**
 * Class WITHOUT @Native on the class itself: ONLY @Native / @NativeVM methods should go to .dll
 * when running with -a / --annotations!
 */
public class AnnotatedSample {

    @Native
    public static int nativeOnlyAdd(int a, int b) {
        return (a ^ 0x5A5A) + b * 7;
    }

    @NativeVM
    public static String vmOnlyTransform(String s, int n) {
        return "VM[" + s + ":" + (n * 3) + "]";
    }

    @Native
    public static int nativeWithLambda(List<Integer> nums) {
        return nums.stream().mapToInt(x -> x * 3 + 1).sum();
    }

    public static int plainJavaAdd(int a, int b) {
        return a + b;
    }
}
