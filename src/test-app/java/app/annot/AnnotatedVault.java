package app.annot;

import dev.neuro.nativeobfuscator.Native;
import dev.neuro.nativeobfuscator.NativeVM;
import dev.neuro.nativeobfuscator.NotNative;

public class AnnotatedVault {

    @NativeVM
    public static int vmSecret(int a, int b) {
        int s = a * 13 + b * 7;
        for (int i = 0; i < 4; i++) {
            s ^= (i * 31 + a);
        }
        return s;
    }

    @Native
    public static String cffSecret(String name) {
        return "VAULT:" + name + ":" + vmSecret(5, 9);
    }

    @NotNative
    public static int plainHelper(int x) {
        return x + 100;
    }
}
