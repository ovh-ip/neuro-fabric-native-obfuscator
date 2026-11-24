package dev.hydro.testmod;

import dev.neuro.nativeobfuscator.Native;
import dev.neuro.nativeobfuscator.NotNative;

/**
 * Class WITH @Native at class level: all methods go to .dll EXCEPT @NotNative ones.
 */
@Native
public class AnnotatedClassWithExclusion {

    private final int secret;

    public AnnotatedClassWithExclusion(int seed) {
        this.secret = (seed * 13) ^ 0xCAFE;
    }

    public int getIncludedSecret() {
        return secret + 42;
    }

    @NotNative
    public int fastNotNative(int x) {
        return x * 2 + 1;
    }
}
