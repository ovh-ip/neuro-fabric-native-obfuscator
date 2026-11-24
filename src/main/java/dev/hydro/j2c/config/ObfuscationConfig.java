package dev.hydro.j2c.config;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public final class ObfuscationConfig {

    public enum ProtectionTier {
        /** Fast native execution: encrypted JNI/strings + MBA constants + minimal flattening. */
        FAST,
        /** Balanced maximum protection + high FPS: full CFF + opaque predicates + bogus blocks + MBA + encrypted JNI. */
        STRONG,
        /** Maximum irreversibility: full CFF + custom randomized Native VM for eligible methods + anti-debug/dump/tamper. */
        ULTRA
    }

    private Path inputJar;
    private Path outputJar;
    private Path outputDll;
    private Path jdkHome;
    private String compilerPath;
    private String stripPath;

    private ProtectionTier tier = ProtectionTier.STRONG;
    private boolean embedDll = true;
    private boolean encryptEmbeddedDll = false;
    private boolean fuckedClasses = true;
    private int junkCount = 300;
    private String externalDllPath = "";
    private boolean processMixins = true;
    private boolean outlineConstructors = true;
    private boolean obfuscateStubNames = true;
    private boolean stripDebugInfo = true;

    private boolean antiDebug = true;
    private boolean antiDump = true;
    private boolean antiTamper = true;

    private int compileJobs = Math.max(2, Runtime.getRuntime().availableProcessors());
    private int methodsPerShard = 32;
    private long seed = new SecureRandom().nextLong();

    private final List<String> includePatterns = new ArrayList<>();
    private final List<String> excludePatterns = new ArrayList<>();
    private final List<String> vmIncludePatterns = new ArrayList<>();
    private final List<String> vmExcludePatterns = new ArrayList<>();

    public Path getInputJar() { return inputJar; }
    public void setInputJar(Path inputJar) { this.inputJar = inputJar; }

    public Path getOutputJar() { return outputJar; }
    public void setOutputJar(Path outputJar) { this.outputJar = outputJar; }

    public Path getOutputDll() { return outputDll; }
    public void setOutputDll(Path outputDll) { this.outputDll = outputDll; }

    public Path getJdkHome() { return jdkHome; }
    public void setJdkHome(Path jdkHome) { this.jdkHome = jdkHome; }

    public String getCompilerPath() { return compilerPath; }
    public void setCompilerPath(String compilerPath) { this.compilerPath = compilerPath; }

    public String getStripPath() { return stripPath; }
    public void setStripPath(String stripPath) { this.stripPath = stripPath; }

    public ProtectionTier getTier() { return tier; }
    public void setTier(ProtectionTier tier) { this.tier = tier; }

    public boolean isEmbedDll() { return embedDll; }
    public void setEmbedDll(boolean embedDll) { this.embedDll = embedDll; }

    public boolean isEncryptEmbeddedDll() { return encryptEmbeddedDll; }
    public void setEncryptEmbeddedDll(boolean encryptEmbeddedDll) { this.encryptEmbeddedDll = encryptEmbeddedDll; }

    public boolean isFuckedClasses() { return fuckedClasses; }
    public void setFuckedClasses(boolean fuckedClasses) { this.fuckedClasses = fuckedClasses; }

    public int getJunkCount() { return junkCount; }
    public void setJunkCount(int junkCount) { this.junkCount = Math.max(0, junkCount); }

    public String getExternalDllPath() { return externalDllPath; }
    public void setExternalDllPath(String externalDllPath) { this.externalDllPath = externalDllPath; }

    public boolean isProcessMixins() { return processMixins; }
    public void setProcessMixins(boolean processMixins) { this.processMixins = processMixins; }

    public boolean isOutlineConstructors() { return outlineConstructors; }
    public void setOutlineConstructors(boolean outlineConstructors) { this.outlineConstructors = outlineConstructors; }

    public boolean isObfuscateStubNames() { return obfuscateStubNames; }
    public void setObfuscateStubNames(boolean obfuscateStubNames) { this.obfuscateStubNames = obfuscateStubNames; }

    public boolean isStripDebugInfo() { return stripDebugInfo; }
    public void setStripDebugInfo(boolean stripDebugInfo) { this.stripDebugInfo = stripDebugInfo; }

    public boolean isAntiDebug() { return antiDebug; }
    public void setAntiDebug(boolean antiDebug) { this.antiDebug = antiDebug; }

    public boolean isAntiDump() { return antiDump; }
    public void setAntiDump(boolean antiDump) { this.antiDump = antiDump; }

    public boolean isAntiTamper() { return antiTamper; }
    public void setAntiTamper(boolean antiTamper) { this.antiTamper = antiTamper; }

    public int getCompileJobs() { return compileJobs; }
    public void setCompileJobs(int compileJobs) { this.compileJobs = Math.max(1, compileJobs); }

    public int getMethodsPerShard() { return methodsPerShard; }
    public void setMethodsPerShard(int methodsPerShard) { this.methodsPerShard = Math.max(1, methodsPerShard); }

    public long getSeed() { return seed; }
    public void setSeed(long seed) { this.seed = seed; }

    public List<String> getIncludePatterns() { return includePatterns; }
    public List<String> getExcludePatterns() { return excludePatterns; }
    public List<String> getVmIncludePatterns() { return vmIncludePatterns; }
    public List<String> getVmExcludePatterns() { return vmExcludePatterns; }

    public static boolean matchesGlob(String internalName, String pattern) {
        String normPat = pattern.replace('.', '/');
        if (normPat.endsWith("/**") || normPat.endsWith("/*")) {
            String prefix = normPat.substring(0, normPat.lastIndexOf('/'));
            return internalName.equals(prefix) || internalName.startsWith(prefix + "/");
        }
        if (normPat.endsWith("/")) {
            return internalName.startsWith(normPat);
        }
        if (!normPat.contains("*")) {
            return internalName.equals(normPat) || internalName.startsWith(normPat + "/") || internalName.startsWith(normPat + "$");
        }
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < normPat.length(); i++) {
            char c = normPat.charAt(i);
            if (c == '*') {
                if (i + 1 < normPat.length() && normPat.charAt(i + 1) == '*') {
                    regex.append(".*");
                    i++;
                } else {
                    regex.append("[^/]*");
                }
            } else if ("\\.[]{}()+-^$|?".indexOf(c) >= 0) {
                regex.append('\\').append(c);
            } else {
                regex.append(c);
            }
        }
        regex.append('$');
        return internalName.matches(regex.toString());
    }
}
