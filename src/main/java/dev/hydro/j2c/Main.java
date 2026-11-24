package dev.hydro.j2c;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.jar.JarProcessor;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * CLI entrypoint for HydroJ2C — Native Java-to-C++ (.dll) + Encrypted VM Protector for Minecraft Fabric Mods.
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return;
        }

        ObfuscationConfig cfg = new ObfuscationConfig();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-i", "--input" -> cfg.setInputJar(Path.of(nextArg(args, ++i, a)));
                case "-o", "--output" -> cfg.setOutputJar(Path.of(nextArg(args, ++i, a)));
                case "-d", "--dll" -> cfg.setOutputDll(Path.of(nextArg(args, ++i, a)));
                case "--tier" -> cfg.setTier(ObfuscationConfig.ProtectionTier.valueOf(nextArg(args, ++i, a).toUpperCase()));
                case "-a", "--annotations" -> cfg.setUseAnnotations(true);
                case "-w", "--white-list" -> loadListFile(Path.of(nextArg(args, ++i, a)), cfg.getIncludePatterns());
                case "-b", "--black-list" -> loadListFile(Path.of(nextArg(args, ++i, a)), cfg.getExcludePatterns());
                case "--include" -> cfg.getIncludePatterns().add(nextArg(args, ++i, a));
                case "--exclude" -> cfg.getExcludePatterns().add(nextArg(args, ++i, a));
                case "--vm" -> cfg.getVmIncludePatterns().add(nextArg(args, ++i, a));
                case "--vm-exclude" -> cfg.getVmExcludePatterns().add(nextArg(args, ++i, a));
                case "--external-dll" -> {
                    cfg.setEmbedDll(false);
                    if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                        cfg.setExternalDllPath(args[++i]);
                    }
                }
                case "--no-embed" -> cfg.setEmbedDll(false);
                case "--encrypt-dll" -> cfg.setEncryptEmbeddedDll(true);
                case "--no-fucked" -> cfg.setFuckedClasses(false);
                case "--no-junk" -> cfg.setJunkCount(0);
                case "--junk" -> cfg.setJunkCount(Integer.parseInt(nextArg(args, ++i, a)));
                case "--no-mixins" -> cfg.setProcessMixins(false);
                case "--no-ctor-outline" -> cfg.setOutlineConstructors(false);
                case "--no-anti-debug" -> cfg.setAntiDebug(false);
                case "--no-anti-dump" -> cfg.setAntiDump(false);
                case "--no-anti-tamper" -> cfg.setAntiTamper(false);
                case "--jobs", "-j" -> cfg.setCompileJobs(Integer.parseInt(nextArg(args, ++i, a)));
                case "--jdk" -> cfg.setJdkHome(Path.of(nextArg(args, ++i, a)));
                case "--compiler" -> cfg.setCompilerPath(nextArg(args, ++i, a));
                case "--seed" -> cfg.setSeed(Long.decode(nextArg(args, ++i, a)));
                case "-h", "--help" -> { printUsage(); return; }
                default -> {
                    if (cfg.getInputJar() == null && !a.startsWith("-")) {
                        cfg.setInputJar(Path.of(a));
                    } else {
                        throw new IllegalArgumentException("Unknown option: " + a);
                    }
                }
            }
        }

        if (cfg.getInputJar() == null) {
            throw new IllegalArgumentException("Missing --input <mod.jar>");
        }
        if (cfg.getOutputJar() == null) {
            String inName = cfg.getInputJar().getFileName().toString();
            String outName = inName.endsWith(".jar")
                    ? inName.substring(0, inName.length() - 4) + "-protected.jar"
                    : inName + "-protected.jar";
            Path parent = cfg.getInputJar().toAbsolutePath().getParent();
            cfg.setOutputJar(parent.resolve(outName));
        }

        System.out.println("[HydroJ2C] Protecting: " + cfg.getInputJar());
        System.out.println("[HydroJ2C] Tier: " + cfg.getTier()
                + " | Annotations=" + cfg.isUseAnnotations()
                + " | AntiDebug=" + cfg.isAntiDebug()
                + " | AntiDump=" + cfg.isAntiDump()
                + " | AntiTamper=" + cfg.isAntiTamper()
                + " | EmbedDLL=" + cfg.isEmbedDll());

        JarProcessor.Result res = JarProcessor.process(cfg);
        System.out.println("[HydroJ2C] Done in " + res.compileTimeMs + " ms");
        System.out.println("  Total classes:       " + res.totalClasses);
        System.out.println("  Protected classes:   " + res.protectedClasses);
        System.out.println("  Encrypted .fucked:   " + res.fuckedClasses);
        System.out.println("  Junk decoy entries:  " + res.junkEntries);
        System.out.println("  CFF+MBA methods:     " + res.cffNativeMethods);
        System.out.println("  Native VM methods:   " + res.vmMethods);
        System.out.println("  Mixin bridges:       " + res.mixinBridgesCreated);
        System.out.println("  Output JAR:          " + res.outputJar);
        System.out.println("  Output DLL:          " + res.outputDll);
    }

    private static void loadListFile(Path file, List<String> target) throws Exception {
        for (String raw : Files.readAllLines(file)) {
            String line = raw.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                target.add(line);
            }
        }
    }

    private static String nextArg(String[] args, int idx, String flag) {
        if (idx >= args.length) throw new IllegalArgumentException("Missing value for " + flag);
        return args[idx];
    }

    private static void printUsage() {
        System.out.println("""
                HydroJ2C — Minecraft Fabric J2C Native (.dll) & Encrypted VM Obfuscator
                Usage:
                  hydro -i <input-mod.jar> [-o <output-mod.jar>] [-d <output.dll>] [options]

                Options:
                  -a, --annotations            Process only @Native classes/methods (and respect @NotNative / @NativeVM)
                  -w, --white-list <file>      Read whitelist class/method patterns from file
                  -b, --black-list <file>      Read blacklist class/method patterns from file
                  --tier <FAST|STRONG|ULTRA>   Protection level (default: STRONG; ULTRA adds Native VM)
                  --include <glob>             Class/package glob (auto-detected from fabric.mod.json if omitted)
                  --exclude <glob>             Exclude class/package glob
                  --vm <glob>                  Force matching classes/methods into randomized Native VM
                  --vm-exclude <glob>          Keep matching classes/methods in fast CFF native C++ instead of VM
                  --external-dll [path]        Load external .dll instead of embedding inside JAR natives/
                  --encrypt-dll                Also encrypt the DLL payload inside natives/
                  --junk <N>                   Generate N decoy .class & .fucked files in nested junk folders (default: 300)
                  --no-junk                    Disable junk classes/folders
                  --no-fucked                  Keep protected stub classes as .class instead of encrypted .fucked
                  --no-mixins                  Disable automatic @Mixin hook outlining
                  --no-ctor-outline            Disable <init> body outlining
                  --no-anti-debug              Disable PEB/NtQuery/DrX anti-debug checks
                  --no-anti-dump               Disable JNI vtable hook & anti-dump checks
                  --no-anti-tamper             Disable DLL & JAR integrity verification
                  -j, --jobs <N>               Parallel C++ compile jobs
                  --jdk <path>                 Path to JDK with jni.h
                  --compiler <path>            Path to g++/clang++
                  --seed <hex/int>             Deterministic build seed
                """);
    }
}
