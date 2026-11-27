package dev.hydro.j2c.cpp;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.crypto.CryptoEngine;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Orchestrates C++20 compilation (direct g++/clang++ or CMake), exports cross-platform
 * Windows/Linux/macOS CMake projects, bundles prebuilt multi-OS/multi-arch natives,
 * and patches the per-build integrity seal box.
 */
public final class NativeCompiler {

    public static String stripLibNameToBase(String fileName) {
        String s = fileName;
        if (s.endsWith(".dll")) s = s.substring(0, s.length() - 4);
        else if (s.endsWith(".dylib")) s = s.substring(0, s.length() - 6);
        else if (s.endsWith(".so")) s = s.substring(0, s.length() - 3);
        if ((fileName.endsWith(".so") || fileName.endsWith(".dylib")) && s.startsWith("lib") && s.length() > 3) {
            s = s.substring(3);
        }
        return s;
    }

    public static String hostOsTag() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return "windows";
        if (os.contains("mac") || os.contains("darwin")) return "macos";
        return "linux";
    }

    public static String hostArchTag() {
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (arch.equals("amd64") || arch.equals("x86_64")) return "x86_64";
        if (arch.equals("aarch64") || arch.equals("arm64")) return "arm64";
        if (arch.equals("x86") || arch.equals("i386") || arch.equals("i686")) return "x86";
        return arch;
    }

    public static String formatHostLibFileName(String libBaseName) {
        String os = hostOsTag();
        return switch (os) {
            case "windows" -> libBaseName + ".dll";
            case "macos" -> "lib" + libBaseName + ".dylib";
            default -> "lib" + libBaseName + ".so";
        };
    }

    public static Path detectJdkHome(ObfuscationConfig config) {
        List<Path> candidates = new ArrayList<>();
        if (config.getJdkHome() != null) candidates.add(config.getJdkHome());
        String javaHomeProp = System.getProperty("java.home");
        if (javaHomeProp != null) candidates.add(Path.of(javaHomeProp));
        String envHome = System.getenv("JAVA_HOME");
        if (envHome != null && !envHome.isBlank()) candidates.add(Path.of(envHome));
        if ("windows".equals(hostOsTag())) {
            Path adoptium = Path.of("C:\\Program Files\\Eclipse Adoptium");
            if (Files.isDirectory(adoptium)) {
                try (var s = Files.list(adoptium)) {
                    s.forEach(candidates::add);
                } catch (IOException ignored) {}
            }
        }
        String osSubdir = switch (hostOsTag()) {
            case "windows" -> "win32";
            case "macos" -> "darwin";
            default -> "linux";
        };
        for (Path p : candidates) {
            if (Files.exists(p.resolve("include/jni.h"))
                    && Files.exists(p.resolve("include/" + osSubdir + "/jni_md.h"))) {
                return p;
            }
        }
        throw new IllegalStateException("Cannot locate JDK with include/jni.h and include/" + osSubdir + "/jni_md.h");
    }

    public static String detectCompiler(ObfuscationConfig config) {
        if (config.getCompilerPath() != null && !config.getCompilerPath().isBlank()) {
            return config.getCompilerPath();
        }
        return "macos".equals(hostOsTag()) ? "clang++" : "g++";
    }

    public static void compileNative(
            Path buildDir,
            Path outputLib,
            String libBaseName,
            Map<String, String> coreNativeFiles,
            String buildCfgHpp,
            String tablesCpp,
            String exportsDef,
            List<String> methodShards,
            byte[] symBlobBytes,
            CryptoEngine crypto,
            ObfuscationConfig config) throws Exception {

        Files.createDirectories(buildDir);
        if (outputLib.getParent() != null) Files.createDirectories(outputLib.getParent());

        List<Path> cppFiles = new ArrayList<>();
        for (Map.Entry<String, String> nf : coreNativeFiles.entrySet()) {
            Path p = buildDir.resolve(nf.getKey());
            Files.writeString(p, nf.getValue(), StandardCharsets.UTF_8);
            if (nf.getKey().endsWith(".cpp")) {
                cppFiles.add(p);
            }
        }
        Files.writeString(buildDir.resolve("hydro_build_cfg.hpp"), buildCfgHpp, StandardCharsets.UTF_8);
        Path tablesPath = buildDir.resolve("hydro_tables.cpp");
        Files.writeString(tablesPath, tablesCpp, StandardCharsets.UTF_8);
        cppFiles.add(tablesPath);

        Files.writeString(buildDir.resolve("exports.def"), exportsDef, StandardCharsets.UTF_8);
        boolean exportUnload = config.isServerEnabled();
        Files.writeString(buildDir.resolve("exports.map"), CMakeEmitter.emitLinuxVersionScript(exportUnload), StandardCharsets.UTF_8);
        Files.writeString(buildDir.resolve("exports.exp"), CMakeEmitter.emitMacOsExportsList(exportUnload), StandardCharsets.UTF_8);

        List<String> shardNames = new ArrayList<>();
        for (int i = 0; i < methodShards.size(); i++) {
            String sName = "shard_" + i + ".cpp";
            shardNames.add(sName);
            Path sp = buildDir.resolve(sName);
            Files.writeString(sp, methodShards.get(i), StandardCharsets.UTF_8);
            cppFiles.add(sp);
        }

        String cmakeLists = CMakeEmitter.emitCMakeLists(libBaseName, shardNames);
        Files.writeString(buildDir.resolve("CMakeLists.txt"), cmakeLists, StandardCharsets.UTF_8);
        Files.writeString(buildDir.resolve("README-BUILD.txt"), CMakeEmitter.emitBuildInstructions(libBaseName), StandardCharsets.UTF_8);

        // Optionally export clean standalone CMake project for building Linux/macOS/ARM64 targets externally
        if (config.getCmakeOutDir() != null) {
            Path cmakeOut = config.getCmakeOutDir();
            Files.createDirectories(cmakeOut);
            try (var stream = Files.list(buildDir)) {
                for (Path p : stream.toList()) {
                    if (Files.isRegularFile(p)) {
                        Files.copy(p, cmakeOut.resolve(p.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }

        Path jdk = detectJdkHome(config);
        String cxx = detectCompiler(config);

        if (config.isBuildWithCmake()) {
            compileViaCMake(buildDir, outputLib, libBaseName, jdk, cxx, config);
        } else {
            compileDirect(buildDir, outputLib, cppFiles, jdk, cxx, config);
        }

        if (config.isAntiTamper()) {
            long symHash = crypto.hash64(symBlobBytes);
            patchSealHash(outputLib, crypto.getSealMagic(), symHash);
        }
    }

    private static void compileViaCMake(
            Path buildDir,
            Path outputLib,
            String libBaseName,
            Path jdk,
            String cxx,
            ObfuscationConfig config) throws Exception {

        Path cmakeBuild = buildDir.resolve("_cmbuild");
        List<String> cfgCmd = new ArrayList<>();
        cfgCmd.add("cmake");
        cfgCmd.add("-S");
        cfgCmd.add(buildDir.toAbsolutePath().toString());
        cfgCmd.add("-B");
        cfgCmd.add(cmakeBuild.toAbsolutePath().toString());
        if (isToolAvailable("ninja")) {
            cfgCmd.add("-G");
            cfgCmd.add("Ninja");
        }
        cfgCmd.add("-DCMAKE_BUILD_TYPE=Release");
        cfgCmd.add("-DHYDRO_JDK_HOME=" + jdk.toAbsolutePath().toString().replace('\\', '/'));
        if (config.getCompilerPath() != null && !config.getCompilerPath().isBlank()) {
            cfgCmd.add("-DCMAKE_CXX_COMPILER=" + cxx);
        } else if ("windows".equals(hostOsTag()) && isToolAvailable(cxx)) {
            cfgCmd.add("-DCMAKE_CXX_COMPILER=" + cxx);
        }
        runTool(cfgCmd, buildDir);

        runTool(List.of(
                "cmake", "--build", cmakeBuild.toAbsolutePath().toString(),
                "--parallel", String.valueOf(config.getCompileJobs())
        ), buildDir);

        String expectedName = formatHostLibFileName(libBaseName);
        Path produced = null;
        try (var s = Files.walk(cmakeBuild)) {
            for (Path p : s.toList()) {
                if (Files.isRegularFile(p) && p.getFileName().toString().equalsIgnoreCase(expectedName)) {
                    produced = p;
                    break;
                }
            }
        }
        if (produced == null) {
            throw new IllegalStateException("CMake build succeeded but did not produce " + expectedName + " inside " + cmakeBuild);
        }
        Files.copy(produced, outputLib, StandardCopyOption.REPLACE_EXISTING);
    }

    private static void compileDirect(
            Path buildDir,
            Path outputLib,
            List<Path> cppFiles,
            Path jdk,
            String cxx,
            ObfuscationConfig config) throws Exception {

        String os = hostOsTag();
        String incCommon = jdk.resolve("include").toAbsolutePath().toString();
        String incOs = jdk.resolve("include/" + switch (os) {
            case "windows" -> "win32";
            case "macos" -> "darwin";
            default -> "linux";
        }).toAbsolutePath().toString();

        List<Path> objFiles = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(config.getCompileJobs());
        List<Future<?>> futures = new ArrayList<>();

        for (Path cpp : cppFiles) {
            Path obj = buildDir.resolve(cpp.getFileName().toString().replace(".cpp", ".o"));
            objFiles.add(obj);
            futures.add(pool.submit(() -> {
                List<String> cmd = List.of(
                        cxx,
                        "-std=c++20",
                        "-O2",
                        "-fno-rtti",
                        "-fno-exceptions",
                        "-fvisibility=hidden",
                        "-fno-ident",
                        "-ffunction-sections",
                        "-fdata-sections",
                        "-w",
                        "-I" + buildDir.toAbsolutePath(),
                        "-I" + incCommon,
                        "-I" + incOs,
                        "-c", cpp.toAbsolutePath().toString(),
                        "-o", obj.toAbsolutePath().toString()
                );
                runTool(cmd, buildDir);
                return null;
            }));
        }
        try {
            for (Future<?> f : futures) f.get();
        } finally {
            pool.shutdownNow();
        }

        List<String> linkCmd = new ArrayList<>();
        linkCmd.add(cxx);
        linkCmd.addAll(List.of("-shared", "-O2", "-fno-rtti", "-fno-exceptions", "-fvisibility=hidden"));
        if ("windows".equals(os)) {
            linkCmd.addAll(List.of("-static", "-static-libgcc", "-static-libstdc++", "-Wl,--exclude-all-symbols", "-Wl,--gc-sections", "-s"));
        } else if ("macos".equals(os)) {
            linkCmd.addAll(List.of("-Wl,-exported_symbols_list," + buildDir.resolve("exports.exp").toAbsolutePath(), "-Wl,-dead_strip", "-Wl,-x"));
        } else {
            linkCmd.addAll(List.of("-static-libgcc", "-static-libstdc++", "-Wl,--version-script=" + buildDir.resolve("exports.map").toAbsolutePath(), "-Wl,--gc-sections", "-Wl,-s"));
        }
        for (Path o : objFiles) linkCmd.add(o.toAbsolutePath().toString());
        if ("windows".equals(os)) {
            linkCmd.add(buildDir.resolve("exports.def").toAbsolutePath().toString());
        } else if ("linux".equals(os)) {
            linkCmd.add("-ldl");
            linkCmd.add("-lpthread");
        }
        linkCmd.add("-o");
        linkCmd.add(outputLib.toAbsolutePath().toString());

        runTool(linkCmd, buildDir);
    }

    /**
     * Collects prebuilt multi-OS/multi-arch native libraries from --natives-dir and maps them
     * cleanly into JAR resource paths like natives/linux-x86_64/libfoo.so, natives/macos-arm64/libfoo.dylib, etc.
     */
    public static Map<String, byte[]> collectPrebuiltNatives(Path dir, String libBaseName) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (dir == null || !Files.isDirectory(dir)) return out;
        try (var walk = Files.walk(dir)) {
            for (Path p : walk.toList()) {
                if (!Files.isRegularFile(p)) continue;
                String fn = p.getFileName().toString();
                String low = fn.toLowerCase(Locale.ROOT);
                if (!low.endsWith(".dll") && !low.endsWith(".so") && !low.endsWith(".dylib")) continue;

                String rel = dir.toAbsolutePath().relativize(p.toAbsolutePath()).toString().replace('\\', '/').toLowerCase(Locale.ROOT);
                String os;
                if (low.endsWith(".dll")) os = "windows";
                else if (low.endsWith(".dylib")) os = "macos";
                else os = "linux";

                String arch = detectArchHint(rel);
                String canonicalFile = switch (os) {
                    case "windows" -> libBaseName + ".dll";
                    case "macos" -> "lib" + libBaseName + ".dylib";
                    default -> "lib" + libBaseName + ".so";
                };
                String targetPath = arch != null
                        ? "natives/" + os + "-" + arch + "/" + canonicalFile
                        : ("macos".equals(os) && rel.contains("universal")
                            ? "natives/macos/" + canonicalFile
                            : "natives/" + os + "-" + hostArchTag() + "/" + canonicalFile);
                out.put(targetPath, Files.readAllBytes(p));
            }
        }
        return out;
    }

    private static String detectArchHint(String pathLower) {
        if (pathLower.contains("aarch64") || pathLower.contains("arm64")) return "arm64";
        if (pathLower.contains("x86_64") || pathLower.contains("amd64") || pathLower.contains("x64")) return "x86_64";
        if (pathLower.contains("i386") || pathLower.contains("i686") || pathLower.contains("win32") || pathLower.matches(".*[/\\\\_-]x86[/\\\\_-].*")) return "x86";
        return null;
    }

    private static boolean isToolAvailable(String tool) {
        try {
            Process p = new ProcessBuilder(tool, "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void patchSealHash(Path libPath, long sealMagic, long symHash) throws IOException {
        byte[] bytes = Files.readAllBytes(libPath);
        byte[] magic = new byte[8];
        ByteBuffer.wrap(magic).order(ByteOrder.LITTLE_ENDIAN).putLong(sealMagic);
        int found = -1;
        for (int i = 0; i <= bytes.length - 16; i++) {
            boolean match = true;
            for (int j = 0; j < 8; j++) {
                if (bytes[i + j] != magic[j]) { match = false; break; }
            }
            if (match) {
                found = i;
                break;
            }
        }
        if (found >= 0) {
            ByteBuffer.wrap(bytes, found + 8, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(symHash);
        }
        boolean scrubbed = scrubPeTimestamps(bytes);
        if (found >= 0 || scrubbed) {
            Files.write(libPath, bytes);
        }
    }

    /** Zeroes PE COFF/Export/Debug timestamps and clears the Debug directory entry without touching code or SEH. */
    private static boolean scrubPeTimestamps(byte[] bytes) {
        if (bytes.length < 0x40 || bytes[0] != 'M' || bytes[1] != 'Z') return false;
        ByteBuffer bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int lfanew = bb.getInt(0x3C);
        if (lfanew < 0x40 || lfanew + 24 > bytes.length) return false;
        if (bb.getInt(lfanew) != 0x00004550) return false; // "PE\0\0"

        int numSections = bb.getShort(lfanew + 6) & 0xFFFF;
        int optSize = bb.getShort(lfanew + 20) & 0xFFFF;
        bb.putInt(lfanew + 8, 0);

        int optOff = lfanew + 24;
        if (optOff + optSize > bytes.length || optSize < 96) return true;
        int magic = bb.getShort(optOff) & 0xFFFF;
        int dataDirOff;
        int numDirs;
        if (magic == 0x20B) {
            if (optSize < 112) return true;
            numDirs = bb.getInt(optOff + 108);
            dataDirOff = optOff + 112;
        } else if (magic == 0x10B) {
            numDirs = bb.getInt(optOff + 92);
            dataDirOff = optOff + 96;
        } else {
            return true;
        }
        int secTableOff = optOff + optSize;
        if (secTableOff + numSections * 40 > bytes.length) return true;

        if (numDirs > 0 && dataDirOff + 8 <= bytes.length) {
            int expRva = bb.getInt(dataDirOff);
            int expSize = bb.getInt(dataDirOff + 4);
            if (expRva > 0 && expSize >= 8) {
                int expOff = rvaToFileOffset(bb, secTableOff, numSections, expRva);
                if (expOff >= 0 && expOff + 8 <= bytes.length) {
                    bb.putInt(expOff + 4, 0);
                }
            }
        }
        if (numDirs > 6 && dataDirOff + 6 * 8 + 8 <= bytes.length) {
            int dbgRva = bb.getInt(dataDirOff + 6 * 8);
            int dbgSize = bb.getInt(dataDirOff + 6 * 8 + 4);
            if (dbgRva > 0 && dbgSize >= 28) {
                int dbgOff = rvaToFileOffset(bb, secTableOff, numSections, dbgRva);
                if (dbgOff >= 0 && dbgOff + dbgSize <= bytes.length) {
                    for (int off = dbgOff; off + 28 <= dbgOff + dbgSize; off += 28) {
                        bb.putInt(off + 4, 0);
                    }
                }
            }
            bb.putInt(dataDirOff + 6 * 8, 0);
            bb.putInt(dataDirOff + 6 * 8 + 4, 0);
        }
        return true;
    }

    private static int rvaToFileOffset(ByteBuffer bb, int secTableOff, int numSections, int rva) {
        for (int i = 0; i < numSections; i++) {
            int s = secTableOff + i * 40;
            int virtSize = bb.getInt(s + 8);
            int virtAddr = bb.getInt(s + 12);
            int rawSize = bb.getInt(s + 16);
            int rawPtr = bb.getInt(s + 20);
            int span = Math.max(virtSize, rawSize);
            if (rva >= virtAddr && rva < virtAddr + span) {
                int delta = rva - virtAddr;
                if (delta < rawSize) return rawPtr + delta;
            }
        }
        return -1;
    }

    private static void runTool(List<String> cmd, Path cwd) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(cwd.toFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) {
            throw new IllegalStateException("Compiler failed (" + code + "): " + String.join(" ", cmd) + "\n" + output);
        }
    }
}
