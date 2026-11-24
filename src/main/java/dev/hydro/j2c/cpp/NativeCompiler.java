package dev.hydro.j2c.cpp;

import dev.hydro.j2c.config.ObfuscationConfig;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;

/**
 * Orchestrates parallel C++20 compilation via MinGW-W64 g++ into a stripped, static,
 * single-export Windows x64 DLL with zero third-party runtime DLL dependencies, and
 * writes the post-link integrity seal into g_hydro_seal_box.
 */
public final class NativeCompiler {

    public static Path detectJdkHome(ObfuscationConfig config) {
        List<Path> candidates = new ArrayList<>();
        if (config.getJdkHome() != null) candidates.add(config.getJdkHome());
        String javaHomeProp = System.getProperty("java.home");
        if (javaHomeProp != null) candidates.add(Path.of(javaHomeProp));
        String envHome = System.getenv("JAVA_HOME");
        if (envHome != null && !envHome.isBlank()) candidates.add(Path.of(envHome));
        // Scan Adoptium / standard JDK roots
        Path adoptium = Path.of("C:\\Program Files\\Eclipse Adoptium");
        if (Files.isDirectory(adoptium)) {
            try (var s = Files.list(adoptium)) {
                s.forEach(candidates::add);
            } catch (IOException ignored) {}
        }
        for (Path p : candidates) {
            if (Files.exists(p.resolve("include/jni.h")) && Files.exists(p.resolve("include/win32/jni_md.h"))) {
                return p;
            }
        }
        throw new IllegalStateException("Cannot locate JDK with include/jni.h and include/win32/jni_md.h");
    }

    public static String detectCompiler(ObfuscationConfig config) {
        if (config.getCompilerPath() != null && !config.getCompilerPath().isBlank()) {
            return config.getCompilerPath();
        }
        return "g++";
    }

    public static void compileDll(
            Path buildDir,
            Path outputDll,
            String runtimeHpp,
            String runtimeCpp,
            String vmCpp,
            String exportsDef,
            List<String> methodShards,
            byte[] symBlobBytes,
            ObfuscationConfig config) throws Exception {

        Files.createDirectories(buildDir);
        if (outputDll.getParent() != null) Files.createDirectories(outputDll.getParent());

        Path jdk = detectJdkHome(config);
        String gxx = detectCompiler(config);
        String incCommon = jdk.resolve("include").toAbsolutePath().toString();
        String incWin = jdk.resolve("include/win32").toAbsolutePath().toString();

        Files.writeString(buildDir.resolve("hydro_runtime.hpp"), runtimeHpp, StandardCharsets.UTF_8);
        Files.writeString(buildDir.resolve("hydro_runtime.cpp"), runtimeCpp, StandardCharsets.UTF_8);
        Files.writeString(buildDir.resolve("hydro_vm.cpp"), vmCpp, StandardCharsets.UTF_8);
        Files.writeString(buildDir.resolve("exports.def"), exportsDef, StandardCharsets.UTF_8);

        List<Path> cppFiles = new ArrayList<>();
        cppFiles.add(buildDir.resolve("hydro_runtime.cpp"));
        cppFiles.add(buildDir.resolve("hydro_vm.cpp"));
        for (int i = 0; i < methodShards.size(); i++) {
            Path sp = buildDir.resolve("shard_" + i + ".cpp");
            Files.writeString(sp, methodShards.get(i), StandardCharsets.UTF_8);
            cppFiles.add(sp);
        }

        List<Path> objFiles = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(config.getCompileJobs());
        List<Future<?>> futures = new ArrayList<>();

        for (Path cpp : cppFiles) {
            Path obj = buildDir.resolve(cpp.getFileName().toString().replace(".cpp", ".o"));
            objFiles.add(obj);
            futures.add(pool.submit(() -> {
                List<String> cmd = List.of(
                        gxx,
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
                        "-I" + incWin,
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
        linkCmd.add(gxx);
        linkCmd.addAll(List.of(
                "-shared", "-O2", "-fno-rtti", "-fno-exceptions",
                "-fvisibility=hidden", "-static", "-static-libgcc", "-static-libstdc++",
                "-Wl,--exclude-all-symbols", "-Wl,--gc-sections", "-s"
        ));
        for (Path o : objFiles) linkCmd.add(o.toAbsolutePath().toString());
        linkCmd.add(buildDir.resolve("exports.def").toAbsolutePath().toString());
        linkCmd.add("-o");
        linkCmd.add(outputDll.toAbsolutePath().toString());

        runTool(linkCmd, buildDir);

        // Compute FNV-1a-64 hash over symBlobBytes and patch g_hydro_seal_box.hash in the DLL
        if (config.isAntiTamper()) {
            long symHash = 0xCBF29CE484222325L;
            for (byte b : symBlobBytes) {
                symHash ^= (b & 0xFFL);
                symHash *= 0x100000001B3L;
            }
            patchSealHash(outputDll, symHash);
        }
    }

    private static void patchSealHash(Path dllPath, long symHash) throws IOException {
        byte[] bytes = Files.readAllBytes(dllPath);
        byte[] magic = new byte[8];
        ByteBuffer.wrap(magic).order(ByteOrder.LITTLE_ENDIAN).putLong(CppRuntimeEmitter.SEAL_MAGIC);
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
            Files.write(dllPath, bytes);
        }
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
