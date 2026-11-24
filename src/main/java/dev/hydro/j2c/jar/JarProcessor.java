package dev.hydro.j2c.jar;

import dev.hydro.j2c.analysis.ControlFlowGraph;
import dev.hydro.j2c.analysis.FrameAnalyzer;
import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.cpp.CppMethodEmitter;
import dev.hydro.j2c.cpp.CppRuntimeEmitter;
import dev.hydro.j2c.cpp.NativeCompiler;
import dev.hydro.j2c.crypto.CryptoEngine;
import dev.hydro.j2c.crypto.SymbolPool;
import dev.hydro.j2c.fabric.FabricMetadata;
import dev.hydro.j2c.fabric.MixinOutliner;
import dev.hydro.j2c.preprocess.AnnotationFilter;
import dev.hydro.j2c.preprocess.ConstructorOutliner;
import dev.hydro.j2c.preprocess.IndyLowerer;
import dev.hydro.j2c.preprocess.JavaPreHardener;
import dev.hydro.j2c.vm.VmCompiler;
import dev.hydro.j2c.vm.VmIsa;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Frame;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.ZipEntry;

/**
 * End-to-end J2C & Native VM pipeline for Java / Minecraft Fabric mod JARs.
 */
public final class JarProcessor implements Opcodes {

    public static final class Result {
        public int totalClasses;
        public int protectedClasses;
        public int fuckedClasses;
        public int junkEntries;
        public int cffNativeMethods;
        public int vmMethods;
        public int mixinBridgesCreated;
        public long compileTimeMs;
        public Path outputJar;
        public Path outputDll;
    }

    public static Result process(ObfuscationConfig config) throws Exception {
        long t0 = System.currentTimeMillis();
        Random rng = new Random(config.getSeed());
        CryptoEngine crypto = new CryptoEngine(config.getSeed());
        SymbolPool pool = new SymbolPool(crypto);
        VmIsa vmIsa = new VmIsa(rng);

        Map<String, byte[]> resources = new LinkedHashMap<>();
        Map<String, ClassNode> classes = new LinkedHashMap<>();

        try (JarInputStream jis = new JarInputStream(Files.newInputStream(config.getInputJar()))) {
            Manifest mf = jis.getManifest();
            if (mf != null) {
                ByteArrayOutputStream mbo = new ByteArrayOutputStream();
                mf.write(mbo);
                resources.put("META-INF/MANIFEST.MF", mbo.toByteArray());
            }
            JarEntry entry;
            while ((entry = jis.getNextJarEntry()) != null) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                byte[] data = jis.readAllBytes();
                if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    ClassNode cn = new ClassNode();
                    new ClassReader(data).accept(cn, ClassReader.EXPAND_FRAMES);
                    classes.put(cn.name, cn);
                } else if (!"META-INF/MANIFEST.MF".equals(name)) {
                    resources.put(name, data);
                }
            }
        }

        FabricMetadata fabricMeta = FabricMetadata.parse(resources);
        if (config.getIncludePatterns().isEmpty() && fabricMeta.isFabricMod() && !fabricMeta.getDetectedPackages().isEmpty()) {
            for (String p : fabricMeta.getDetectedPackages()) {
                config.getIncludePatterns().add(p + "/**");
            }
        }

        String randTag = Long.toUnsignedString(rng.nextLong(), 36);
        String loaderInternal = "dev/hydro/rt/H_" + randTag;
        String regMethodName = "r_" + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFL, 36);
        String verifyMethodName = "v_" + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFL, 36);
        String bootMethodName = "b_" + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFL, 36);

        // 1. Outline Fabric @Mixin hook bodies into synthetic bridge classes
        Map<MethodNode, MixinOutliner.MixinContext> mixinBridgeContexts = new IdentityHashMap<>();
        Set<ClassNode> generatedMixinBridges = new HashSet<>();
        Set<String> mixinTargets = new HashSet<>();
        if (config.isProcessMixins()) {
            List<ClassNode> extraBridges = MixinOutliner.outlineMixins(
                    classes.values(), fabricMeta, config, mixinBridgeContexts, generatedMixinBridges,
                    mixinTargets, loaderInternal, bootMethodName, rng);
            for (ClassNode b : extraBridges) classes.put(b.name, b);
        }

        // 2. Select target classes and collect lambda/annotation targets
        if (!config.isUseAnnotations()) {
            boolean foundNativeAnn = false;
            for (ClassNode cn : classes.values()) {
                if (AnnotationFilter.hasClassNative(cn)) { foundNativeAnn = true; break; }
                if (cn.methods != null) {
                    for (MethodNode mn : cn.methods) {
                        if (AnnotationFilter.hasMethodNative(mn)) { foundNativeAnn = true; break; }
                    }
                }
                if (foundNativeAnn) break;
            }
            if (foundNativeAnn) {
                System.out.println("[HydroJ2C] Note: @Native annotations detected; pass -a / --annotations to compile ONLY annotated classes/methods.");
            }
        }

        Set<ClassNode> targetClasses = new LinkedHashSet<>();
        for (ClassNode cn : classes.values()) {
            if (generatedMixinBridges.contains(cn) || shouldIncludeClass(cn, fabricMeta, config)) {
                targetClasses.add(cn);
            }
        }

        Set<MethodNode> nonNativeHelpers = Collections.newSetFromMap(new IdentityHashMap<>());
        Set<MethodNode> outlinedCtorBodies = Collections.newSetFromMap(new IdentityHashMap<>());
        Map<ClassNode, Set<MethodNode>> classEligibleMethods = new IdentityHashMap<>();

        for (ClassNode cn : targetClasses) {
            if (config.isStripDebugInfo()) {
                JavaPreHardener.stripDebugInfo(cn);
            }
            Set<MethodNode> lambdas = AnnotationFilter.collectLambdaTargets(cn, config);
            Set<MethodNode> eligibleSet = Collections.newSetFromMap(new IdentityHashMap<>());
            if (cn.methods != null) {
                for (MethodNode mn : cn.methods) {
                    if (generatedMixinBridges.contains(cn)
                            || AnnotationFilter.shouldProcessMethod(cn, mn, config, lambdas)) {
                        eligibleSet.add(mn);
                    }
                }
            }
            IndyLowerer.lowerClass(cn, nonNativeHelpers, eligibleSet);
            if (config.isOutlineConstructors() && !MixinOutliner.isMixinClass(cn, fabricMeta)) {
                ConstructorOutliner.outlineConstructors(cn, config, outlinedCtorBodies);
                eligibleSet.addAll(outlinedCtorBodies);
            }
            classEligibleMethods.put(cn, eligibleSet);
        }

        // 3. Compile methods into Flattened C++ or Encrypted Native VM
        Path outDll = config.getOutputDll();
        if (outDll == null) {
            String base = config.getOutputJar().getFileName().toString().replaceAll("\\.jar$", "");
            outDll = config.getOutputJar().toAbsolutePath().getParent().resolve(base + ".dll");
            config.setOutputDll(outDll);
        }
        String dllName = outDll.getFileName().toString();
        String embeddedResPath = "natives/" + dllName;
        long dllEncKey = rng.nextLong();

        List<String> methodCpus = new ArrayList<>();
        List<VmCompiler.CompiledVmMethod> vmMethods = new ArrayList<>();
        List<CppRuntimeEmitter.RegisteredClass> regClasses = new ArrayList<>();

        int classIdSeq = 1;
        int fnSeq = 0;
        int cffCount = 0;
        int vmCount = 0;

        for (ClassNode cn : targetClasses) {
            boolean isMixin = MixinOutliner.isMixinClass(cn, fabricMeta);
            if (isMixin && config.isProcessMixins()) continue;

            Set<MethodNode> eligibleSet = classEligibleMethods.getOrDefault(cn, Set.of());
            List<CppRuntimeEmitter.RegisteredMethod> regMethodsForClass = new ArrayList<>();
            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (!isEligibleMethod(cn, mn, nonNativeHelpers)) continue;
                if (!eligibleSet.contains(mn) && !outlinedCtorBodies.contains(mn)) continue;

                Frame<FrameAnalyzer.TypedValue>[] frames;
                try {
                    frames = FrameAnalyzer.analyze(cn.name, mn);
                } catch (Exception e) {
                    continue;
                }

                String cFuncName = "hy_fn_" + (fnSeq++);
                MixinOutliner.MixinContext mCtx = mixinBridgeContexts.get(mn);

                boolean useVm = shouldUseVm(cn, mn, mCtx, config);
                if (useVm) {
                    try {
                        VmCompiler.CompiledVmMethod vm = VmCompiler.compile(
                                vmMethods.size(), cn.name, mn, cFuncName, frames, vmIsa, pool);
                        vmMethods.add(vm);
                        regMethodsForClass.add(new CppRuntimeEmitter.RegisteredMethod(mn.name, mn.desc, cFuncName));
                        ClassRewriter.makeMethodNative(mn);
                        vmCount++;
                        continue;
                    } catch (UnsupportedOperationException ex) {
                        // Fall through to full C++ emitter
                    }
                }

                try {
                    ControlFlowGraph cfg = ControlFlowGraph.build(mn, frames, rng);
                    String cpp = CppMethodEmitter.emitMethod(
                            cn.name, mn, cFuncName, frames, cfg, mCtx, pool, crypto, config, rng);
                    methodCpus.add(cpp);
                    regMethodsForClass.add(new CppRuntimeEmitter.RegisteredMethod(mn.name, mn.desc, cFuncName));
                    ClassRewriter.makeMethodNative(mn);
                    cffCount++;
                } catch (Exception ex) {
                    // Preserve safely
                }
            }

            if (!regMethodsForClass.isEmpty()) {
                int cid = classIdSeq++;
                regClasses.add(new CppRuntimeEmitter.RegisteredClass(cid, cn.name, regMethodsForClass));
                ClassRewriter.injectClassRegistration(cn, cid, loaderInternal, regMethodName);
            }
        }

        // Clean @Native / @NotNative / @NativeVM annotations from output classes and drop bundled annotation classes
        classes.keySet().removeIf(name ->
                name.startsWith("dev/neuro/nativeobfuscator/")
                        || name.startsWith("by/radioegor146/nativeobfuscator/"));
        for (ClassNode cn : classes.values()) {
            AnnotationFilter.cleanAnnotations(cn);
        }

        // 4. Populate junk classes, nested junk directories, and decoy .fucked blobs
        List<String> fuckedDirs = new ArrayList<>();
        int resBeforeJunk = resources.size();
        JunkGenerator.populateJunk(resources, classes.keySet(), fuckedDirs, config.getJunkCount(), rng);
        int junkAdded = resources.size() - resBeforeJunk;

        // 5. Generate HLoader + serialize classes (encrypting eligible target classes into .fucked!)
        byte[] loaderBytes = ClassRewriter.generateLoaderClass(
                loaderInternal, regMethodName, verifyMethodName, bootMethodName,
                embeddedResPath, dllEncKey, config);

        Map<String, byte[]> finalClassBytes = new LinkedHashMap<>();
        List<ClassNode> fuckedCandidates = new ArrayList<>();

        for (ClassNode cn : classes.values()) {
            boolean mustStayClass = !config.isFuckedClasses()
                    || !targetClasses.contains(cn)
                    || fabricMeta.getEntrypointClasses().contains(cn.name)
                    || MixinOutliner.isMixinClass(cn, fabricMeta)
                    || mixinTargets.contains(cn.name);
            if (mustStayClass) {
                finalClassBytes.put(cn.name + ".class", ClassRewriter.writeClass(cn, classes));
            } else {
                fuckedCandidates.add(cn);
            }
        }
        finalClassBytes.put(loaderInternal + ".class", loaderBytes);

        // Topologically sort .fucked classes (superclasses, interfaces, outer NestHost before subclasses/inners)
        List<ClassNode> sortedFucked = topoSortClasses(fuckedCandidates);
        List<CppRuntimeEmitter.FuckedEntry> fuckedEntries = new ArrayList<>();

        for (ClassNode cn : sortedFucked) {
            byte[] rawBytes = ClassRewriter.writeClass(cn, classes);
            long fileSeed = rng.nextLong();
            long mac = fnvUpdate(0xCBF29CE484222325L, rawBytes);
            byte[] encBytes = ClassRewriter.encryptFuckedClass(rawBytes, fileSeed);

            String dir = fuckedDirs.isEmpty()
                    ? (cn.name.contains("/") ? cn.name.substring(0, cn.name.lastIndexOf('/')) : "dev/hydro/v4")
                    : fuckedDirs.get(rng.nextInt(fuckedDirs.size()));
            String resPath;
            do {
                resPath = dir + "/" + Long.toUnsignedString(rng.nextLong(), 36) + ".fucked";
            } while (resources.containsKey(resPath));

            resources.put(resPath, encBytes);
            fuckedEntries.add(new CppRuntimeEmitter.FuckedEntry(cn.name, resPath, rawBytes.length, fileSeed, mac));
        }

        // Compute JAR integrity fingerprint over HLoader + fabric.mod.json (if present)
        List<String> verifyResources = new ArrayList<>();
        long jarHash = 0xCBF29CE484222325L;
        if (resources.containsKey("fabric.mod.json")) {
            verifyResources.add("fabric.mod.json");
            jarHash = fnvUpdate(jarHash, resources.get("fabric.mod.json"));
        }
        verifyResources.add(loaderInternal + ".class");
        jarHash = fnvUpdate(jarHash, loaderBytes);

        // 6. Partition C++ methods into parallel compilation shards
        List<String> shards = new ArrayList<>();
        int perShard = config.getMethodsPerShard();
        for (int i = 0; i < methodCpus.size(); i += perShard) {
            StringBuilder ssb = new StringBuilder();
            ssb.append("#include \"hydro_runtime.hpp\"\n\n");
            for (int k = i; k < Math.min(methodCpus.size(), i + perShard); k++) {
                ssb.append(methodCpus.get(k));
            }
            shards.add(ssb.toString());
        }

        String header = CppRuntimeEmitter.emitHeader();
        String runtimeCpp = CppRuntimeEmitter.emitRuntimeCpp(
                pool, crypto, regClasses, fuckedEntries,
                loaderInternal, regMethodName, verifyMethodName,
                jarHash, verifyResources, config);
        String vmCpp = CppRuntimeEmitter.emitVmCppWithHelpers(vmMethods, vmIsa, crypto);
        String exportsDef = CppRuntimeEmitter.emitExportsDef();

        byte[] symBlobBytes = concatSymBlob(pool);

        // 7. Compile native Windows x64 DLL
        Path buildDir = Files.createTempDirectory("hydro_cpp_");
        try {
            NativeCompiler.compileDll(
                    buildDir, outDll, header, runtimeCpp, vmCpp, exportsDef, shards, symBlobBytes, config);
        } finally {
            deleteRecursive(buildDir);
        }

        // 8. Package natives/<dllName> directly inside the JAR (and encrypt if --encrypt-dll)
        if (config.isEmbedDll()) {
            byte[] rawDll = Files.readAllBytes(outDll);
            resources.put(embeddedResPath, config.isEncryptEmbeddedDll()
                    ? ClassRewriter.encryptDllPayload(rawDll, dllEncKey)
                    : rawDll);
        }

        // Shuffle resource order slightly when writing JAR so real vs junk entries mix naturally
        writeJar(config.getOutputJar(), resources, finalClassBytes, rng);

        Result res = new Result();
        res.totalClasses = classes.size();
        res.protectedClasses = regClasses.size();
        res.fuckedClasses = fuckedEntries.size();
        res.junkEntries = junkAdded;
        res.cffNativeMethods = cffCount;
        res.vmMethods = vmCount;
        res.mixinBridgesCreated = generatedMixinBridges.size();
        res.compileTimeMs = System.currentTimeMillis() - t0;
        res.outputJar = config.getOutputJar();
        res.outputDll = outDll;
        return res;
    }

    private static List<ClassNode> topoSortClasses(List<ClassNode> nodes) {
        Map<String, ClassNode> map = new LinkedHashMap<>();
        for (ClassNode cn : nodes) map.put(cn.name, cn);
        List<ClassNode> result = new ArrayList<>(nodes.size());
        Set<String> visited = new HashSet<>();
        Set<String> visiting = new HashSet<>();

        for (ClassNode cn : nodes) {
            dfsTopo(cn, map, visited, visiting, result);
        }
        return result;
    }

    private static void dfsTopo(
            ClassNode cn,
            Map<String, ClassNode> map,
            Set<String> visited,
            Set<String> visiting,
            List<ClassNode> out) {
        if (cn == null || visited.contains(cn.name) || visiting.contains(cn.name)) return;
        visiting.add(cn.name);
        if (cn.superName != null && map.containsKey(cn.superName)) {
            dfsTopo(map.get(cn.superName), map, visited, visiting, out);
        }
        if (cn.interfaces != null) {
            for (String itf : cn.interfaces) {
                if (map.containsKey(itf)) dfsTopo(map.get(itf), map, visited, visiting, out);
            }
        }
        if (cn.nestHostClass != null && map.containsKey(cn.nestHostClass)) {
            dfsTopo(map.get(cn.nestHostClass), map, visited, visiting, out);
        }
        int dollar = cn.name.lastIndexOf('$');
        if (dollar > 0) {
            String outer = cn.name.substring(0, dollar);
            if (map.containsKey(outer)) dfsTopo(map.get(outer), map, visited, visiting, out);
        }
        visiting.remove(cn.name);
        visited.add(cn.name);
        out.add(cn);
    }

    private static boolean shouldIncludeClass(ClassNode cn, FabricMetadata meta, ObfuscationConfig config) {
        if ((cn.access & ACC_ANNOTATION) != 0) return false;
        if (cn.name.startsWith("dev/neuro/nativeobfuscator/")
                || cn.name.startsWith("by/radioegor146/nativeobfuscator/")) {
            return false;
        }
        return AnnotationFilter.shouldProcessClass(cn, config);
    }

    private static boolean isEligibleMethod(ClassNode cn, MethodNode mn, Set<MethodNode> nonNativeHelpers) {
        if (nonNativeHelpers.contains(mn)) return false;
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) return false;
        if (mn.instructions == null || mn.instructions.size() == 0) return false;
        return true;
    }

    private static boolean shouldUseVm(ClassNode cn, MethodNode mn, MixinOutliner.MixinContext mCtx, ObfuscationConfig config) {
        if (mCtx != null) return false;
        if (AnnotationFilter.shouldUseVm(cn, mn)) return true;
        String full = cn.name + "." + mn.name;
        for (String exc : config.getVmExcludePatterns()) {
            if (ObfuscationConfig.matchesGlob(cn.name, exc) || ObfuscationConfig.matchesGlob(full, exc)) return false;
        }
        for (String inc : config.getVmIncludePatterns()) {
            if (ObfuscationConfig.matchesGlob(cn.name, inc) || ObfuscationConfig.matchesGlob(full, inc)) return true;
        }
        if (config.getTier() == ObfuscationConfig.ProtectionTier.ULTRA) {
            int realInsns = 0;
            for (var insn : mn.instructions) if (insn.getOpcode() >= 0) realInsns++;
            return realInsns >= 6 && realInsns <= 1500;
        }
        return false;
    }

    private static byte[] concatSymBlob(SymbolPool pool) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (SymbolPool.SymEntry se : pool.getSymEntries()) {
            bos.writeBytes(se.encrypted);
        }
        return bos.toByteArray();
    }

    private static long fnvUpdate(long h, byte[] data) {
        for (byte b : data) {
            h ^= (b & 0xFFL);
            h *= 0x100000001B3L;
        }
        return h;
    }

    private static void writeJar(Path outPath, Map<String, byte[]> resources, Map<String, byte[]> classes, Random rng) throws IOException {
        if (outPath.getParent() != null) Files.createDirectories(outPath.getParent());
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(outPath))) {
            byte[] mf = resources.get("META-INF/MANIFEST.MF");
            if (mf != null) {
                jos.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
                jos.write(mf);
                jos.closeEntry();
            }
            List<Map.Entry<String, byte[]>> mixed = new ArrayList<>();
            for (Map.Entry<String, byte[]> e : resources.entrySet()) {
                if ("META-INF/MANIFEST.MF".equals(e.getKey())) continue;
                mixed.add(e);
            }
            mixed.addAll(classes.entrySet());
            Collections.shuffle(mixed, rng);
            for (Map.Entry<String, byte[]> e : mixed) {
                jos.putNextEntry(new ZipEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }

    private static void deleteRecursive(Path p) {
        try {
            if (Files.exists(p)) {
                try (var s = Files.walk(p)) {
                    s.sorted(Comparator.reverseOrder()).forEach(f -> {
                        try { Files.deleteIfExists(f); } catch (IOException ignored) {}
                    });
                }
            }
        } catch (IOException ignored) {}
    }
}
