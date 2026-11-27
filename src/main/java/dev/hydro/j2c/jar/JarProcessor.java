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
import java.util.zip.ZipInputStream;

/**
 * End-to-end J2C & Native VM pipeline for standard Java JARs (runnable/library) and Minecraft Fabric mods.
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

        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(config.getInputJar()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                if (isJarSignatureFile(name)) continue;
                byte[] data = zis.readAllBytes();
                if ("META-INF/MANIFEST.MF".equals(name)) {
                    resources.put(name, ensureManifestTrailingNewline(data));
                } else if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                    ClassNode cn = new ClassNode();
                    new ClassReader(data).accept(cn, ClassReader.EXPAND_FRAMES);
                    classes.put(cn.name, cn);
                } else {
                    resources.put(name, data);
                }
            }
        }

        FabricMetadata fabricMeta = FabricMetadata.parse(resources);
        JarMetadata jarMeta = JarMetadata.parse(resources);
        if (config.getIncludePatterns().isEmpty() && fabricMeta.isFabricMod() && !fabricMeta.getDetectedPackages().isEmpty()) {
            for (String p : fabricMeta.getDetectedPackages()) {
                config.getIncludePatterns().add(p + "/**");
            }
        }
        String jarKind = fabricMeta.isFabricMod()
                ? "Fabric Mod (" + fabricMeta.getModId() + ")"
                : (!jarMeta.getEntrypointClasses().isEmpty()
                    ? "Runnable/Agent JAR (Main-Class=" + jarMeta.getMainClass() + ")"
                    : "Standard Library JAR");
        System.out.println("[HydroJ2C] Target mode: " + jarKind);

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
            if ((cn.access & ACC_INTERFACE) != 0) {
                classEligibleMethods.put(cn, Set.of());
                continue;
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
            IndyLowerer.lowerClass(cn, nonNativeHelpers, eligibleSet, rng);
            if (config.isOutlineConstructors() && !MixinOutliner.isMixinClass(cn, fabricMeta)) {
                ConstructorOutliner.outlineConstructors(cn, config, outlinedCtorBodies, rng);
                eligibleSet.addAll(outlinedCtorBodies);
            }
            classEligibleMethods.put(cn, eligibleSet);
        }

        // Derive shared per-build dynamic server state bound into BOTH CFF dispatcher and Native VM
        long[] srvDynParams = config.isServerEnabled() ? new long[8] : null;
        if (srvDynParams != null) {
            for (int d = 0; d < 8; d++) srvDynParams[d] = rng.nextLong();
        }

        // 3. Compile methods into Flattened C++ or Encrypted Native VM
        Path outDll = config.getOutputDll();
        if (outDll == null) {
            String base = config.getOutputJar().getFileName().toString().replaceAll("\\.jar$", "");
            outDll = config.getOutputJar().toAbsolutePath().getParent().resolve(NativeCompiler.formatHostLibFileName(base));
            config.setOutputDll(outDll);
        }
        String dllName = outDll.getFileName().toString();
        String libBaseName = NativeCompiler.stripLibNameToBase(dllName);
        String embeddedResPath = "natives/" + NativeCompiler.hostOsTag() + "-" + NativeCompiler.hostArchTag() + "/" + dllName;
        long dllEncKey = rng.nextLong();

        List<String> methodCpus = new ArrayList<>();
        List<VmCompiler.CompiledVmMethod> vmMethods = new ArrayList<>();
        List<CppRuntimeEmitter.RegisteredClass> regClasses = new ArrayList<>();

        int classIdSeq = 1;
        int fnSeq = 0;
        int cffCount = 0;
        int vmCount = 0;

        Set<String> registeredClassNames = new HashSet<>();
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
                                vmMethods.size(), cn.name, mn, cFuncName, frames, mCtx, vmIsa, pool, rng);
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
                            cn.name, mn, cFuncName, frames, cfg, mCtx, pool, crypto, config, srvDynParams, rng);
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
                registeredClassNames.add(cn.name);
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
        // Encrypt residual strings and numeric literals in any non-native Java methods inside targetClasses
        for (ClassNode cn : targetClasses) {
            JavaPreHardener.hardenResidualBytecode(cn, rng);
        }

        // 4. Populate junk classes, nested junk directories, and decoy .fucked blobs
        int dominantClassVersion = Opcodes.V17;
        for (ClassNode cn : classes.values()) {
            if (cn.version > dominantClassVersion) dominantClassVersion = cn.version;
        }
        List<String> fuckedDirs = new ArrayList<>();
        int resBeforeJunk = resources.size();
        JunkGenerator.populateJunk(
                resources, classes.keySet(), fuckedDirs, config.getJunkCount(),
                fabricMeta.isFabricMod(), dominantClassVersion, rng);
        int junkAdded = resources.size() - resBeforeJunk;

        // 5. Compute startup-visible classes that must remain valid .class files before HLoader unpacks .fucked
        Set<String> startupStayClasses = computeStartupStayClasses(
                classes, fabricMeta, jarMeta, mixinTargets, targetClasses);

        byte[] loaderBytes = ClassRewriter.generateLoaderClass(
                loaderInternal, regMethodName, verifyMethodName, bootMethodName,
                libBaseName, embeddedResPath, dllEncKey, config, rng);

        Map<String, byte[]> finalClassBytes = new LinkedHashMap<>();
        List<ClassNode> fuckedCandidates = new ArrayList<>();

        for (ClassNode cn : classes.values()) {
            boolean mustStayClass = !config.isFuckedClasses()
                    || !targetClasses.contains(cn)
                    || startupStayClasses.contains(cn.name);
            if (mustStayClass) {
                if (!registeredClassNames.contains(cn.name)
                        && needsStartupBootHook(cn, fabricMeta, jarMeta, startupStayClasses)) {
                    ClassRewriter.injectLoaderBoot(cn, loaderInternal, bootMethodName);
                }
                finalClassBytes.put(cn.name + ".class", ClassRewriter.writeClass(cn, classes));
            } else {
                fuckedCandidates.add(cn);
            }
        }
        finalClassBytes.put(loaderInternal + ".class", loaderBytes);

        // Topologically sort .fucked classes (superclasses, interfaces, outer NestHost before subclasses/inners)
        List<ClassNode> sortedFucked = topoSortClasses(fuckedCandidates);
        List<CppRuntimeEmitter.FuckedEntry> fuckedEntries = new ArrayList<>();
        long vaultSaltBase = crypto.getHashBasis() ^ crypto.getTagSalt();
        long serverVmShare = config.isServerEnabled() ? rng.nextLong() : 0L;
        long serverVaultShare = config.isServerEnabled() ? rng.nextLong() : 0L;
        long effectiveFuckedVaultSalt = vaultSaltBase ^ serverVaultShare;

        for (ClassNode cn : sortedFucked) {
            byte[] rawBytes = ClassRewriter.writeClass(cn, classes);
            long fileSeed = rng.nextLong();
            long mac = crypto.hash64(rawBytes);
            byte[] encBytes = ClassRewriter.encryptFuckedClass(rawBytes, fileSeed, effectiveFuckedVaultSalt, 640, rng);

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

        // Compute JAR integrity fingerprint over HLoader + fabric.mod.json / META-INF/MANIFEST.MF (if present)
        List<String> verifyResources = new ArrayList<>();
        long jarHash = crypto.getHashBasis();
        if (resources.containsKey("fabric.mod.json")) {
            verifyResources.add("fabric.mod.json");
            jarHash = crypto.hash64Update(jarHash, resources.get("fabric.mod.json"));
        } else if (resources.containsKey("META-INF/MANIFEST.MF")) {
            verifyResources.add("META-INF/MANIFEST.MF");
            jarHash = crypto.hash64Update(jarHash, resources.get("META-INF/MANIFEST.MF"));
        }
        verifyResources.add(loaderInternal + ".class");
        jarHash = crypto.hash64Update(jarHash, loaderBytes);

        // Derive productId & buildId for optional Spring server binding
        String productId = (config.getProductId() != null && !config.getProductId().isBlank())
                ? config.getProductId()
                : (fabricMeta.isFabricMod() ? fabricMeta.getModId() : libBaseName);
        String buildId = (config.getBuildId() != null && !config.getBuildId().isBlank())
                ? config.getBuildId()
                : "bld_" + Long.toUnsignedString(rng.nextLong(), 36);

        // 6. Partition C++ methods & VM JNI stubs into parallel compilation shards
        List<String> shards = new ArrayList<>();
        int perShard = Math.max(1, config.getMethodsPerShard());
        for (int i = 0; i < methodCpus.size(); i += perShard) {
            StringBuilder ssb = new StringBuilder();
            ssb.append("#include \"hydro_runtime.hpp\"\n\n");
            for (int k = i; k < Math.min(methodCpus.size(), i + perShard); k++) {
                ssb.append(methodCpus.get(k));
            }
            shards.add(ssb.toString());
        }

        Map<String, String> coreNativeFiles = CppRuntimeEmitter.loadCoreNativeFiles();
        CppRuntimeEmitter.GeneratedRuntime genRt = CppRuntimeEmitter.generateBuildRuntime(
                pool, crypto, regClasses, fuckedEntries, vmMethods, vmIsa,
                loaderInternal, regMethodName, verifyMethodName,
                jarHash, vaultSaltBase, serverVmShare, srvDynParams, productId, buildId, verifyResources, config);
        shards.addAll(genRt.vmStubShards());
        String exportsDef = CppRuntimeEmitter.emitExportsDef(config.isServerEnabled());

        byte[] symBlobBytes = concatSymBlob(pool);

        // Emit Spring server build manifest (and optionally auto-register onto --server-url)
        if (config.isServerEnabled()) {
            StringBuilder dynHex = new StringBuilder();
            for (int d = 0; d < 8; d++) {
                dynHex.append(dev.hydro.j2c.crypto.HydroCrypto.hex64Padded(srvDynParams[d]));
            }
            String manifestJson = """
                    {
                      "productId": "%s",
                      "buildId": "%s",
                      "jarDigest": "%s",
                      "symDigest": "%s",
                      "vmShareHex": "%s",
                      "vaultShareHex": "%s",
                      "dynParamsHex": "%s",
                      "note": "HydroJ2C build manifest"
                    }
                    """.formatted(
                    escJson(productId),
                    escJson(buildId),
                    dev.hydro.j2c.crypto.HydroCrypto.hex64Padded(jarHash),
                    dev.hydro.j2c.crypto.HydroCrypto.hex64Padded(crypto.hash64(symBlobBytes)),
                    dev.hydro.j2c.crypto.HydroCrypto.hex64Padded(serverVmShare),
                    dev.hydro.j2c.crypto.HydroCrypto.hex64Padded(serverVaultShare),
                    dynHex.toString()
            );
            Path mfPath = config.getManifestOut() != null
                    ? config.getManifestOut()
                    : config.getOutputJar().toAbsolutePath().getParent().resolve(
                        config.getOutputJar().getFileName().toString().replaceAll("\\.jar$", "") + "-server.json");
            if (mfPath.getParent() != null) Files.createDirectories(mfPath.getParent());
            Files.writeString(mfPath, manifestJson, java.nio.charset.StandardCharsets.UTF_8);
            if (config.getServerAdminToken() != null && !config.getServerAdminToken().isBlank()) {
                registerBuildOnServer(config.getServerUrl(), config.getServerAdminToken(), manifestJson);
            }
        }

        // 7. Compile native library (direct or via CMake, plus optional --cmake-out export)
        Path buildDir = Files.createTempDirectory("hydro_cpp_");
        try {
            NativeCompiler.compileNative(
                    buildDir, outDll, libBaseName, coreNativeFiles,
                    genRt.buildCfgHpp(), genRt.tablesCpp(),
                    exportsDef, shards, symBlobBytes, crypto, config);
        } finally {
            deleteRecursive(buildDir);
        }

        // 8. Package natives/<os>-<arch>/<lib> (plus any prebuilt multi-OS libs from --natives-dir) inside the JAR
        if (config.isEmbedDll()) {
            byte[] rawDll = Files.readAllBytes(outDll);
            resources.put(embeddedResPath, config.isEncryptEmbeddedDll()
                    ? ClassRewriter.encryptDllPayload(rawDll, dllEncKey)
                    : rawDll);
            if (config.getPrebuiltNativesDir() != null) {
                Map<String, byte[]> extraNatives = NativeCompiler.collectPrebuiltNatives(config.getPrebuiltNativesDir(), libBaseName);
                for (Map.Entry<String, byte[]> ne : extraNatives.entrySet()) {
                    if (ne.getKey().equals(embeddedResPath)) continue;
                    byte[] payload = config.isEncryptEmbeddedDll()
                            ? ClassRewriter.encryptDllPayload(ne.getValue(), dllEncKey)
                            : ne.getValue();
                    resources.put(ne.getKey(), payload);
                }
            }
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
        if ((cn.access & (ACC_ANNOTATION | ACC_MODULE)) != 0) return false;
        if ("module-info".equals(cn.name) || "package-info".equals(cn.name) || cn.name.endsWith("/package-info")) {
            return false;
        }
        if (cn.name.startsWith("dev/neuro/nativeobfuscator/")
                || cn.name.startsWith("by/radioegor146/nativeobfuscator/")) {
            return false;
        }
        return AnnotationFilter.shouldProcessClass(cn, config);
    }

    private static boolean isEligibleMethod(ClassNode cn, MethodNode mn, Set<MethodNode> nonNativeHelpers) {
        if ((cn.access & ACC_INTERFACE) != 0) return false;
        if (nonNativeHelpers.contains(mn)) return false;
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ((mn.access & (ACC_ABSTRACT | ACC_NATIVE)) != 0) return false;
        if (mn.instructions == null || mn.instructions.size() == 0) return false;
        return true;
    }

    private static Set<String> computeStartupStayClasses(
            Map<String, ClassNode> classes,
            FabricMetadata fabricMeta,
            JarMetadata jarMeta,
            Set<String> mixinTargets,
            Set<ClassNode> targetClasses) {

        Set<String> seeds = new LinkedHashSet<>();
        seeds.addAll(fabricMeta.getEntrypointClasses());
        for (ClassNode cn : classes.values()) {
            if (MixinOutliner.isMixinClass(cn, fabricMeta)) seeds.add(cn.name);
        }
        seeds.addAll(mixinTargets);
        seeds.addAll(jarMeta.getEntrypointClasses());
        seeds.addAll(jarMeta.getSpiClasses());

        // Plain library JAR (no Fabric mod metadata and no Main-Class / Agent entrypoint):
        // external callers can touch any public top-level class before HLoader initializes.
        if (!fabricMeta.isFabricMod() && jarMeta.getEntrypointClasses().isEmpty()) {
            for (ClassNode cn : classes.values()) {
                if ((cn.access & ACC_PUBLIC) != 0 && !cn.name.contains("$")) {
                    seeds.add(cn.name);
                }
            }
        }

        // Propagate transitive superclasses/interfaces/nest-hosts/enclosing-classes of stay classes,
        // because JVM resolves supers/interfaces BEFORE executing <clinit> (where HLoader unpacks .fucked).
        Set<String> closure = new LinkedHashSet<>();
        ArrayDeque<String> queue = new ArrayDeque<>(seeds);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (cur == null || !closure.add(cur)) continue;
            ClassNode cn = classes.get(cur);
            if (cn == null) continue;
            if (cn.superName != null && classes.containsKey(cn.superName)) queue.add(cn.superName);
            if (cn.interfaces != null) {
                for (String itf : cn.interfaces) {
                    if (classes.containsKey(itf)) queue.add(itf);
                }
            }
            if (cn.nestHostClass != null && classes.containsKey(cn.nestHostClass)) queue.add(cn.nestHostClass);
            int dollar = cn.name.lastIndexOf('$');
            if (dollar > 0) {
                String outer = cn.name.substring(0, dollar);
                if (classes.containsKey(outer)) queue.add(outer);
            }
        }
        return closure;
    }

    private static boolean needsStartupBootHook(
            ClassNode cn,
            FabricMetadata fabricMeta,
            JarMetadata jarMeta,
            Set<String> startupStayClasses) {
        if ((cn.access & (ACC_INTERFACE | ACC_ANNOTATION | ACC_MODULE)) != 0) return false;
        if ("module-info".equals(cn.name) || "package-info".equals(cn.name) || cn.name.endsWith("/package-info")) {
            return false;
        }
        if (fabricMeta.getEntrypointClasses().contains(cn.name) || jarMeta.getEntrypointClasses().contains(cn.name)) {
            return true;
        }
        // In Library JAR mode, any public API entry stub needs to trigger HLoader if it had no native methods itself
        return !fabricMeta.isFabricMod()
                && jarMeta.getEntrypointClasses().isEmpty()
                && startupStayClasses.contains(cn.name)
                && (cn.access & ACC_PUBLIC) != 0
                && !cn.name.contains("$");
    }

    private static boolean isJarSignatureFile(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String up = name.toUpperCase(Locale.ROOT);
        return up.endsWith(".SF") || up.endsWith(".DSA") || up.endsWith(".RSA") || up.endsWith(".EC");
    }

    private static byte[] ensureManifestTrailingNewline(byte[] raw) {
        if (raw.length == 0 || raw[raw.length - 1] == '\n') return raw;
        byte[] copy = Arrays.copyOf(raw, raw.length + 1);
        copy[raw.length] = '\n';
        return copy;
    }

    private static boolean shouldUseVm(ClassNode cn, MethodNode mn, MixinOutliner.MixinContext mCtx, ObfuscationConfig config) {
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
            return realInsns >= 1 && realInsns <= 2500;
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

    private static void writeJar(Path outPath, Map<String, byte[]> resources, Map<String, byte[]> classes, Random rng) throws IOException {
        if (outPath.getParent() != null) Files.createDirectories(outPath.getParent());
        Set<String> written = new HashSet<>();
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(outPath))) {
            byte[] mf = resources.get("META-INF/MANIFEST.MF");
            if (mf != null) {
                written.add("META-INF/MANIFEST.MF");
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
                if (!written.add(e.getKey())) continue;
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

    private static String escJson(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void registerBuildOnServer(String serverUrl, String adminToken, String jsonBody) throws Exception {
        String base = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        var client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();
        var req = java.net.http.HttpRequest.newBuilder(java.net.URI.create(base + "/api/v1/admin/builds"))
                .timeout(java.time.Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("X-Admin-Token", adminToken)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        var resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("Failed to register build on server (" + resp.statusCode() + "): " + resp.body());
        }
        System.out.println("[HydroJ2C] Build manifest registered on server: " + base);
    }
}
