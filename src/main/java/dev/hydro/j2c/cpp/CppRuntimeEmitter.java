package dev.hydro.j2c.cpp;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.crypto.CryptoEngine;
import dev.hydro.j2c.crypto.HydroCrypto;
import dev.hydro.j2c.crypto.SymbolPool;
import dev.hydro.j2c.vm.VmCompiler;
import dev.hydro.j2c.vm.VmIsa;
import org.objectweb.asm.Type;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Loads the real C++20 runtime/security/crypto/net/VM sources from src/main/resources/native/
 * and emits per-build randomized configuration headers, encrypted data tables, and sharded JNI stubs.
 */
public final class CppRuntimeEmitter {

    private static final List<String> CORE_NATIVE_FILES = List.of(
            "hydro_runtime.hpp",
            "hydro_crypto.hpp",
            "hydro_memory.cpp",
            "hydro_crypto.cpp",
            "hydro_security.cpp",
            "hydro_net.cpp",
            "hydro_jni_bridge.cpp",
            "hydro_vm_core.cpp"
    );

    public record RegisteredMethod(String name, String desc, String cFuncName) {}

    public record RegisteredClass(int classId, String classInternalName, List<RegisteredMethod> methods) {}

    public record FuckedEntry(String classInternalName, String resourcePath, int rawLen, long fileSeed, long expectedMac) {}

    public record GeneratedRuntime(String buildCfgHpp, String tablesCpp, List<String> vmStubShards) {}

    public static Map<String, String> loadCoreNativeFiles() throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        for (String name : CORE_NATIVE_FILES) {
            out.put(name, loadNativeResource(name));
        }
        return out;
    }

    private static String loadNativeResource(String name) throws IOException {
        try (InputStream in = CppRuntimeEmitter.class.getResourceAsStream("/native/" + name)) {
            if (in != null) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        Path devPath = Path.of("src/main/resources/native", name);
        if (Files.isRegularFile(devPath)) {
            return Files.readString(devPath, StandardCharsets.UTF_8);
        }
        throw new IllegalStateException("Missing bundled C++ runtime resource: /native/" + name);
    }

    public static String emitExportsDef() {
        return "EXPORTS\nJNI_OnLoad\n";
    }

    private static long computeOneWayVerifyTag(long h, long tagSalt, long hashPrime, long vaultSaltBase) {
        long a = CryptoEngine.splitMix64(h ^ tagSalt);
        long b = CryptoEngine.splitMix64(h * hashPrime + vaultSaltBase);
        long c = (h >>> 17) * (h | 1L);
        return a ^ b ^ c;
    }

    public static GeneratedRuntime generateBuildRuntime(
            SymbolPool pool,
            CryptoEngine crypto,
            List<RegisteredClass> registeredClasses,
            List<FuckedEntry> fuckedEntries,
            List<VmCompiler.CompiledVmMethod> vmMethods,
            VmIsa isa,
            String loaderClassInternal,
            String registerMethodName,
            String verifyMethodName,
            long expectedJarHash,
            long vaultSaltBase,
            long serverVmShare,
            String productId,
            String buildId,
            List<String> jarVerifyResources,
            ObfuscationConfig config) {

        // 1. Intern ALL runtime, anti-debug, server, and loader symbols FIRST so they go into g_sym_blob
        int symClass = pool.internSym("java/lang/Class");
        int symForName = pool.internSym("forName");
        int symForNameDesc = pool.internSym("(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
        int symNpe = pool.internSym("java/lang/NullPointerException");
        int symArith = pool.internSym("java/lang/ArithmeticException");
        int symNegArr = pool.internSym("java/lang/NegativeArraySizeException");
        int symCce = pool.internSym("java/lang/ClassCastException");
        int symAioobe = pool.internSym("java/lang/ArrayIndexOutOfBoundsException");
        int symSb = pool.internSym("java/lang/StringBuilder");
        int symSbInit = pool.internSym("<init>");
        int symSbInitDesc = pool.internSym("()V");
        int symSbAppStr = pool.internSym("append");
        int symSbAppStrDesc = pool.internSym("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
        int symSbAppObjDesc = pool.internSym("(Ljava/lang/Object;)Ljava/lang/StringBuilder;");
        int symSbAppIntDesc = pool.internSym("(I)Ljava/lang/StringBuilder;");
        int symSbAppLongDesc = pool.internSym("(J)Ljava/lang/StringBuilder;");
        int symSbAppFloatDesc = pool.internSym("(F)Ljava/lang/StringBuilder;");
        int symSbAppDoubleDesc = pool.internSym("(D)Ljava/lang/StringBuilder;");
        int symSbAppBoolDesc = pool.internSym("(Z)Ljava/lang/StringBuilder;");
        int symSbAppCharDesc = pool.internSym("(C)Ljava/lang/StringBuilder;");
        int symToStr = pool.internSym("toString");
        int symToStrDesc = pool.internSym("()Ljava/lang/String;");
        int symBoolArr = pool.internSym("[Z");
        int symObj = pool.internSym("java/lang/Object");

        int symLoader = pool.internSym(loaderClassInternal);
        int symRegName = pool.internSym(registerMethodName);
        int symRegDesc = pool.internSym("(Ljava/lang/Class;I)V");
        int symVerName = pool.internSym(verifyMethodName);
        int symVerDesc = pool.internSym("(Ljava/lang/ClassLoader;)V");

        int symIntCls = pool.internSym("java/lang/Integer");
        int symLongCls = pool.internSym("java/lang/Long");
        int symFloatCls = pool.internSym("java/lang/Float");
        int symDoubleCls = pool.internSym("java/lang/Double");
        int symBoolCls = pool.internSym("java/lang/Boolean");
        int symByteCls = pool.internSym("java/lang/Byte");
        int symCharCls = pool.internSym("java/lang/Character");
        int symShortCls = pool.internSym("java/lang/Short");
        int symVoidCls = pool.internSym("java/lang/Void");
        int symTypeField = pool.internSym("TYPE");
        int symClsFieldDesc = pool.internSym("Ljava/lang/Class;");

        int symDivZeroMsg = pool.internSym("/ by zero");
        int symCl = pool.internSym("java/lang/ClassLoader");
        int symGetRes = pool.internSym("getResourceAsStream");
        int symGetResDesc = pool.internSym("(Ljava/lang/String;)Ljava/io/InputStream;");
        int symGetResUrl = pool.internSym("getResource");
        int symGetResUrlDesc = pool.internSym("(Ljava/lang/String;)Ljava/net/URL;");
        int symGetResEnum = pool.internSym("getResources");
        int symGetResEnumDesc = pool.internSym("(Ljava/lang/String;)Ljava/util/Enumeration;");
        int symUrlCls = pool.internSym("java/net/URL");
        int symUrlOpen = pool.internSym("openStream");
        int symUrlOpenDesc = pool.internSym("()Ljava/io/InputStream;");
        int symEnumCls = pool.internSym("java/util/Enumeration");
        int symHasMore = pool.internSym("hasMoreElements");
        int symHasMoreDesc = pool.internSym("()Z");
        int symNextElem = pool.internSym("nextElement");
        int symNextElemDesc = pool.internSym("()Ljava/lang/Object;");
        int symStrCls = pool.internSym("java/lang/String");
        int symEndsWith = pool.internSym("endsWith");
        int symStartsWith = pool.internSym("startsWith");
        int symBoolStrDesc = pool.internSym("(Ljava/lang/String;)Z");
        int symSubstr = pool.internSym("substring");
        int symSubstrDesc = pool.internSym("(II)Ljava/lang/String;");
        int symStrLen = pool.internSym("length");
        int symIntVoidDesc = pool.internSym("()I");
        int symLoaderRes = pool.internSym("/" + loaderClassInternal + ".class");
        int symLoaderTail = pool.internSym(loaderClassInternal + ".class");
        int symIs = pool.internSym("java/io/InputStream");
        int symIsRead = pool.internSym("read");
        int symIsReadDesc = pool.internSym("([B)I");
        int symIsClose = pool.internSym("close");

        int symJdwp = pool.internSym("jdwp");
        int symXrunjdwp = pool.internSym("xrunjdwp");
        int symProcStatus = pool.internSym("/proc/self/status");
        int symTracerPid = pool.internSym("TracerPid:");
        int symProcCmd = pool.internSym("/proc/self/cmdline");
        int symLibJvm = pool.internSym("libjvm");

        // Native server auth / HWID / license symbols (encrypted in g_sym_blob)
        int symRegCrypto = pool.internSym("SOFTWARE\\Microsoft\\Cryptography");
        int symMachineGuid = pool.internSym("MachineGuid");
        int symSysCls = pool.internSym("java/lang/System");
        int symGetProp = pool.internSym("getProperty");
        int symGetPropDesc = pool.internSym("(Ljava/lang/String;)Ljava/lang/String;");
        int symPropKey = pool.internSym("hydro.key");
        int symEnvKey = pool.internSym("HYDRO_LICENSE_KEY");
        String licFilePath = (config.getServerKeyFile() != null && !config.getServerKeyFile().isBlank())
                ? config.getServerKeyFile() : "hydro.key";
        int symLicFile = pool.internSym(licFilePath);
        boolean hasBakedLic = config.getBakedLicenseKey() != null && !config.getBakedLicenseKey().isBlank();
        int symBakedLic = hasBakedLic ? pool.internSym(config.getBakedLicenseKey()) : 0;
        int symProductId = pool.internSym(productId != null ? productId : "");
        int symBuildId = pool.internSym(buildId != null ? buildId : "");
        int symSrvUrl = pool.internSym(config.isServerEnabled() ? config.getServerUrl() : "");
        int symSecEx = pool.internSym("java/lang/SecurityException");
        int symSecMsg = pool.internSym("License verification failed");

        boolean srv = config.isServerEnabled();
        int symBcryptDll = pool.internSym("bcrypt.dll");
        int symAdvapi32Dll = pool.internSym(srv ? "advapi32.dll" : "");
        int symWinhttpDll = pool.internSym(srv ? "winhttp.dll" : "");
        int symDriveC = pool.internSym(srv ? "C:\\" : "");
        int symUa = pool.internSym(srv ? "HydroAgent/1.0" : "");
        int symCtype = pool.internSym(srv ? "Content-Type: application/json\r\n" : "");
        int symEpHs = pool.internSym(srv ? "/api/v1/session/handshake" : "");
        int symEpHb = pool.internSym(srv ? "/api/v1/session/heartbeat" : "");
        int symHwidTag = pool.internSym(srv ? "HY-HWID-V1" : "");
        int symHsPfx = pool.internSym(srv ? "HY-HS-AUTH|" : "");
        int symSessPfx = pool.internSym(srv ? "HY-SESS-V1|" : "");
        int symJSess = pool.internSym(srv ? "sessionId" : "");
        int symJSEph = pool.internSym(srv ? "srvEphPub" : "");
        int symJSNonce = pool.internSym(srv ? "serverNonce" : "");
        int symJNonce = pool.internSym(srv ? "nonce12" : "");
        int symJCt = pool.internSym(srv ? "ciphertext" : "");
        int symJMac = pool.internSym(srv ? "mac" : "");

        int[] verifyResSyms = new int[jarVerifyResources.size()];
        for (int i = 0; i < jarVerifyResources.size(); i++) {
            verifyResSyms[i] = pool.internSym(jarVerifyResources.get(i));
        }

        boolean verifyJar = (config.isAntiTamper() || config.isServerEnabled()) && !jarVerifyResources.isEmpty();
        long effectiveKey = verifyJar ? expectedJarHash : (crypto.getMasterSeed() ^ crypto.getTagSalt());
        long verifyTag = computeOneWayVerifyTag(effectiveKey, crypto.getTagSalt(), crypto.getHashPrime(), vaultSaltBase);
        long sealedVmKey = isa.keySeed ^ CryptoEngine.splitMix64(effectiveKey ^ crypto.getTagSalt()) ^ serverVmShare;

        // Intern and blind .fucked metadata under live JAR key `effectiveKey`
        List<long[]> fuckedMetaRows = new ArrayList<>();
        for (int fi = 0; fi < fuckedEntries.size(); fi++) {
            FuckedEntry fe = fuckedEntries.get(fi);
            long cs = pool.internSym(fe.classInternalName());
            long ps = pool.internSym(fe.resourcePath());
            long mCls = CryptoEngine.splitMix64(effectiveKey ^ ((long) fi * 0xD6E8FEB86659FD93L)) & 0xFFFFFFFFL;
            long mPath = CryptoEngine.splitMix64(effectiveKey ^ ((long) fi * 0x517CC1B727220A95L)) & 0xFFFFFFFFL;
            long mLen = CryptoEngine.splitMix64(effectiveKey + ((long) fi * 0x9E3779B97F4A7C15L)) & 0xFFFFFFFFL;
            long mSeed = CryptoEngine.splitMix64(effectiveKey + ((long) fi * 0xBF58476D1CE4E5B9L));
            long mMac = CryptoEngine.splitMix64(effectiveKey + ((long) fi * 0x94D049BB133111EBL));
            fuckedMetaRows.add(new long[]{
                    (cs ^ mCls) & 0xFFFFFFFFL,
                    (ps ^ mPath) & 0xFFFFFFFFL,
                    (((long) fe.rawLen() & 0xFFFFFFFFL) ^ mLen) & 0xFFFFFFFFL,
                    fe.fileSeed() ^ mSeed,
                    fe.expectedMac() ^ mMac
            });
        }

        // Intern all registered native method names & descriptors
        List<int[]> regMethodSyms = new ArrayList<>();
        List<String> regMethodFnPtrs = new ArrayList<>();
        List<int[]> regClassEntries = new ArrayList<>();
        for (RegisteredClass rc : registeredClasses) {
            int clsSym = pool.internSym(rc.classInternalName());
            int start = regMethodFnPtrs.size();
            for (RegisteredMethod rm : rc.methods()) {
                int ns = pool.internSym(rm.name());
                int ds = pool.internSym(rm.desc());
                regMethodSyms.add(new int[]{ns, ds});
                regMethodFnPtrs.add(rm.cFuncName());
            }
            regClassEntries.add(new int[]{rc.classId(), clsSym, start, rc.methods().size()});
        }

        long pubKeyMaskSeed = crypto.getTagSalt() ^ crypto.getMasterSeed();
        byte[] srvPubMasked = new byte[32];
        if (config.isServerEnabled()) {
            byte[] rawPub = HydroCrypto.fromHex(config.getServerPubKeyHex());
            if (rawPub.length != 32) {
                throw new IllegalArgumentException("--server-pubkey must be 64 hex chars (32 bytes X25519 public key)");
            }
            for (int i = 0; i < 32; i++) {
                long mask = CryptoEngine.splitMix64(pubKeyMaskSeed + ((long) i * 0x9E3779B97F4A7C15L));
                srvPubMasked[i] = (byte) ((rawPub[i] & 0xFF) ^ (int) ((mask >>> ((i & 7) * 8)) & 0xFF));
            }
        }

        // 2. Emit hydro_build_cfg.hpp (macros consumed by hydro_*.cpp)
        StringBuilder cfg = new StringBuilder(10240);
        cfg.append("#pragma once\n\n");
        cfg.append("#define HY_ENABLE_ANTI_DEBUG ").append(config.isAntiDebug() ? 1 : 0).append("\n");
        cfg.append("#define HY_ENABLE_ANTI_DUMP ").append(config.isAntiDump() ? 1 : 0).append("\n");
        cfg.append("#define HY_ENABLE_ANTI_TAMPER ").append(config.isAntiTamper() ? 1 : 0).append("\n");
        cfg.append("#define HY_VERIFY_JAR ").append(verifyJar ? 1 : 0).append("\n");
        cfg.append("#define HY_HAS_FUCKED ").append(!fuckedMetaRows.isEmpty() ? 1 : 0).append("\n");
        cfg.append("#define HY_INITIAL_JAR_VERIFIED ").append((config.isAntiTamper() || config.isServerEnabled()) ? 0 : 1).append("\n");
        cfg.append("#define HY_ENABLE_SERVER ").append(config.isServerEnabled() ? 1 : 0).append("\n");
        cfg.append("#define HY_HAS_BAKED_LIC ").append(hasBakedLic ? 1 : 0).append("\n");
        cfg.append("#define HY_SRV_HB_SEC ").append(config.getServerHeartbeatSec()).append("\n");
        cfg.append("#define HY_VERIFY_TAG ").append(CryptoEngine.hex64(verifyTag)).append("ULL\n\n");

        cfg.append("#define HY_HASH_KERNEL32 ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("kernel32.dll"))).append("u\n");
        cfg.append("#define HY_HASH_NTDLL ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("ntdll.dll"))).append("u\n");
        cfg.append("#define HY_HASH_JVM ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("jvm.dll"))).append("u\n");
        cfg.append("#define HY_HASH_ISDBG ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("IsDebuggerPresent"))).append("u\n");
        cfg.append("#define HY_HASH_NTQIP ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("NtQueryInformationProcess"))).append("u\n");
        cfg.append("#define HY_HASH_GETCTX ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("GetThreadContext"))).append("u\n");
        cfg.append("#define HY_HASH_CURTHR ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("GetCurrentThread"))).append("u\n");
        cfg.append("#define HY_HASH_CURPROC ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("GetCurrentProcess"))).append("u\n");
        cfg.append("#define HY_HASH_TERMPROC ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("TerminateProcess"))).append("u\n");
        cfg.append("#define HY_HASH_LOADLIB ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("LoadLibraryA"))).append("u\n");
        cfg.append("#define HY_HASH_VIRTUALQUERY ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("VirtualQuery"))).append("u\n");
        cfg.append("#define HY_HASH_NTSETINFOTHREAD ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("NtSetInformationThread"))).append("u\n");
        cfg.append("#define HY_HASH_BCRYPT ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("bcrypt.dll"))).append("u\n");
        cfg.append("#define HY_HASH_ADVAPI32 ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("advapi32.dll"))).append("u\n");
        cfg.append("#define HY_HASH_WINHTTP ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("winhttp.dll"))).append("u\n");
        cfg.append("#define HY_HASH_BCRYPT_GEN ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("BCryptGenRandom"))).append("u\n");
        cfg.append("#define HY_HASH_REG_OPEN ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("RegOpenKeyExA"))).append("u\n");
        cfg.append("#define HY_HASH_REG_QUERY ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("RegQueryValueExA"))).append("u\n");
        cfg.append("#define HY_HASH_REG_CLOSE ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("RegCloseKey"))).append("u\n");
        cfg.append("#define HY_HASH_WH_OPEN ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpOpen"))).append("u\n");
        cfg.append("#define HY_HASH_WH_CONN ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpConnect"))).append("u\n");
        cfg.append("#define HY_HASH_WH_REQ ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpOpenRequest"))).append("u\n");
        cfg.append("#define HY_HASH_WH_TIME ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpSetTimeouts"))).append("u\n");
        cfg.append("#define HY_HASH_WH_SEND ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpSendRequest"))).append("u\n");
        cfg.append("#define HY_HASH_WH_RECV ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpReceiveResponse"))).append("u\n");
        cfg.append("#define HY_HASH_WH_HDR ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpQueryHeaders"))).append("u\n");
        cfg.append("#define HY_HASH_WH_AVAIL ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpQueryDataAvailable"))).append("u\n");
        cfg.append("#define HY_HASH_WH_READ ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpReadData"))).append("u\n");
        cfg.append("#define HY_HASH_WH_CLOSE ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32("WinHttpCloseHandle"))).append("u\n");
        cfg.append("#define HY_HASH_FRIDA_AGENT ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("frida-agent.dll"))).append("u\n");
        cfg.append("#define HY_HASH_FRIDA_GADGET ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("frida-gadget.dll"))).append("u\n");
        cfg.append("#define HY_HASH_X64DBG ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("x64dbg.dll"))).append("u\n");
        cfg.append("#define HY_HASH_SCYLLA ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("scyllahide.dll"))).append("u\n");
        cfg.append("#define HY_HASH_VEHDBG ").append(CryptoEngine.hex32(CryptoEngine.fnv1a32LowerAscii("vehdebug-x86_64.dll"))).append("u\n\n");

        defSym(cfg, "HY_SYM_CLASS", symClass);
        defSym(cfg, "HY_SYM_FORNAME", symForName);
        defSym(cfg, "HY_SYM_FORNAME_DESC", symForNameDesc);
        defSym(cfg, "HY_SYM_NPE", symNpe);
        defSym(cfg, "HY_SYM_ARITH", symArith);
        defSym(cfg, "HY_SYM_NEGARR", symNegArr);
        defSym(cfg, "HY_SYM_CCE", symCce);
        defSym(cfg, "HY_SYM_AIOOBE", symAioobe);
        defSym(cfg, "HY_SYM_SB", symSb);
        defSym(cfg, "HY_SYM_SB_INIT", symSbInit);
        defSym(cfg, "HY_SYM_SB_INIT_DESC", symSbInitDesc);
        defSym(cfg, "HY_SYM_SB_APP_STR", symSbAppStr);
        defSym(cfg, "HY_SYM_SB_APP_STR_DESC", symSbAppStrDesc);
        defSym(cfg, "HY_SYM_SB_APP_OBJ_DESC", symSbAppObjDesc);
        defSym(cfg, "HY_SYM_SB_APP_INT_DESC", symSbAppIntDesc);
        defSym(cfg, "HY_SYM_SB_APP_LONG_DESC", symSbAppLongDesc);
        defSym(cfg, "HY_SYM_SB_APP_FLOAT_DESC", symSbAppFloatDesc);
        defSym(cfg, "HY_SYM_SB_APP_DOUBLE_DESC", symSbAppDoubleDesc);
        defSym(cfg, "HY_SYM_SB_APP_BOOL_DESC", symSbAppBoolDesc);
        defSym(cfg, "HY_SYM_SB_APP_CHAR_DESC", symSbAppCharDesc);
        defSym(cfg, "HY_SYM_TOSTR", symToStr);
        defSym(cfg, "HY_SYM_TOSTR_DESC", symToStrDesc);
        defSym(cfg, "HY_SYM_BOOL_ARR", symBoolArr);
        defSym(cfg, "HY_SYM_OBJ", symObj);

        defSym(cfg, "HY_SYM_LOADER", symLoader);
        defSym(cfg, "HY_SYM_REG_NAME", symRegName);
        defSym(cfg, "HY_SYM_REG_DESC", symRegDesc);
        defSym(cfg, "HY_SYM_VER_NAME", symVerName);
        defSym(cfg, "HY_SYM_VER_DESC", symVerDesc);

        defSym(cfg, "HY_SYM_INT_CLS", symIntCls);
        defSym(cfg, "HY_SYM_LONG_CLS", symLongCls);
        defSym(cfg, "HY_SYM_FLOAT_CLS", symFloatCls);
        defSym(cfg, "HY_SYM_DOUBLE_CLS", symDoubleCls);
        defSym(cfg, "HY_SYM_BOOL_CLS", symBoolCls);
        defSym(cfg, "HY_SYM_BYTE_CLS", symByteCls);
        defSym(cfg, "HY_SYM_CHAR_CLS", symCharCls);
        defSym(cfg, "HY_SYM_SHORT_CLS", symShortCls);
        defSym(cfg, "HY_SYM_VOID_CLS", symVoidCls);
        defSym(cfg, "HY_SYM_TYPE_FIELD", symTypeField);
        defSym(cfg, "HY_SYM_CLS_FIELD_DESC", symClsFieldDesc);

        defSym(cfg, "HY_SYM_DIV_ZERO_MSG", symDivZeroMsg);
        defSym(cfg, "HY_SYM_CL", symCl);
        defSym(cfg, "HY_SYM_GETRES", symGetRes);
        defSym(cfg, "HY_SYM_GETRES_DESC", symGetResDesc);
        defSym(cfg, "HY_SYM_GETRES_URL", symGetResUrl);
        defSym(cfg, "HY_SYM_GETRES_URL_DESC", symGetResUrlDesc);
        defSym(cfg, "HY_SYM_GETRES_ENUM", symGetResEnum);
        defSym(cfg, "HY_SYM_GETRES_ENUM_DESC", symGetResEnumDesc);
        defSym(cfg, "HY_SYM_URL_CLS", symUrlCls);
        defSym(cfg, "HY_SYM_URL_OPEN", symUrlOpen);
        defSym(cfg, "HY_SYM_URL_OPEN_DESC", symUrlOpenDesc);
        defSym(cfg, "HY_SYM_ENUM_CLS", symEnumCls);
        defSym(cfg, "HY_SYM_HAS_MORE", symHasMore);
        defSym(cfg, "HY_SYM_HAS_MORE_DESC", symHasMoreDesc);
        defSym(cfg, "HY_SYM_NEXT_ELEM", symNextElem);
        defSym(cfg, "HY_SYM_NEXT_ELEM_DESC", symNextElemDesc);
        defSym(cfg, "HY_SYM_STR_CLS", symStrCls);
        defSym(cfg, "HY_SYM_ENDS_WITH", symEndsWith);
        defSym(cfg, "HY_SYM_STARTS_WITH", symStartsWith);
        defSym(cfg, "HY_SYM_BOOL_STR_DESC", symBoolStrDesc);
        defSym(cfg, "HY_SYM_SUBSTR", symSubstr);
        defSym(cfg, "HY_SYM_SUBSTR_DESC", symSubstrDesc);
        defSym(cfg, "HY_SYM_STR_LEN", symStrLen);
        defSym(cfg, "HY_SYM_INT_VOID_DESC", symIntVoidDesc);
        defSym(cfg, "HY_SYM_LOADER_RES", symLoaderRes);
        defSym(cfg, "HY_SYM_LOADER_TAIL", symLoaderTail);
        defSym(cfg, "HY_SYM_IS", symIs);
        defSym(cfg, "HY_SYM_IS_READ", symIsRead);
        defSym(cfg, "HY_SYM_IS_READ_DESC", symIsReadDesc);
        defSym(cfg, "HY_SYM_IS_CLOSE", symIsClose);

        defSym(cfg, "HY_SYM_JDWP", symJdwp);
        defSym(cfg, "HY_SYM_XRUNJDWP", symXrunjdwp);
        defSym(cfg, "HY_SYM_PROC_STATUS", symProcStatus);
        defSym(cfg, "HY_SYM_TRACER_PID", symTracerPid);
        defSym(cfg, "HY_SYM_PROC_CMD", symProcCmd);
        defSym(cfg, "HY_SYM_LIBJVM", symLibJvm);

        defSym(cfg, "HY_SYM_REG_CRYPTO", symRegCrypto);
        defSym(cfg, "HY_SYM_MACHINE_GUID", symMachineGuid);
        defSym(cfg, "HY_SYM_SYS_CLS", symSysCls);
        defSym(cfg, "HY_SYM_GET_PROP", symGetProp);
        defSym(cfg, "HY_SYM_GET_PROP_DESC", symGetPropDesc);
        defSym(cfg, "HY_SYM_PROP_KEY", symPropKey);
        defSym(cfg, "HY_SYM_ENV_KEY", symEnvKey);
        defSym(cfg, "HY_SYM_LIC_FILE", symLicFile);
        defSym(cfg, "HY_SYM_BAKED_LIC", symBakedLic);
        defSym(cfg, "HY_SYM_PRODUCT_ID", symProductId);
        defSym(cfg, "HY_SYM_BUILD_ID", symBuildId);
        defSym(cfg, "HY_SYM_SRV_URL", symSrvUrl);
        defSym(cfg, "HY_SYM_SEC_EX", symSecEx);
        defSym(cfg, "HY_SYM_SEC_MSG", symSecMsg);
        defSym(cfg, "HY_SYM_BCRYPT_DLL", symBcryptDll);
        defSym(cfg, "HY_SYM_ADVAPI32_DLL", symAdvapi32Dll);
        defSym(cfg, "HY_SYM_WINHTTP_DLL", symWinhttpDll);
        defSym(cfg, "HY_SYM_DRIVE_C", symDriveC);
        defSym(cfg, "HY_SYM_UA", symUa);
        defSym(cfg, "HY_SYM_CTYPE", symCtype);
        defSym(cfg, "HY_SYM_EP_HS", symEpHs);
        defSym(cfg, "HY_SYM_EP_HB", symEpHb);
        defSym(cfg, "HY_SYM_HWID_TAG", symHwidTag);
        defSym(cfg, "HY_SYM_HS_PFX", symHsPfx);
        defSym(cfg, "HY_SYM_SESS_PFX", symSessPfx);
        defSym(cfg, "HY_SYM_J_SESS", symJSess);
        defSym(cfg, "HY_SYM_J_SEPH", symJSEph);
        defSym(cfg, "HY_SYM_J_SNONCE", symJSNonce);
        defSym(cfg, "HY_SYM_J_NONCE", symJNonce);
        defSym(cfg, "HY_SYM_J_CT", symJCt);
        defSym(cfg, "HY_SYM_J_MAC", symJMac);
        cfg.append("\n");

        int dispMul = ((int) CryptoEngine.splitMix64(crypto.getMasterSeed() ^ 0x517CC1B727220A95L)) | 1;
        int dispXor = (int) (CryptoEngine.splitMix64(crypto.getTagSalt() ^ 0x9E3779B97F4A7C15L) >>> 17);

        // MBA-masked key expressions anchored to runtime opaque seed `op`
        cfg.append("#define HY_MBA_MASTER_SEED(op) ").append(crypto.mbaConst64WithVar(crypto.getMasterSeed(), "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_HASH_BASIS(op) ").append(crypto.mbaConst64WithVar(crypto.getHashBasis(), "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_HASH_PRIME(op) ").append(crypto.mbaConst64WithVar(crypto.getHashPrime(), "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_TAG_SALT(op) ").append(crypto.mbaConst64WithVar(crypto.getTagSalt(), "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_VAULT_SALT(op) ").append(crypto.mbaConst64WithVar(vaultSaltBase, "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_PUBKEY_MASK(op) ").append(crypto.mbaConst64WithVar(pubKeyMaskSeed, "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_EFFECTIVE_KEY(op) ").append(crypto.mbaConst64WithVar(effectiveKey, "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_VM_MIX_CONST(op) ").append(crypto.mbaConst64WithVar(isa.streamMixConst, "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_VM_MIX_MUL(op) ").append(crypto.mbaConst64WithVar(isa.streamMixMul, "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_VM_DISP_MUL(op) ").append(crypto.mbaConst64WithVar(Integer.toUnsignedLong(dispMul), "(op)", true)).append("\n");
        cfg.append("#define HY_MBA_VM_DISP_XOR(op) ").append(crypto.mbaConst64WithVar(Integer.toUnsignedLong(dispXor), "(op)", true)).append("\n\n");

        // Shuffled + 32-bit sparse bijective VM opcodes (defeats dense jump-table recovery) + unused trap cases
        for (VmIsa.Op op : VmIsa.Op.values()) {
            int encOp = ((isa.encodeOp(op) & 0xFF) * dispMul) ^ dispXor;
            cfg.append("#define HY_OP_").append(op.name()).append(" 0x").append(Integer.toHexString(encOp)).append("u\n");
        }
        Set<Integer> usedOpcodes = new HashSet<>(isa.opcodeMap.values());
        cfg.append("\n#define HY_VM_TRAP_CASES");
        int trapsEmitted = 0;
        for (int opc = 0; opc < 256 && trapsEmitted < 12; opc++) {
            if (!usedOpcodes.contains(opc)) {
                int encTrap = (opc * dispMul) ^ dispXor;
                cfg.append(" \\\n    case 0x").append(Integer.toHexString(encTrap)).append("u: g_tampered = 1; g_ptr_cookie ^= _op; cleanup(); return 0;");
                trapsEmitted++;
            }
        }
        cfg.append("\n");

        // 3. Emit hydro_tables.cpp (pure per-build tables & encrypted payloads)
        List<Byte> allCode = new ArrayList<>();
        List<VmCompiler.VmTryCatch> allTries = new ArrayList<>();
        List<int[]> allCalls = new ArrayList<>();
        List<Integer> allCallArgKinds = new ArrayList<>();
        List<int[]> allFields = new ArrayList<>();
        List<int[]> allConcats = new ArrayList<>();
        List<Integer> allConcatConsts = new ArrayList<>();
        List<Integer> allConcatArgKinds = new ArrayList<>();
        List<long[]> methodMetas = new ArrayList<>();

        for (VmCompiler.CompiledVmMethod vm : vmMethods) {
            int cOff = allCode.size();
            long methodKey = CryptoEngine.splitMix64(
                    isa.keySeed ^ vm.methodSalt ^ ((long) vm.vmMethodId * isa.streamMixConst));
            for (int i = 0; i < vm.rawCode.length; i++) {
                long k = CryptoEngine.splitMix64(methodKey + ((long) i * isa.streamMixMul));
                byte enc = (byte) ((vm.rawCode[i] & 0xFF) ^ ((int) ((k >>> ((i & 7) * 8)) & 0xFF)));
                allCode.add(enc);
            }
            int tOff = allTries.size();
            allTries.addAll(vm.tryCatches);
            int callOff = allCalls.size();
            for (VmCompiler.VmCallSite cs : vm.callSites) {
                int ao = allCallArgKinds.size();
                for (int ak : cs.argKinds()) allCallArgKinds.add(ak);
                allCalls.add(new int[]{cs.memberId(), cs.retKind(), ao, cs.argKinds().length});
            }
            int fldOff = allFields.size();
            for (VmCompiler.VmFieldSite fs : vm.fieldSites) {
                allFields.add(new int[]{fs.memberId(), fs.fieldKind()});
            }
            int cncOff = allConcats.size();
            for (VmCompiler.VmConcatSite cc : vm.concatSites) {
                int co = allConcatConsts.size();
                for (int cid : cc.constWStrIds()) allConcatConsts.add(cid);
                int ao = allConcatArgKinds.size();
                for (int ak : cc.argKinds()) allConcatArgKinds.add(ak);
                allConcats.add(new int[]{cc.recipeSymId(), co, cc.constWStrIds().length, ao, cc.argKinds().length});
            }
            methodMetas.add(new long[]{
                    cOff, vm.rawCode.length, vm.methodSalt, vm.opMask, vm.pcMul,
                    vm.maxStack, vm.maxLocals, tOff, vm.tryCatches.size(), callOff, fldOff, cncOff
            });
        }

        StringBuilder tbl = new StringBuilder(65536);
        tbl.append("#include \"hydro_runtime.hpp\"\n\n");
        for (String fn : regMethodFnPtrs) {
            tbl.append("extern \"C\" void ").append(fn).append("();\n");
        }
        tbl.append("\nextern \"C\" {\n");
        tbl.append("HY_USED volatile HySealBox g_hydro_seal_box = { ").append(CryptoEngine.hex64(crypto.getSealMagic())).append("ULL, 0ULL };\n");
        tbl.append("}\n\n");
        tbl.append("namespace hy {\n\n");
        tbl.append("volatile uint64_t g_rt_entropy = ").append(CryptoEngine.hex64(crypto.getMasterSeed() ^ 0x517CC1B727220A95L)).append("ULL;\n");
        tbl.append("volatile uint64_t g_vm_key_masked = ").append(CryptoEngine.hex64(sealedVmKey)).append("ULL;\n\n");

        tbl.append("const uint8_t g_srv_pubkey_masked[32] = {");
        for (int i = 0; i < 32; i++) {
            tbl.append("0x").append(Integer.toHexString(srvPubMasked[i] & 0xFF)).append(",");
        }
        tbl.append("};\n\n");

        List<SymbolPool.SymEntry> syms = pool.getSymEntries();
        List<int[]> symOffsets = new ArrayList<>();
        int curOff = 0;
        tbl.append("const uint8_t g_sym_blob[] = {\n");
        for (SymbolPool.SymEntry se : syms) {
            symOffsets.add(new int[]{curOff, se.encrypted.length});
            tbl.append("    ");
            for (byte b : se.encrypted) tbl.append("0x").append(Integer.toHexString(b & 0xFF)).append(",");
            tbl.append("\n");
            curOff += se.encrypted.length;
        }
        if (syms.isEmpty()) tbl.append("    0\n");
        tbl.append("};\nconst uint32_t g_sym_blob_size = (uint32_t)sizeof(g_sym_blob);\n");
        tbl.append("const SymMeta g_sym_meta[] = {\n");
        for (int[] om : symOffsets) tbl.append("    {").append(om[0]).append("u, ").append(om[1]).append("u},\n");
        if (symOffsets.isEmpty()) tbl.append("    {0u, 0u}\n");
        tbl.append("};\n\n");

        List<SymbolPool.WStrEntry> wstrs = pool.getWStrEntries();
        List<int[]> wstrOffsets = new ArrayList<>();
        tbl.append("const uint16_t g_wstr_blob[] = {\n");
        for (SymbolPool.WStrEntry we : wstrs) {
            int wOff = wstrOffsets.isEmpty() ? 0 : (wstrOffsets.get(wstrOffsets.size() - 1)[0] + Math.max(1, wstrOffsets.get(wstrOffsets.size() - 1)[1]));
            wstrOffsets.add(new int[]{wOff, we.encrypted.length});
            tbl.append("    ");
            for (short c : we.encrypted) tbl.append("0x").append(Integer.toHexString(c & 0xFFFF)).append("u,");
            if (we.encrypted.length == 0) tbl.append("0u,");
            tbl.append("\n");
        }
        if (wstrs.isEmpty()) tbl.append("    0u\n");
        tbl.append("};\nconst WStrMeta g_wstr_meta[] = {\n");
        for (int[] om : wstrOffsets) tbl.append("    {").append(om[0]).append("u, ").append(om[1]).append("u},\n");
        if (wstrOffsets.isEmpty()) tbl.append("    {0u, 0u}\n");
        tbl.append("};\n\n");

        List<SymbolPool.ClassRef> clsRefs = pool.getClassRefs();
        tbl.append("const uint32_t g_cls_syms[] = {");
        for (SymbolPool.ClassRef cr : clsRefs) tbl.append(cr.symId()).append("u,");
        if (clsRefs.isEmpty()) tbl.append("0u");
        tbl.append("};\nuintptr_t g_cls_cache[").append(Math.max(1, clsRefs.size())).append("] = {};\n\n");

        List<SymbolPool.MemberRef> mRefs = pool.getMethodRefs();
        tbl.append("const MemberMeta g_method_meta[] = {\n");
        for (SymbolPool.MemberRef mr : mRefs) {
            tbl.append("    {").append(mr.classId()).append("u, ").append(mr.nameSymId()).append("u, ").append(mr.descSymId()).append("u},\n");
        }
        if (mRefs.isEmpty()) tbl.append("    {0u, 0u, 0u}\n");
        tbl.append("};\nuintptr_t g_method_cache[").append(Math.max(1, mRefs.size())).append("] = {};\n\n");

        List<SymbolPool.MemberRef> fRefs = pool.getFieldRefs();
        tbl.append("const MemberMeta g_field_meta[] = {\n");
        for (SymbolPool.MemberRef mr : fRefs) {
            tbl.append("    {").append(mr.classId()).append("u, ").append(mr.nameSymId()).append("u, ").append(mr.descSymId()).append("u},\n");
        }
        if (fRefs.isEmpty()) tbl.append("    {0u, 0u, 0u}\n");
        tbl.append("};\nuintptr_t g_field_cache[").append(Math.max(1, fRefs.size())).append("] = {};\n\n");

        tbl.append("const RegMethodMeta g_reg_methods[] = {\n");
        for (int i = 0; i < regMethodSyms.size(); i++) {
            int[] nsds = regMethodSyms.get(i);
            tbl.append("    {").append(nsds[0]).append("u, ").append(nsds[1]).append("u, (void*)&").append(regMethodFnPtrs.get(i)).append("},\n");
        }
        if (regMethodSyms.isEmpty()) tbl.append("    {0u, 0u, nullptr}\n");
        tbl.append("};\nconst RegClassMeta g_reg_classes[] = {\n");
        for (int[] rc : regClassEntries) {
            tbl.append("    {").append(rc[0]).append(", ").append(rc[1]).append("u, ").append(rc[2]).append("u, ").append(rc[3]).append("u},\n");
        }
        if (regClassEntries.isEmpty()) tbl.append("    {0, 0u, 0u, 0u}\n");
        tbl.append("};\nconst uint32_t g_reg_class_count = ").append(regClassEntries.size()).append("u;\n\n");

        tbl.append("const FuckedMeta g_fucked_entries[] = {\n");
        for (long[] row : fuckedMetaRows) {
            tbl.append("    {").append(row[0]).append("u, ").append(row[1]).append("u, ").append(row[2]).append("u, ")
               .append(CryptoEngine.hex64(row[3])).append("ULL, ").append(CryptoEngine.hex64(row[4])).append("ULL},\n");
        }
        if (fuckedMetaRows.isEmpty()) tbl.append("    {0u, 0u, 0u, 0ULL, 0ULL}\n");
        tbl.append("};\nconst uint32_t g_fucked_count = ").append(fuckedMetaRows.size()).append("u;\n");

        tbl.append("const uint32_t g_verify_res_syms[] = {");
        for (int r : verifyResSyms) tbl.append(r).append("u,");
        if (verifyResSyms.length == 0) tbl.append("0u");
        tbl.append("};\nconst uint32_t g_verify_res_count = ").append(verifyResSyms.length).append("u;\n\n");

        emitByteArr(tbl, "g_vm_code", allCode);
        emitIntArr(tbl, "g_vm_call_ak", allCallArgKinds);
        emitIntArr(tbl, "g_vm_cnc_consts", allConcatConsts);
        emitIntArr(tbl, "g_vm_cnc_ak", allConcatArgKinds);

        tbl.append("const VmTryEntry g_vm_tries[] = {\n");
        for (VmCompiler.VmTryCatch t : allTries) {
            tbl.append("    {").append(t.startPc()).append("u, ").append(t.endPc()).append("u, ").append(t.handlerPc()).append("u, ").append(t.catchClsId()).append("},\n");
        }
        if (allTries.isEmpty()) tbl.append("    {0u, 0u, 0u, -1}\n");
        tbl.append("};\nconst VmCallMeta g_vm_calls[] = {\n");
        for (int[] c : allCalls) tbl.append("    {").append(c[0]).append(", ").append(c[1]).append(", ").append(c[2]).append(", ").append(c[3]).append("},\n");
        if (allCalls.isEmpty()) tbl.append("    {0, 0, 0, 0}\n");
        tbl.append("};\nconst VmFieldMeta g_vm_fields[] = {\n");
        for (int[] f : allFields) tbl.append("    {").append(f[0]).append(", ").append(f[1]).append("},\n");
        if (allFields.isEmpty()) tbl.append("    {0, 0}\n");
        tbl.append("};\nconst VmConcatMeta g_vm_concats[] = {\n");
        for (int[] cc : allConcats) tbl.append("    {").append(cc[0]).append(", ").append(cc[1]).append(", ").append(cc[2]).append(", ").append(cc[3]).append(", ").append(cc[4]).append("},\n");
        if (allConcats.isEmpty()) tbl.append("    {0, 0, 0, 0, 0}\n");
        tbl.append("};\nconst VmMethodMeta g_vm_methods[] = {\n");
        for (long[] m : methodMetas) {
            tbl.append("    {").append(m[0]).append("u, ").append(m[1]).append("u, ")
               .append(CryptoEngine.hex64(m[2])).append("ULL, ")
               .append(m[3]).append("u, ").append(m[4]).append("u, ")
               .append(m[5]).append("u, ").append(m[6]).append("u, ")
               .append(m[7]).append("u, ").append(m[8]).append("u, ")
               .append(m[9]).append("u, ").append(m[10]).append("u, ").append(m[11]).append("u},\n");
        }
        if (methodMetas.isEmpty()) tbl.append("    {0u, 0u, 0ULL, 0u, 0u, 4u, 4u, 0u, 0u, 0u, 0u, 0u}\n");
        tbl.append("};\n\n} // namespace hy\n");

        // 4. Sharded VM JNI wrapper stubs
        List<String> stubShards = new ArrayList<>();
        int perShard = Math.max(1, config.getMethodsPerShard());
        for (int i = 0; i < vmMethods.size(); i += perShard) {
            StringBuilder ssb = new StringBuilder();
            ssb.append("#include \"hydro_runtime.hpp\"\n\n");
            for (int k = i; k < Math.min(vmMethods.size(), i + perShard); k++) {
                emitVmJniStub(ssb, vmMethods.get(k));
            }
            stubShards.add(ssb.toString());
        }

        return new GeneratedRuntime(cfg.toString(), tbl.toString(), stubShards);
    }

    private static void defSym(StringBuilder sb, String macro, int symId) {
        sb.append("#define ").append(macro).append(" ").append(symId).append("u\n");
    }

    private static void emitVmJniStub(StringBuilder sb, VmCompiler.CompiledVmMethod vm) {
        Type mt = Type.getMethodType(vm.methodDesc);
        Type[] args = mt.getArgumentTypes();
        Type ret = mt.getReturnType();
        int totalSlots = (vm.isStatic ? 0 : 1);
        for (Type a : args) totalSlots += a.getSize();
        totalSlots = Math.max(1, totalSlots);

        sb.append("extern \"C\" ").append(CppMethodEmitter.jniRetType(ret)).append(" JNICALL ")
          .append(vm.cNativeFnName).append("(JNIEnv* env, ").append(vm.isStatic ? "jclass" : "jobject").append(" _self_cls");
        for (int i = 0; i < args.length; i++) {
            sb.append(", ").append(CppMethodEmitter.jniParamType(args[i])).append(" _p").append(i);
        }
        sb.append(") {\n");
        sb.append("    uint64_t _iv[").append(totalSlots).append("] = {};\n");
        sb.append("    uint8_t _ir[").append(totalSlots).append("] = {};\n");
        int slot = 0;
        if (!vm.isStatic) {
            sb.append("    _iv[0] = (uint64_t)(uintptr_t)_self_cls; _ir[0] = 1;\n");
            slot = 1;
        }
        for (int i = 0; i < args.length; i++) {
            Type a = args[i];
            switch (a.getSort()) {
                case Type.BOOLEAN -> sb.append("    _iv[").append(slot).append("] = _p").append(i).append(" ? 1ULL : 0ULL;\n");
                case Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> sb.append("    _iv[").append(slot).append("] = (uint64_t)(uint32_t)(int32_t)_p").append(i).append(";\n");
                case Type.LONG -> sb.append("    _iv[").append(slot).append("] = (uint64_t)_p").append(i).append(";\n");
                case Type.FLOAT -> sb.append("    { float _f = _p").append(i).append("; memcpy(&_iv[").append(slot).append("], &_f, 4); }\n");
                case Type.DOUBLE -> sb.append("    { double _d = _p").append(i).append("; memcpy(&_iv[").append(slot).append("], &_d, 8); }\n");
                default -> sb.append("    _iv[").append(slot).append("] = (uint64_t)(uintptr_t)_p").append(i).append("; _ir[").append(slot).append("] = 1;\n");
            }
            slot += a.getSize();
        }
        if (ret.getSort() == Type.OBJECT || ret.getSort() == Type.ARRAY) {
            sb.append("    jobject _out = nullptr;\n");
            sb.append("    hy::vm_exec_core(env, ").append(vm.vmMethodId).append("u, _iv, _ir, ").append(totalSlots).append(", &_out);\n");
            sb.append("    return (").append(CppMethodEmitter.jniRetType(ret)).append(")_out;\n");
        } else if (ret.getSort() == Type.VOID) {
            sb.append("    hy::vm_exec_core(env, ").append(vm.vmMethodId).append("u, _iv, _ir, ").append(totalSlots).append(", nullptr);\n");
        } else {
            sb.append("    uint64_t _rv = hy::vm_exec_core(env, ").append(vm.vmMethodId).append("u, _iv, _ir, ").append(totalSlots).append(", nullptr);\n");
            switch (ret.getSort()) {
                case Type.BOOLEAN -> sb.append("    return (_rv & 1ULL) ? JNI_TRUE : JNI_FALSE;\n");
                case Type.BYTE -> sb.append("    return (jbyte)(int32_t)(uint32_t)_rv;\n");
                case Type.CHAR -> sb.append("    return (jchar)(uint16_t)(uint32_t)_rv;\n");
                case Type.SHORT -> sb.append("    return (jshort)(int32_t)(uint32_t)_rv;\n");
                case Type.INT -> sb.append("    return (jint)(uint32_t)_rv;\n");
                case Type.LONG -> sb.append("    return (jlong)_rv;\n");
                case Type.FLOAT -> sb.append("    return hy::bits_to_f32((uint32_t)_rv);\n");
                case Type.DOUBLE -> sb.append("    return hy::bits_to_f64(_rv);\n");
            }
        }
        sb.append("}\n\n");
    }

    private static void emitByteArr(StringBuilder sb, String name, List<Byte> list) {
        sb.append("const uint8_t ").append(name).append("[] = {\n    ");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0 && i % 20 == 0) sb.append("\n    ");
            sb.append("0x").append(Integer.toHexString(list.get(i) & 0xFF)).append(",");
        }
        if (list.isEmpty()) sb.append("0");
        sb.append("\n};\n");
    }

    private static void emitIntArr(StringBuilder sb, String name, List<Integer> list) {
        sb.append("const int32_t ").append(name).append("[] = {\n    ");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n    ");
            sb.append(list.get(i)).append(",");
        }
        if (list.isEmpty()) sb.append("0");
        sb.append("\n};\n");
    }
}
