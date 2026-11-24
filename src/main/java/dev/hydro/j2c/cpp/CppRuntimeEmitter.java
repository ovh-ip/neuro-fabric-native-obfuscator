package dev.hydro.j2c.cpp;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.crypto.CryptoEngine;
import dev.hydro.j2c.crypto.SymbolPool;
import dev.hydro.j2c.vm.VmCompiler;
import dev.hydro.j2c.vm.VmIsa;
import org.objectweb.asm.Type;

import java.util.*;

/**
 * Generates hydro_runtime.hpp, hydro_runtime.cpp, hydro_vm.cpp, and exports.def.
 * Uses zero C++ STL dependencies so the compiled DLL depends ONLY on Windows KERNEL32.dll
 * and exposes zero C++ RTTI / exception / std:: metadata to IDA or Ghidra.
 */
public final class CppRuntimeEmitter {

    public static final long SEAL_MAGIC = 0x485944524F534541L; // "HYDROSEA" patched post-link

    public record RegisteredMethod(String name, String desc, String cFuncName) {}

    public record RegisteredClass(int classId, String classInternalName, List<RegisteredMethod> methods) {}

    public record FuckedEntry(String classInternalName, String resourcePath, int rawLen, long fileSeed, long expectedMac) {}

    public static String emitHeader() {
        return """
#pragma once
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include <string.h>

namespace hy {

extern volatile uint64_t g_rt_entropy;
extern uintptr_t g_ptr_cookie;

inline uint64_t opaque_seed() {
    uint64_t v = g_rt_entropy;
    v ^= (v << 13);
    v ^= (v >> 7);
    return v | 1ULL;
}

inline float bits_to_f32(uint32_t u) {
    float f = 0.0f;
    __builtin_memcpy(&f, &u, sizeof(f));
    return f;
}

inline double bits_to_f64(uint64_t u) {
    double d = 0.0;
    __builtin_memcpy(&d, &u, sizeof(d));
    return d;
}

inline int32_t j_idiv(int32_t a, int32_t b) {
    if (a == INT32_MIN && b == -1) return INT32_MIN;
    return a / b;
}

inline int32_t j_irem(int32_t a, int32_t b) {
    if (a == INT32_MIN && b == -1) return 0;
    return a % b;
}

inline int64_t j_ldiv(int64_t a, int64_t b) {
    if (a == INT64_MIN && b == -1) return INT64_MIN;
    return a / b;
}

inline int64_t j_lrem(int64_t a, int64_t b) {
    if (a == INT64_MIN && b == -1) return 0;
    return a % b;
}

inline float j_frem(float a, float b) { return __builtin_fmodf(a, b); }
inline double j_drem(double a, double b) { return __builtin_fmod(a, b); }

inline int32_t j_f2i(float v) {
    if (v != v) return 0;
    if (v >= 2147483648.0f) return INT32_MAX;
    if (v <= -2147483648.0f) return INT32_MIN;
    return (int32_t)v;
}

inline int64_t j_f2l(float v) {
    if (v != v) return 0;
    if (v >= 9223372036854775808.0f) return INT64_MAX;
    if (v <= -9223372036854775808.0f) return INT64_MIN;
    return (int64_t)v;
}

inline int32_t j_d2i(double v) {
    if (v != v) return 0;
    if (v >= 2147483648.0) return INT32_MAX;
    if (v <= -2147483648.0) return INT32_MIN;
    return (int32_t)v;
}

inline int64_t j_d2l(double v) {
    if (v != v) return 0;
    if (v >= 9223372036854775808.0) return INT64_MAX;
    if (v <= -9223372036854775808.0) return INT64_MIN;
    return (int64_t)v;
}

inline int32_t j_fcmpl(float a, float b) {
    if (a != a || b != b) return -1;
    return (a > b) ? 1 : ((a < b) ? -1 : 0);
}

inline int32_t j_fcmpg(float a, float b) {
    if (a != a || b != b) return 1;
    return (a > b) ? 1 : ((a < b) ? -1 : 0);
}

inline int32_t j_dcmpl(double a, double b) {
    if (a != a || b != b) return -1;
    return (a > b) ? 1 : ((a < b) ? -1 : 0);
}

inline int32_t j_dcmpg(double a, double b) {
    if (a != a || b != b) return 1;
    return (a > b) ? 1 : ((a < b) ? -1 : 0);
}

void* heap_alloc(size_t sz);
void heap_free(void* p);

struct RefSlot {
    jobject obj;
    uint32_t rc;
    int32_t next_free;
    uint8_t owned;
};

/**
 * O(1) stack-allocated + overflow ref-counted JNI LocalRef table.
 * Prevents local reference table overflows in long loops while keeping DUP/ALOAD alias-safe.
 */
struct RefTable {
    static constexpr int32_t INLINE_CAP = 128;
    JNIEnv* env;
    RefSlot inline_slots[INLINE_CAP];
    RefSlot* overflow;
    int32_t overflow_cap;
    int32_t used;
    int32_t free_head;

    explicit RefTable(JNIEnv* e) : env(e), overflow(nullptr), overflow_cap(0), used(0), free_head(-1) {}

    ~RefTable() {
        for (int32_t i = 0; i < used; i++) {
            RefSlot& s = at(i);
            if (s.owned && s.obj != nullptr) {
                env->DeleteLocalRef(s.obj);
                s.obj = nullptr;
            }
        }
        if (overflow) heap_free(overflow);
    }

    RefTable(const RefTable&) = delete;
    RefTable& operator=(const RefTable&) = delete;

    inline RefSlot& at(int32_t idx) {
        return idx < INLINE_CAP ? inline_slots[idx] : overflow[idx - INLINE_CAP];
    }

    int32_t track(jobject o, bool owned) {
        if (o == nullptr) return -1;
        int32_t idx;
        if (free_head >= 0) {
            idx = free_head;
            free_head = at(idx).next_free;
        } else {
            if (used >= INLINE_CAP) {
                int32_t need = used - INLINE_CAP + 1;
                if (need > overflow_cap) grow(need * 2);
            }
            idx = used++;
        }
        RefSlot& s = at(idx);
        s.obj = o;
        s.rc = 1;
        s.owned = owned ? 1 : 0;
        s.next_free = -1;
        return idx;
    }

    inline int32_t retain(int32_t idx) {
        if (idx >= 0) at(idx).rc++;
        return idx;
    }

    inline void release(int32_t idx) {
        if (idx < 0) return;
        RefSlot& s = at(idx);
        if (s.rc > 0 && --s.rc == 0) {
            if (s.owned && s.obj != nullptr) {
                env->DeleteLocalRef(s.obj);
            }
            s.obj = nullptr;
            s.owned = 0;
            s.next_free = free_head;
            free_head = idx;
        }
    }

    inline jobject raw(int32_t idx) {
        return idx < 0 ? nullptr : at(idx).obj;
    }

    jobject detach_return(int32_t idx) {
        if (idx < 0) return nullptr;
        RefSlot& s = at(idx);
        jobject r = s.obj;
        if (r == nullptr) return nullptr;
        if (!s.owned || s.rc > 1) {
            return env->NewLocalRef(r);
        }
        s.owned = 0;
        return r;
    }

private:
    void grow(int32_t new_cap) {
        int32_t cap = new_cap < 64 ? 64 : new_cap;
        RefSlot* mem = (RefSlot*)heap_alloc((size_t)cap * sizeof(RefSlot));
        if (overflow && overflow_cap > 0) {
            __builtin_memcpy(mem, overflow, (size_t)overflow_cap * sizeof(RefSlot));
            heap_free(overflow);
        }
        overflow = mem;
        overflow_cap = cap;
    }
};

struct ConcatArg {
    int32_t kind;
    int32_t i;
    int64_t j;
    float f;
    double d;
    jobject obj;
};

jclass resolve_class(JNIEnv* env, int32_t cls_id);
jclass resolve_prim_class(JNIEnv* env, int32_t kind);
jmethodID resolve_imethod(JNIEnv* env, int32_t mid_id);
jmethodID resolve_smethod(JNIEnv* env, int32_t mid_id);
jfieldID resolve_ifield(JNIEnv* env, int32_t fid_id);
jfieldID resolve_sfield(JNIEnv* env, int32_t fid_id);
jmethodID resolve_dyn_method(JNIEnv* env, jobject recv, int32_t name_sym, int32_t desc_sym);
jfieldID resolve_dyn_field(JNIEnv* env, jobject obj, int32_t name_sym, int32_t desc_sym);

jstring new_wstr(JNIEnv* env, int32_t wstr_id);
jstring string_concat(JNIEnv* env, int32_t recipe_wid, const int32_t* const_wids, int32_t const_cnt, const ConcatArg* args, int32_t argc);
jobject new_multi_array(JNIEnv* env, const int32_t* cids, const int32_t* dims, int32_t ndims, int32_t elem_kind);
int32_t baload_dyn(JNIEnv* env, jarray arr, int32_t idx);
void bastore_dyn(JNIEnv* env, jarray arr, int32_t idx, int32_t val);

void throw_arith(JNIEnv* env);
void throw_npe(JNIEnv* env);
void throw_neg_arr(JNIEnv* env);
void throw_cce(JNIEnv* env);
void throw_aioobe(JNIEnv* env);

uint64_t vm_exec(JNIEnv* env, jobject self_or_cls, uint32_t vm_method_id, const uint64_t* args, int32_t argc, int32_t ret_kind);

} // namespace hy
""";
    }

    public static String emitExportsDef() {
        return "EXPORTS\nJNI_OnLoad\n";
    }

    public static String emitRuntimeCpp(
            SymbolPool pool,
            CryptoEngine crypto,
            List<RegisteredClass> registeredClasses,
            List<FuckedEntry> fuckedEntries,
            String loaderClassInternal,
            String registerMethodName,
            String verifyMethodName,
            long expectedJarHash,
            List<String> jarVerifyResources,
            ObfuscationConfig config) {

        return emitRuntimeCppOrdered(
                pool, crypto, registeredClasses, fuckedEntries,
                loaderClassInternal, registerMethodName, verifyMethodName,
                expectedJarHash, jarVerifyResources, config
        );
    }

    private static String emitRuntimeCppOrdered(
            SymbolPool pool,
            CryptoEngine crypto,
            List<RegisteredClass> registeredClasses,
            List<FuckedEntry> fuckedEntries,
            String loaderClassInternal,
            String registerMethodName,
            String verifyMethodName,
            long expectedJarHash,
            List<String> jarVerifyResources,
            ObfuscationConfig config) {

        // 1. Intern ALL runtime & registration symbols FIRST so they go into g_sym_blob!
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
        int symIs = pool.internSym("java/io/InputStream");
        int symIsRead = pool.internSym("read");
        int symIsReadDesc = pool.internSym("([B)I");
        int symIsClose = pool.internSym("close");

        int[] verifyResSyms = new int[jarVerifyResources.size()];
        for (int i = 0; i < jarVerifyResources.size(); i++) {
            verifyResSyms[i] = pool.internSym(jarVerifyResources.get(i));
        }

        // Intern all encrypted .fucked class paths & internal names (kept encrypted inside DLL vault)
        List<long[]> fuckedMetaRows = new ArrayList<>(); // [clsSym, pathSym, rawLen, fileSeed, expectedMac]
        for (FuckedEntry fe : fuckedEntries) {
            int cs = pool.internSym(fe.classInternalName());
            int ps = pool.internSym(fe.resourcePath());
            fuckedMetaRows.add(new long[]{cs, ps, fe.rawLen(), fe.fileSeed(), fe.expectedMac()});
        }

        // Intern all registered native method names & descriptors
        List<int[]> regMethodSyms = new ArrayList<>(); // [nameSym, descSym]
        List<String> regMethodFnPtrs = new ArrayList<>();
        List<int[]> regClassEntries = new ArrayList<>(); // [classId, clsSymId, startIdx, count]
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

        StringBuilder sb = new StringBuilder(32768);
        sb.append("#include \"hydro_runtime.hpp\"\n");
        sb.append("#include <windows.h>\n\n");

        for (String fn : regMethodFnPtrs) {
            sb.append("extern \"C\" void ").append(fn).append("();\n");
        }

        sb.append("\nnamespace hy {\n\n");
        sb.append("volatile uint64_t g_rt_entropy = ").append(CryptoEngine.hex64(crypto.getMasterSeed() ^ 0x517CC1B727220A95L)).append("ULL;\n");
        sb.append("uintptr_t g_ptr_cookie = 0;\n");
        sb.append("static jobject g_mod_loader = nullptr;\n");
        sb.append("static volatile int32_t g_tampered = 0;\n");
        sb.append("static HANDLE g_heap = nullptr;\n\n");

        sb.append("extern \"C\" {\n");
        sb.append("struct SealBox { volatile uint64_t magic; volatile uint64_t hash; };\n");
        sb.append("__attribute__((used)) volatile SealBox g_hydro_seal_box = { ").append(CryptoEngine.hex64(SEAL_MAGIC)).append("ULL, 0ULL };\n");
        sb.append("}\n\n");

        sb.append("void* heap_alloc(size_t sz) {\n");
        sb.append("    if (!g_heap) g_heap = GetProcessHeap();\n");
        sb.append("    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, sz);\n");
        sb.append("}\n");
        sb.append("void heap_free(void* p) {\n");
        sb.append("    if (p && g_heap) HeapFree(g_heap, 0, p);\n");
        sb.append("}\n\n");

        sb.append("static inline void secure_wipe(void* p, size_t n) {\n");
        sb.append("    volatile uint8_t* vp = (volatile uint8_t*)p;\n");
        sb.append("    while (n--) *vp++ = 0;\n");
        sb.append("}\n\n");

        // Emit g_sym_blob + g_sym_meta
        List<SymbolPool.SymEntry> syms = pool.getSymEntries();
        sb.append("struct SymMeta { uint32_t off; uint32_t len; };\n");
        sb.append("static const uint8_t g_sym_blob[] = {\n");
        List<int[]> symOffsets = new ArrayList<>();
        int curOff = 0;
        for (SymbolPool.SymEntry se : syms) {
            symOffsets.add(new int[]{curOff, se.encrypted.length});
            sb.append("    ");
            for (byte b : se.encrypted) {
                sb.append("0x").append(Integer.toHexString(b & 0xFF)).append(",");
            }
            sb.append("\n");
            curOff += se.encrypted.length;
        }
        if (syms.isEmpty()) sb.append("    0\n");
        sb.append("};\nstatic const SymMeta g_sym_meta[] = {\n");
        for (int[] om : symOffsets) sb.append("    {").append(om[0]).append("u, ").append(om[1]).append("u},\n");
        if (symOffsets.isEmpty()) sb.append("    {0u, 0u}\n");
        sb.append("};\n\n");

        // Emit g_wstr_blob + g_wstr_meta
        List<SymbolPool.WStrEntry> wstrs = pool.getWStrEntries();
        sb.append("struct WStrMeta { uint32_t off; uint32_t len; };\n");
        sb.append("static const uint16_t g_wstr_blob[] = {\n");
        List<int[]> wstrOffsets = new ArrayList<>();
        int wOff = 0;
        for (SymbolPool.WStrEntry we : wstrs) {
            wstrOffsets.add(new int[]{wOff, we.encrypted.length});
            sb.append("    ");
            for (short c : we.encrypted) {
                sb.append("0x").append(Integer.toHexString(c & 0xFFFF)).append("u,");
            }
            if (we.encrypted.length == 0) sb.append("0u,");
            sb.append("\n");
            wOff += Math.max(1, we.encrypted.length);
        }
        if (wstrs.isEmpty()) sb.append("    0u\n");
        sb.append("};\nstatic const WStrMeta g_wstr_meta[] = {\n");
        for (int[] om : wstrOffsets) sb.append("    {").append(om[0]).append("u, ").append(om[1]).append("u},\n");
        if (wstrOffsets.isEmpty()) sb.append("    {0u, 0u}\n");
        sb.append("};\n\n");

        sb.append("static inline uint64_t splitmix64(uint64_t z) {\n");
        sb.append("    z += 0x9E3779B97F4A7C15ULL;\n");
        sb.append("    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;\n");
        sb.append("    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;\n");
        sb.append("    return z ^ (z >> 31);\n");
        sb.append("}\n\n");

        sb.append("static void decrypt_sym(uint32_t id, char* out, uint32_t cap) {\n");
        sb.append("    const SymMeta& m = g_sym_meta[id];\n");
        sb.append("    uint32_t n = m.len < cap ? m.len : cap;\n");
        sb.append("    uint64_t st = splitmix64(").append(CryptoEngine.hex64(crypto.getMasterSeed())).append("ULL ^ ((uint64_t)id * 0xD6E8FEB86659FD93ULL) ^ 0xA5A55A5AF0F00F0FULL);\n");
        sb.append("    for (uint32_t i = 0; i < n; i++) {\n");
        sb.append("        st = splitmix64(st + (uint64_t)i * 0x9E3779B97F4A7C15ULL);\n");
        sb.append("        uint8_t k = (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);\n");
        sb.append("        uint32_t rot = (uint32_t)((st >> 56) & 7u);\n");
        sb.append("        uint8_t r = g_sym_blob[m.off + i] ^ (uint8_t)((i * 31u + id) & 0xFFu);\n");
        sb.append("        uint8_t x = (uint8_t)(((r >> rot) | (r << (8u - rot))) & 0xFFu);\n");
        sb.append("        out[i] = (char)(x ^ k);\n");
        sb.append("    }\n");
        sb.append("    if (cap > 0) out[n > 0 ? n - 1 : 0] = '\\0';\n");
        sb.append("}\n\n");

        sb.append("jstring new_wstr(JNIEnv* env, int32_t wstr_id) {\n");
        sb.append("    const WStrMeta& m = g_wstr_meta[(uint32_t)wstr_id];\n");
        sb.append("    if (m.len == 0) return env->NewString(nullptr, 0);\n");
        sb.append("    jchar stack_buf[256];\n");
        sb.append("    jchar* buf = m.len <= 256 ? stack_buf : (jchar*)heap_alloc((size_t)m.len * sizeof(jchar));\n");
        sb.append("    uint64_t st = splitmix64(").append(CryptoEngine.hex64(crypto.getMasterSeed())).append("ULL ^ ((uint64_t)(uint32_t)wstr_id * 0x94D049BB133111EBULL) ^ 0x55AA33CC11EE7799ULL);\n");
        sb.append("    for (uint32_t i = 0; i < m.len; i++) {\n");
        sb.append("        st = splitmix64(st ^ ((uint64_t)i * 0xBF58476D1CE4E5B9ULL));\n");
        sb.append("        uint16_t k = (uint16_t)(st & 0xFFFFu);\n");
        sb.append("        uint32_t rot = (uint32_t)((st >> 48) & 15u);\n");
        sb.append("        uint16_t r = g_wstr_blob[m.off + i] ^ (uint16_t)((i * 131u + (uint32_t)wstr_id * 17u) & 0xFFFFu);\n");
        sb.append("        uint16_t x = (uint16_t)(((r >> rot) | (r << (16u - rot))) & 0xFFFFu);\n");
        sb.append("        buf[i] = (jchar)(x ^ k);\n");
        sb.append("    }\n");
        sb.append("    jstring js = env->NewString(buf, (jsize)m.len);\n");
        sb.append("    secure_wipe(buf, (size_t)m.len * sizeof(jchar));\n");
        sb.append("    if (buf != stack_buf) heap_free(buf);\n");
        sb.append("    return js;\n");
        sb.append("}\n\n");

        // Symbol pool metadata arrays
        List<SymbolPool.ClassRef> clsRefs = pool.getClassRefs();
        sb.append("static const uint32_t g_cls_syms[] = {");
        for (SymbolPool.ClassRef cr : clsRefs) sb.append(cr.symId()).append("u,");
        if (clsRefs.isEmpty()) sb.append("0u");
        sb.append("};\nstatic uintptr_t g_cls_cache[").append(Math.max(1, clsRefs.size())).append("] = {};\n\n");

        List<SymbolPool.MemberRef> mRefs = pool.getMethodRefs();
        sb.append("struct MemberMeta { uint32_t cls_id; uint32_t name_sym; uint32_t desc_sym; };\n");
        sb.append("static const MemberMeta g_method_meta[] = {\n");
        for (SymbolPool.MemberRef mr : mRefs) {
            sb.append("    {").append(mr.classId()).append("u, ").append(mr.nameSymId()).append("u, ").append(mr.descSymId()).append("u},\n");
        }
        if (mRefs.isEmpty()) sb.append("    {0u, 0u, 0u}\n");
        sb.append("};\nstatic uintptr_t g_method_cache[").append(Math.max(1, mRefs.size())).append("] = {};\n\n");

        List<SymbolPool.MemberRef> fRefs = pool.getFieldRefs();
        sb.append("static const MemberMeta g_field_meta[] = {\n");
        for (SymbolPool.MemberRef mr : fRefs) {
            sb.append("    {").append(mr.classId()).append("u, ").append(mr.nameSymId()).append("u, ").append(mr.descSymId()).append("u},\n");
        }
        if (fRefs.isEmpty()) sb.append("    {0u, 0u, 0u}\n");
        sb.append("};\nstatic uintptr_t g_field_cache[").append(Math.max(1, fRefs.size())).append("] = {};\n\n");

        // Native registration metadata
        sb.append("struct RegMethodMeta { uint32_t name_sym; uint32_t desc_sym; void* fn; };\n");
        sb.append("struct RegClassMeta { int32_t class_id; uint32_t cls_sym; uint32_t start; uint32_t count; };\n");
        sb.append("static const RegMethodMeta g_reg_methods[] = {\n");
        for (int i = 0; i < regMethodSyms.size(); i++) {
            int[] nsds = regMethodSyms.get(i);
            sb.append("    {").append(nsds[0]).append("u, ").append(nsds[1]).append("u, (void*)&").append(regMethodFnPtrs.get(i)).append("},\n");
        }
        if (regMethodSyms.isEmpty()) sb.append("    {0u, 0u, nullptr}\n");
        sb.append("};\n");
        sb.append("static const RegClassMeta g_reg_classes[] = {\n");
        for (int[] rc : regClassEntries) {
            sb.append("    {").append(rc[0]).append(", ").append(rc[1]).append("u, ").append(rc[2]).append("u, ").append(rc[3]).append("u},\n");
        }
        if (regClassEntries.isEmpty()) sb.append("    {0, 0u, 0u, 0u}\n");
        sb.append("};\nstatic constexpr uint32_t g_reg_class_count = ").append(regClassEntries.size()).append("u;\n\n");

        // Pre-cached bootstrap handles
        sb.append("static jclass g_cls_class = nullptr;\n");
        sb.append("static jmethodID g_mid_forName = nullptr;\n");
        sb.append("static jclass g_cls_sb = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_init = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_str = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_obj = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_i = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_j = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_f = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_d = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_z = nullptr;\n");
        sb.append("static jmethodID g_mid_sb_app_c = nullptr;\n");
        sb.append("static jmethodID g_mid_toString = nullptr;\n");
        sb.append("static jclass g_cls_bool_arr = nullptr;\n");
        sb.append("static jclass g_cls_obj = nullptr;\n");
        sb.append("static jclass g_cls_npe = nullptr;\n");
        sb.append("static jclass g_cls_arith = nullptr;\n");
        sb.append("static jclass g_cls_negarr = nullptr;\n");
        sb.append("static jclass g_cls_cce = nullptr;\n");
        sb.append("static jclass g_cls_aioobe = nullptr;\n\n");

        // PEB dynamic API resolver + Anti-Debug / Anti-Dump / Anti-Hook / Self-Integrity
        emitSecurityEngine(sb, config);

        // Class, method, field resolution helpers
        sb.append("static jclass find_class_by_sym(JNIEnv* env, uint32_t sym_id) {\n");
        sb.append("    char buf[512];\n");
        sb.append("    decrypt_sym(sym_id, buf, sizeof(buf));\n");
        sb.append("    jclass c = env->FindClass(buf);\n");
        sb.append("    if (c == nullptr || env->ExceptionCheck()) {\n");
        sb.append("        if (env->ExceptionCheck()) env->ExceptionClear();\n");
        sb.append("        if (g_mod_loader && g_cls_class && g_mid_forName) {\n");
        sb.append("            for (char* p = buf; *p; p++) if (*p == '/') *p = '.';\n");
        sb.append("            jstring jn = env->NewStringUTF(buf);\n");
        sb.append("            c = (jclass)env->CallStaticObjectMethod(g_cls_class, g_mid_forName, jn, JNI_TRUE, g_mod_loader);\n");
        sb.append("            if (jn) env->DeleteLocalRef(jn);\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("    secure_wipe(buf, sizeof(buf));\n");
        sb.append("    return c;\n");
        sb.append("}\n\n");

        sb.append("jclass resolve_class(JNIEnv* env, int32_t cls_id) {\n");
        sb.append("    uintptr_t v = __atomic_load_n(&g_cls_cache[cls_id], __ATOMIC_ACQUIRE);\n");
        sb.append("    if (v != 0) [[likely]] return (jclass)(v ^ g_ptr_cookie);\n");
        sb.append("    jclass lc = find_class_by_sym(env, g_cls_syms[cls_id]);\n");
        sb.append("    if (!lc || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    jclass gc = (jclass)env->NewGlobalRef(lc);\n");
        sb.append("    env->DeleteLocalRef(lc);\n");
        sb.append("    uintptr_t masked = ((uintptr_t)gc) ^ g_ptr_cookie;\n");
        sb.append("    uintptr_t expected = 0;\n");
        sb.append("    if (!__atomic_compare_exchange_n(&g_cls_cache[cls_id], &expected, masked, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {\n");
        sb.append("        env->DeleteGlobalRef(gc);\n");
        sb.append("        return (jclass)(expected ^ g_ptr_cookie);\n");
        sb.append("    }\n");
        sb.append("    return gc;\n");
        sb.append("}\n\n");

        sb.append("jclass resolve_prim_class(JNIEnv* env, int32_t kind) {\n");
        sb.append("    uint32_t csym = ").append(symIntCls).append("u;\n");
        sb.append("    switch (kind) {\n");
        sb.append("        case 0: csym = ").append(symVoidCls).append("u; break;\n");
        sb.append("        case 1: csym = ").append(symBoolCls).append("u; break;\n");
        sb.append("        case 2: csym = ").append(symByteCls).append("u; break;\n");
        sb.append("        case 3: csym = ").append(symCharCls).append("u; break;\n");
        sb.append("        case 4: csym = ").append(symShortCls).append("u; break;\n");
        sb.append("        case 5: csym = ").append(symIntCls).append("u; break;\n");
        sb.append("        case 6: csym = ").append(symLongCls).append("u; break;\n");
        sb.append("        case 7: csym = ").append(symFloatCls).append("u; break;\n");
        sb.append("        default: csym = ").append(symDoubleCls).append("u; break;\n");
        sb.append("    }\n");
        sb.append("    jclass wc = find_class_by_sym(env, csym);\n");
        sb.append("    if (!wc) return nullptr;\n");
        sb.append("    char fn[16], fd[32];\n");
        sb.append("    decrypt_sym(").append(symTypeField).append("u, fn, sizeof(fn));\n");
        sb.append("    decrypt_sym(").append(symClsFieldDesc).append("u, fd, sizeof(fd));\n");
        sb.append("    jfieldID fid = env->GetStaticFieldID(wc, fn, fd);\n");
        sb.append("    jclass res = (jclass)env->GetStaticObjectField(wc, fid);\n");
        sb.append("    env->DeleteLocalRef(wc);\n");
        sb.append("    return res;\n");
        sb.append("}\n\n");

        sb.append("static jmethodID resolve_method_impl(JNIEnv* env, int32_t mid_id, bool is_static) {\n");
        sb.append("    uintptr_t v = __atomic_load_n(&g_method_cache[mid_id], __ATOMIC_ACQUIRE);\n");
        sb.append("    if (v != 0) [[likely]] return (jmethodID)(v ^ g_ptr_cookie);\n");
        sb.append("    const MemberMeta& mm = g_method_meta[mid_id];\n");
        sb.append("    jclass cls = resolve_class(env, (int32_t)mm.cls_id);\n");
        sb.append("    if (!cls || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    char nb[256], db[512];\n");
        sb.append("    decrypt_sym(mm.name_sym, nb, sizeof(nb));\n");
        sb.append("    decrypt_sym(mm.desc_sym, db, sizeof(db));\n");
        sb.append("    jmethodID mid = is_static ? env->GetStaticMethodID(cls, nb, db) : env->GetMethodID(cls, nb, db);\n");
        sb.append("    secure_wipe(nb, sizeof(nb)); secure_wipe(db, sizeof(db));\n");
        sb.append("    if (mid && !env->ExceptionCheck()) {\n");
        sb.append("        uintptr_t masked = ((uintptr_t)mid) ^ g_ptr_cookie;\n");
        sb.append("        __atomic_store_n(&g_method_cache[mid_id], masked, __ATOMIC_RELEASE);\n");
        sb.append("    }\n");
        sb.append("    return mid;\n");
        sb.append("}\n\n");
        sb.append("jmethodID resolve_imethod(JNIEnv* env, int32_t id) { return resolve_method_impl(env, id, false); }\n");
        sb.append("jmethodID resolve_smethod(JNIEnv* env, int32_t id) { return resolve_method_impl(env, id, true); }\n\n");

        sb.append("static jfieldID resolve_field_impl(JNIEnv* env, int32_t fid_id, bool is_static) {\n");
        sb.append("    uintptr_t v = __atomic_load_n(&g_field_cache[fid_id], __ATOMIC_ACQUIRE);\n");
        sb.append("    if (v != 0) [[likely]] return (jfieldID)(v ^ g_ptr_cookie);\n");
        sb.append("    const MemberMeta& fm = g_field_meta[fid_id];\n");
        sb.append("    jclass cls = resolve_class(env, (int32_t)fm.cls_id);\n");
        sb.append("    if (!cls || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    char nb[256], db[512];\n");
        sb.append("    decrypt_sym(fm.name_sym, nb, sizeof(nb));\n");
        sb.append("    decrypt_sym(fm.desc_sym, db, sizeof(db));\n");
        sb.append("    jfieldID fid = is_static ? env->GetStaticFieldID(cls, nb, db) : env->GetFieldID(cls, nb, db);\n");
        sb.append("    secure_wipe(nb, sizeof(nb)); secure_wipe(db, sizeof(db));\n");
        sb.append("    if (fid && !env->ExceptionCheck()) {\n");
        sb.append("        uintptr_t masked = ((uintptr_t)fid) ^ g_ptr_cookie;\n");
        sb.append("        __atomic_store_n(&g_field_cache[fid_id], masked, __ATOMIC_RELEASE);\n");
        sb.append("    }\n");
        sb.append("    return fid;\n");
        sb.append("}\n\n");
        sb.append("jfieldID resolve_ifield(JNIEnv* env, int32_t id) { return resolve_field_impl(env, id, false); }\n");
        sb.append("jfieldID resolve_sfield(JNIEnv* env, int32_t id) { return resolve_field_impl(env, id, true); }\n");
        sb.append("jclass resolve_field_owner(JNIEnv* env, int32_t fid_id) { return resolve_class(env, (int32_t)g_field_meta[fid_id].cls_id); }\n");
        sb.append("jclass resolve_method_owner(JNIEnv* env, int32_t mid_id) { return resolve_class(env, (int32_t)g_method_meta[mid_id].cls_id); }\n\n");

        sb.append("jmethodID resolve_dyn_method(JNIEnv* env, jobject recv, int32_t name_sym, int32_t desc_sym) {\n");
        sb.append("    jclass cls = env->GetObjectClass(recv);\n");
        sb.append("    char nb[256], db[512];\n");
        sb.append("    decrypt_sym((uint32_t)name_sym, nb, sizeof(nb));\n");
        sb.append("    decrypt_sym((uint32_t)desc_sym, db, sizeof(db));\n");
        sb.append("    jmethodID mid = env->GetMethodID(cls, nb, db);\n");
        sb.append("    secure_wipe(nb, sizeof(nb)); secure_wipe(db, sizeof(db));\n");
        sb.append("    env->DeleteLocalRef(cls);\n");
        sb.append("    return mid;\n");
        sb.append("}\n\n");

        sb.append("jfieldID resolve_dyn_field(JNIEnv* env, jobject obj, int32_t name_sym, int32_t desc_sym) {\n");
        sb.append("    jclass cls = env->GetObjectClass(obj);\n");
        sb.append("    char nb[256], db[512];\n");
        sb.append("    decrypt_sym((uint32_t)name_sym, nb, sizeof(nb));\n");
        sb.append("    decrypt_sym((uint32_t)desc_sym, db, sizeof(db));\n");
        sb.append("    jfieldID fid = env->GetFieldID(cls, nb, db);\n");
        sb.append("    secure_wipe(nb, sizeof(nb)); secure_wipe(db, sizeof(db));\n");
        sb.append("    env->DeleteLocalRef(cls);\n");
        sb.append("    return fid;\n");
        sb.append("}\n\n");

        // StringConcatFactory handler
        sb.append("jstring string_concat(JNIEnv* env, int32_t recipe_wid, const int32_t* const_wids, int32_t const_cnt, const ConcatArg* args, int32_t argc) {\n");
        sb.append("    jobject sbo = env->NewObject(g_cls_sb, g_mid_sb_init);\n");
        sb.append("    if (!sbo || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    const WStrMeta& rm = g_wstr_meta[(uint32_t)recipe_wid];\n");
        sb.append("    jchar stack_rec[256];\n");
        sb.append("    jchar* rbuf = rm.len <= 256 ? stack_rec : (jchar*)heap_alloc((size_t)rm.len * sizeof(jchar));\n");
        sb.append("    uint64_t st = splitmix64(").append(CryptoEngine.hex64(crypto.getMasterSeed())).append("ULL ^ ((uint64_t)(uint32_t)recipe_wid * 0x94D049BB133111EBULL) ^ 0x55AA33CC11EE7799ULL);\n");
        sb.append("    for (uint32_t i = 0; i < rm.len; i++) {\n");
        sb.append("        st = splitmix64(st ^ ((uint64_t)i * 0xBF58476D1CE4E5B9ULL));\n");
        sb.append("        uint16_t k = (uint16_t)(st & 0xFFFFu);\n");
        sb.append("        uint32_t rot = (uint32_t)((st >> 48) & 15u);\n");
        sb.append("        uint16_t r = g_wstr_blob[rm.off + i] ^ (uint16_t)((i * 131u + (uint32_t)recipe_wid * 17u) & 0xFFFFu);\n");
        sb.append("        uint16_t x = (uint16_t)(((r >> rot) | (r << (16u - rot))) & 0xFFFFu);\n");
        sb.append("        rbuf[i] = (jchar)(x ^ k);\n");
        sb.append("    }\n");
        sb.append("    uint32_t seg_start = 0;\n");
        sb.append("    int32_t arg_idx = 0, const_idx = 0;\n");
        sb.append("    auto flush_lit = [&](uint32_t s, uint32_t e) {\n");
        sb.append("        if (e > s) {\n");
        sb.append("            jstring js = env->NewString(rbuf + s, (jsize)(e - s));\n");
        sb.append("            jobject tmp = env->CallObjectMethod(sbo, g_mid_sb_app_str, js);\n");
        sb.append("            if (tmp) env->DeleteLocalRef(tmp);\n");
        sb.append("            if (js) env->DeleteLocalRef(js);\n");
        sb.append("        }\n");
        sb.append("    };\n");
        sb.append("    for (uint32_t i = 0; i < rm.len; i++) {\n");
        sb.append("        if (rbuf[i] == 1) {\n");
        sb.append("            flush_lit(seg_start, i); seg_start = i + 1;\n");
        sb.append("            if (arg_idx < argc) {\n");
        sb.append("                const ConcatArg& ca = args[arg_idx++];\n");
        sb.append("                jobject tmp = nullptr;\n");
        sb.append("                switch (ca.kind) {\n");
        sb.append("                    case 1: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_z, (jboolean)(ca.i & 1 ? JNI_TRUE : JNI_FALSE)); break;\n");
        sb.append("                    case 2: case 4: case 5: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_i, (jint)ca.i); break;\n");
        sb.append("                    case 3: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_c, (jchar)ca.i); break;\n");
        sb.append("                    case 6: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_j, (jlong)ca.j); break;\n");
        sb.append("                    case 7: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_f, (jfloat)ca.f); break;\n");
        sb.append("                    case 8: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_d, (jdouble)ca.d); break;\n");
        sb.append("                    default: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_obj, ca.obj); break;\n");
        sb.append("                }\n");
        sb.append("                if (tmp) env->DeleteLocalRef(tmp);\n");
        sb.append("            }\n");
        sb.append("        } else if (rbuf[i] == 2) {\n");
        sb.append("            flush_lit(seg_start, i); seg_start = i + 1;\n");
        sb.append("            if (const_idx < const_cnt && const_wids) {\n");
        sb.append("                jstring cs = new_wstr(env, const_wids[const_idx++]);\n");
        sb.append("                jobject tmp = env->CallObjectMethod(sbo, g_mid_sb_app_str, cs);\n");
        sb.append("                if (tmp) env->DeleteLocalRef(tmp);\n");
        sb.append("                if (cs) env->DeleteLocalRef(cs);\n");
        sb.append("            }\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("    flush_lit(seg_start, rm.len);\n");
        sb.append("    secure_wipe(rbuf, (size_t)rm.len * sizeof(jchar));\n");
        sb.append("    if (rbuf != stack_rec) heap_free(rbuf);\n");
        sb.append("    jstring out = (jstring)env->CallObjectMethod(sbo, g_mid_toString);\n");
        sb.append("    env->DeleteLocalRef(sbo);\n");
        sb.append("    return out;\n");
        sb.append("}\n\n");

        // Multi-dimensional array creator
        sb.append("static jobject alloc_multi_rec(JNIEnv* env, const int32_t* cids, const int32_t* dims, int32_t level, int32_t ndims, int32_t elem_kind) {\n");
        sb.append("    int32_t len = dims[level];\n");
        sb.append("    if (len < 0) { throw_neg_arr(env); return nullptr; }\n");
        sb.append("    if (level == ndims - 1) {\n");
        sb.append("        switch (elem_kind) {\n");
        sb.append("            case 1: return env->NewBooleanArray(len);\n");
        sb.append("            case 2: return env->NewByteArray(len);\n");
        sb.append("            case 3: return env->NewCharArray(len);\n");
        sb.append("            case 4: return env->NewShortArray(len);\n");
        sb.append("            case 5: return env->NewIntArray(len);\n");
        sb.append("            case 6: return env->NewLongArray(len);\n");
        sb.append("            case 7: return env->NewFloatArray(len);\n");
        sb.append("            case 8: return env->NewDoubleArray(len);\n");
        sb.append("            default: {\n");
        sb.append("                jclass ec = resolve_class(env, cids[level]);\n");
        sb.append("                return env->NewObjectArray(len, ec, nullptr);\n");
        sb.append("            }\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("    jclass sub_cls = resolve_class(env, cids[level]);\n");
        sb.append("    if (!sub_cls || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    jobjectArray arr = env->NewObjectArray(len, sub_cls, nullptr);\n");
        sb.append("    if (!arr || env->ExceptionCheck()) return nullptr;\n");
        sb.append("    for (int32_t i = 0; i < len; i++) {\n");
        sb.append("        jobject sub = alloc_multi_rec(env, cids, dims, level + 1, ndims, elem_kind);\n");
        sb.append("        if (env->ExceptionCheck()) { if (sub) env->DeleteLocalRef(sub); env->DeleteLocalRef(arr); return nullptr; }\n");
        sb.append("        env->SetObjectArrayElement(arr, i, sub);\n");
        sb.append("        if (sub) env->DeleteLocalRef(sub);\n");
        sb.append("    }\n");
        sb.append("    return arr;\n");
        sb.append("}\n\n");

        sb.append("jobject new_multi_array(JNIEnv* env, const int32_t* cids, const int32_t* dims, int32_t ndims, int32_t elem_kind) {\n");
        sb.append("    for (int32_t i = 0; i < ndims; i++) if (dims[i] < 0) { throw_neg_arr(env); return nullptr; }\n");
        sb.append("    return alloc_multi_rec(env, cids, dims, 0, ndims, elem_kind);\n");
        sb.append("}\n\n");

        // Dynamic boolean[] vs byte[] handlers
        sb.append("int32_t baload_dyn(JNIEnv* env, jarray arr, int32_t idx) {\n");
        sb.append("    if (env->IsInstanceOf(arr, g_cls_bool_arr)) {\n");
        sb.append("        jboolean v = 0; env->GetBooleanArrayRegion((jbooleanArray)arr, idx, 1, &v);\n");
        sb.append("        return v ? 1 : 0;\n");
        sb.append("    } else {\n");
        sb.append("        jbyte v = 0; env->GetByteArrayRegion((jbyteArray)arr, idx, 1, &v);\n");
        sb.append("        return (int32_t)(int8_t)v;\n");
        sb.append("    }\n");
        sb.append("}\n");
        sb.append("void bastore_dyn(JNIEnv* env, jarray arr, int32_t idx, int32_t val) {\n");
        sb.append("    if (env->IsInstanceOf(arr, g_cls_bool_arr)) {\n");
        sb.append("        jboolean v = (val & 1) ? JNI_TRUE : JNI_FALSE;\n");
        sb.append("        env->SetBooleanArrayRegion((jbooleanArray)arr, idx, 1, &v);\n");
        sb.append("    } else {\n");
        sb.append("        jbyte v = (jbyte)val;\n");
        sb.append("        env->SetByteArrayRegion((jbyteArray)arr, idx, 1, &v);\n");
        sb.append("    }\n");
        sb.append("}\n\n");

        // Exception throw helpers
        sb.append("void throw_arith(JNIEnv* env) { char msg[32]; decrypt_sym(").append(symDivZeroMsg).append("u, msg, sizeof(msg)); env->ThrowNew(g_cls_arith, msg); }\n");
        sb.append("void throw_npe(JNIEnv* env) { env->ThrowNew(g_cls_npe, \"\"); }\n");
        sb.append("void throw_neg_arr(JNIEnv* env) { env->ThrowNew(g_cls_negarr, \"\"); }\n");
        sb.append("void throw_cce(JNIEnv* env) { env->ThrowNew(g_cls_cce, \"\"); }\n");
        sb.append("void throw_aioobe(JNIEnv* env) { env->ThrowNew(g_cls_aioobe, \"\"); }\n\n");

        sb.append("static volatile int32_t g_jar_verified = ").append(config.isAntiTamper() ? "0" : "1").append(";\n\n");
        // Class registration & JAR integrity verifier
        sb.append("static void JNICALL hy_register_natives(JNIEnv* env, jclass, jclass target_cls, jint class_id) {\n");
        sb.append("    if (g_tampered || !g_jar_verified) { poison_cookie(); return; }\n");
        sb.append("    if (!target_cls) return;\n");
        sb.append("    for (uint32_t i = 0; i < g_reg_class_count; i++) {\n");
        sb.append("        if (g_reg_classes[i].class_id == class_id) {\n");
        sb.append("            const RegClassMeta& rc = g_reg_classes[i];\n");
        sb.append("            if (rc.count == 0) return;\n");
        sb.append("            JNINativeMethod* methods = (JNINativeMethod*)heap_alloc(rc.count * sizeof(JNINativeMethod));\n");
        sb.append("            char* str_arena = (char*)heap_alloc(rc.count * 768);\n");
        sb.append("            for (uint32_t m = 0; m < rc.count; m++) {\n");
        sb.append("                const RegMethodMeta& rm = g_reg_methods[rc.start + m];\n");
        sb.append("                char* nb = str_arena + m * 768;\n");
        sb.append("                char* db = nb + 256;\n");
        sb.append("                decrypt_sym(rm.name_sym, nb, 256);\n");
        sb.append("                decrypt_sym(rm.desc_sym, db, 512);\n");
        sb.append("                methods[m].name = nb;\n");
        sb.append("                methods[m].signature = db;\n");
        sb.append("                methods[m].fnPtr = rm.fn;\n");
        sb.append("            }\n");
        sb.append("            env->RegisterNatives(target_cls, methods, (jint)rc.count);\n");
        sb.append("            secure_wipe(str_arena, rc.count * 768);\n");
        sb.append("            heap_free(str_arena);\n");
        sb.append("            heap_free(methods);\n");
        sb.append("            return;\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("}\n\n");

        // Anti-tamper JAR verification + native .fucked decryption & DefineClass loader
        sb.append("struct FuckedMeta { uint32_t cls_sym; uint32_t path_sym; uint32_t raw_len; uint64_t seed; uint64_t mac; };\n");
        sb.append("static const FuckedMeta g_fucked_entries[] = {\n");
        for (long[] row : fuckedMetaRows) {
            sb.append("    {").append(row[0]).append("u, ").append(row[1]).append("u, ").append(row[2]).append("u, ")
              .append(CryptoEngine.hex64(row[3])).append("ULL, ").append(CryptoEngine.hex64(row[4])).append("ULL},\n");
        }
        if (fuckedMetaRows.isEmpty()) sb.append("    {0u, 0u, 0u, 0ULL, 0ULL}\n");
        sb.append("};\nstatic constexpr uint32_t g_fucked_count = ").append(fuckedMetaRows.size()).append("u;\n\n");

        sb.append("static void decrypt_fucked_inplace(uint8_t* buf, uint32_t len, uint64_t file_seed) {\n");
        sb.append("    uint64_t st = splitmix64(file_seed ^ 0xF0C7D0C7A1B2C3D4ULL);\n");
        sb.append("    for (uint32_t i = 0; i < len; i++) {\n");
        sb.append("        st = splitmix64(st + (uint64_t)i * 0x9E3779B97F4A7C15ULL);\n");
        sb.append("        uint8_t k = (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);\n");
        sb.append("        uint32_t rot = (uint32_t)((st >> 56) & 7u);\n");
        sb.append("        uint8_t r = buf[i] ^ (uint8_t)((i * 73u + (uint32_t)file_seed) & 0xFFu);\n");
        sb.append("        uint8_t x = (uint8_t)(((r >> rot) | (r << (8u - rot))) & 0xFFu);\n");
        sb.append("        buf[i] = (uint8_t)(x ^ k);\n");
        sb.append("    }\n");
        sb.append("}\n\n");

        sb.append("static void JNICALL hy_verify_loader(JNIEnv* env, jclass, jobject loader) {\n");
        sb.append("    if (loader && !g_mod_loader) {\n");
        sb.append("        g_mod_loader = env->NewGlobalRef(loader);\n");
        sb.append("    }\n");
        boolean needStreamTools = (config.isAntiTamper() && !jarVerifyResources.isEmpty()) || !fuckedMetaRows.isEmpty();
        if (needStreamTools) {
            sb.append("    if (!g_mod_loader) { g_tampered = 1; poison_cookie(); return; }\n");
            sb.append("    jclass cl_cls = find_class_by_sym(env, ").append(symCl).append("u);\n");
            sb.append("    jclass is_cls = find_class_by_sym(env, ").append(symIs).append("u);\n");
            sb.append("    char gn[32], gd[64], rn[16], rd[16], cn[16], vd[8];\n");
            sb.append("    decrypt_sym(").append(symGetRes).append("u, gn, sizeof(gn));\n");
            sb.append("    decrypt_sym(").append(symGetResDesc).append("u, gd, sizeof(gd));\n");
            sb.append("    decrypt_sym(").append(symIsRead).append("u, rn, sizeof(rn));\n");
            sb.append("    decrypt_sym(").append(symIsReadDesc).append("u, rd, sizeof(rd));\n");
            sb.append("    decrypt_sym(").append(symIsClose).append("u, cn, sizeof(cn));\n");
            sb.append("    decrypt_sym(").append(symSbInitDesc).append("u, vd, sizeof(vd));\n");
            sb.append("    jmethodID mid_get = env->GetMethodID(cl_cls, gn, gd);\n");
            sb.append("    jmethodID mid_read = env->GetMethodID(is_cls, rn, rd);\n");
            sb.append("    jmethodID mid_close = env->GetMethodID(is_cls, cn, vd);\n");
            sb.append("    jbyteArray jbuf = env->NewByteArray(4096);\n");
            sb.append("    jbyte raw[4096];\n");
            if (config.isAntiTamper() && !jarVerifyResources.isEmpty()) {
                sb.append("    uint64_t h = 0xCBF29CE484222325ULL;\n");
                sb.append("    const uint32_t rsyms[] = {");
                for (int r : verifyResSyms) sb.append(r).append("u,");
                sb.append("};\n");
                sb.append("    for (uint32_t idx = 0; idx < ").append(verifyResSyms.length).append("u; idx++) {\n");
                sb.append("        char rname[256]; decrypt_sym(rsyms[idx], rname, sizeof(rname));\n");
                sb.append("        jstring js = env->NewStringUTF(rname);\n");
                sb.append("        jobject stm = env->CallObjectMethod(g_mod_loader, mid_get, js);\n");
                sb.append("        env->DeleteLocalRef(js);\n");
                sb.append("        if (env->ExceptionCheck() || !stm) { if (env->ExceptionCheck()) env->ExceptionClear(); g_tampered = 1; break; }\n");
                sb.append("        for (;;) {\n");
                sb.append("            jint n = env->CallIntMethod(stm, mid_read, jbuf);\n");
                sb.append("            if (env->ExceptionCheck()) { env->ExceptionClear(); g_tampered = 1; break; }\n");
                sb.append("            if (n <= 0) break;\n");
                sb.append("            env->GetByteArrayRegion(jbuf, 0, n, raw);\n");
                sb.append("            for (jint k = 0; k < n; k++) { h ^= (uint8_t)raw[k]; h *= 0x100000001B3ULL; }\n");
                sb.append("        }\n");
                sb.append("        env->CallVoidMethod(stm, mid_close);\n");
                sb.append("        if (env->ExceptionCheck()) env->ExceptionClear();\n");
                sb.append("        env->DeleteLocalRef(stm);\n");
                sb.append("    }\n");
                sb.append("    if (h != ").append(CryptoEngine.hex64(expectedJarHash)).append("ULL) { g_tampered = 1; poison_cookie(); }\n");
            }
            if (!fuckedMetaRows.isEmpty()) {
                sb.append("    if (!g_tampered) {\n");
                sb.append("        for (uint32_t fi = 0; fi < g_fucked_count; fi++) {\n");
                sb.append("            const FuckedMeta& fm = g_fucked_entries[fi];\n");
                sb.append("            char cname[512], pname[512];\n");
                sb.append("            decrypt_sym(fm.cls_sym, cname, sizeof(cname));\n");
                sb.append("            decrypt_sym(fm.path_sym, pname, sizeof(pname));\n");
                sb.append("            jstring js = env->NewStringUTF(pname);\n");
                sb.append("            jobject stm = env->CallObjectMethod(g_mod_loader, mid_get, js);\n");
                sb.append("            env->DeleteLocalRef(js);\n");
                sb.append("            if (env->ExceptionCheck() || !stm) { if (env->ExceptionCheck()) env->ExceptionClear(); g_tampered = 1; poison_cookie(); break; }\n");
                sb.append("            uint8_t* cbuf = (uint8_t*)heap_alloc(fm.raw_len > 0 ? fm.raw_len : 1);\n");
                sb.append("            uint32_t total = 0;\n");
                sb.append("            for (;;) {\n");
                sb.append("                jint n = env->CallIntMethod(stm, mid_read, jbuf);\n");
                sb.append("                if (env->ExceptionCheck()) { env->ExceptionClear(); g_tampered = 1; break; }\n");
                sb.append("                if (n <= 0) break;\n");
                sb.append("                if (total + (uint32_t)n > fm.raw_len) { g_tampered = 1; break; }\n");
                sb.append("                env->GetByteArrayRegion(jbuf, 0, n, raw);\n");
                sb.append("                __builtin_memcpy(cbuf + total, raw, (size_t)n);\n");
                sb.append("                total += (uint32_t)n;\n");
                sb.append("            }\n");
                sb.append("            env->CallVoidMethod(stm, mid_close);\n");
                sb.append("            if (env->ExceptionCheck()) env->ExceptionClear();\n");
                sb.append("            env->DeleteLocalRef(stm);\n");
                sb.append("            if (!g_tampered && total == fm.raw_len) {\n");
                sb.append("                decrypt_fucked_inplace(cbuf, fm.raw_len, fm.seed);\n");
                sb.append("                uint64_t mac = 0xCBF29CE484222325ULL;\n");
                sb.append("                for (uint32_t k = 0; k < fm.raw_len; k++) { mac ^= cbuf[k]; mac *= 0x100000001B3ULL; }\n");
                sb.append("                if (mac != fm.mac) {\n");
                sb.append("                    g_tampered = 1; poison_cookie();\n");
                sb.append("                } else {\n");
                sb.append("                    jclass dc = env->DefineClass(cname, g_mod_loader, (const jbyte*)cbuf, (jsize)fm.raw_len);\n");
                sb.append("                    if (!dc || env->ExceptionCheck()) { if (env->ExceptionCheck()) env->ExceptionClear(); g_tampered = 1; poison_cookie(); }\n");
                sb.append("                    if (dc) env->DeleteLocalRef(dc);\n");
                sb.append("                }\n");
                sb.append("            } else { g_tampered = 1; poison_cookie(); }\n");
                sb.append("            secure_wipe(cbuf, fm.raw_len); heap_free(cbuf);\n");
                sb.append("            secure_wipe(cname, sizeof(cname)); secure_wipe(pname, sizeof(pname));\n");
                sb.append("            if (g_tampered) break;\n");
                sb.append("        }\n");
                sb.append("    }\n");
            }
            sb.append("    env->DeleteLocalRef(jbuf);\n");
            sb.append("    env->DeleteLocalRef(cl_cls);\n");
            sb.append("    env->DeleteLocalRef(is_cls);\n");
            sb.append("    if (!g_tampered) g_jar_verified = 1;\n");
        } else {
            sb.append("    g_jar_verified = 1;\n");
        }
        sb.append("}\n\n");

        // Cache core bootstrap classes & methods
        sb.append("static void init_bootstrap(JNIEnv* env) {\n");
        sb.append("    auto gcls = [&](uint32_t sym) -> jclass {\n");
        sb.append("        char b[128]; decrypt_sym(sym, b, sizeof(b));\n");
        sb.append("        jclass lc = env->FindClass(b); secure_wipe(b, sizeof(b));\n");
        sb.append("        if (!lc) return nullptr;\n");
        sb.append("        jclass gc = (jclass)env->NewGlobalRef(lc); env->DeleteLocalRef(lc); return gc;\n");
        sb.append("    };\n");
        sb.append("    auto gmid = [&](jclass c, uint32_t ns, uint32_t ds, bool st) -> jmethodID {\n");
        sb.append("        char nb[64], db[128]; decrypt_sym(ns, nb, sizeof(nb)); decrypt_sym(ds, db, sizeof(db));\n");
        sb.append("        jmethodID m = st ? env->GetStaticMethodID(c, nb, db) : env->GetMethodID(c, nb, db);\n");
        sb.append("        secure_wipe(nb, sizeof(nb)); secure_wipe(db, sizeof(db)); return m;\n");
        sb.append("    };\n");
        sb.append("    g_cls_class = gcls(").append(symClass).append("u);\n");
        sb.append("    g_mid_forName = gmid(g_cls_class, ").append(symForName).append("u, ").append(symForNameDesc).append("u, true);\n");
        sb.append("    g_cls_sb = gcls(").append(symSb).append("u);\n");
        sb.append("    g_mid_sb_init = gmid(g_cls_sb, ").append(symSbInit).append("u, ").append(symSbInitDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_str = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppStrDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_obj = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppObjDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_i = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppIntDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_j = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppLongDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_f = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppFloatDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_d = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppDoubleDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_z = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppBoolDesc).append("u, false);\n");
        sb.append("    g_mid_sb_app_c = gmid(g_cls_sb, ").append(symSbAppStr).append("u, ").append(symSbAppCharDesc).append("u, false);\n");
        sb.append("    g_mid_toString = gmid(g_cls_sb, ").append(symToStr).append("u, ").append(symToStrDesc).append("u, false);\n");
        sb.append("    g_cls_bool_arr = gcls(").append(symBoolArr).append("u);\n");
        sb.append("    g_cls_obj = gcls(").append(symObj).append("u);\n");
        sb.append("    g_cls_npe = gcls(").append(symNpe).append("u);\n");
        sb.append("    g_cls_arith = gcls(").append(symArith).append("u);\n");
        sb.append("    g_cls_negarr = gcls(").append(symNegArr).append("u);\n");
        sb.append("    g_cls_cce = gcls(").append(symCce).append("u);\n");
        sb.append("    g_cls_aioobe = gcls(").append(symAioobe).append("u);\n");
        sb.append("}\n\n");

        sb.append("} // namespace hy\n\n");

        // JNI_OnLoad
        sb.append("extern \"C\" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {\n");
        sb.append("    JNIEnv* env = nullptr;\n");
        sb.append("    if (vm->GetEnv((void**)&env, JNI_VERSION_1_8) != JNI_OK || !env) return JNI_ERR;\n");
        sb.append("    uint64_t tsc = __rdtsc();\n");
        sb.append("    hy::g_ptr_cookie = (uintptr_t)(hy::splitmix64(tsc ^ (uintptr_t)env ^ (uintptr_t)&vm) | 1ULL);\n");
        sb.append("    hy::g_rt_entropy ^= tsc;\n");
        sb.append("    hy::run_security_checks(env);\n");
        sb.append("    hy::init_bootstrap(env);\n");
        sb.append("    jclass lcls = hy::find_class_by_sym(env, ").append(symLoader).append("u);\n");
        sb.append("    if (lcls) {\n");
        sb.append("        char rn[64], rd[64], vn[64], vd[64];\n");
        sb.append("        hy::decrypt_sym(").append(symRegName).append("u, rn, sizeof(rn));\n");
        sb.append("        hy::decrypt_sym(").append(symRegDesc).append("u, rd, sizeof(rd));\n");
        sb.append("        hy::decrypt_sym(").append(symVerName).append("u, vn, sizeof(vn));\n");
        sb.append("        hy::decrypt_sym(").append(symVerDesc).append("u, vd, sizeof(vd));\n");
        sb.append("        JNINativeMethod reg[2] = {\n");
        sb.append("            {rn, rd, (void*)&hy::hy_register_natives},\n");
        sb.append("            {vn, vd, (void*)&hy::hy_verify_loader}\n");
        sb.append("        };\n");
        sb.append("        env->RegisterNatives(lcls, reg, 2);\n");
        sb.append("        hy::secure_wipe(rn, sizeof(rn)); hy::secure_wipe(rd, sizeof(rd));\n");
        sb.append("        hy::secure_wipe(vn, sizeof(vn)); hy::secure_wipe(vd, sizeof(vd));\n");
        sb.append("        env->DeleteLocalRef(lcls);\n");
        sb.append("    }\n");
        sb.append("    return JNI_VERSION_1_8;\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static void emitSecurityEngine(StringBuilder sb, ObfuscationConfig config) {
        int hKernel32 = CryptoEngine.fnv1a32LowerAscii("kernel32.dll");
        int hNtdll = CryptoEngine.fnv1a32LowerAscii("ntdll.dll");
        int hJvm = CryptoEngine.fnv1a32LowerAscii("jvm.dll");
        int hIsDbg = CryptoEngine.fnv1a32("IsDebuggerPresent");
        int hNtQuery = CryptoEngine.fnv1a32("NtQueryInformationProcess");
        int hGetCtx = CryptoEngine.fnv1a32("GetThreadContext");
        int hCurThread = CryptoEngine.fnv1a32("GetCurrentThread");
        int hCurProc = CryptoEngine.fnv1a32("GetCurrentProcess");
        int hTermProc = CryptoEngine.fnv1a32("TerminateProcess");

        sb.append("""
struct HyUnicodeStr { uint16_t Length; uint16_t MaxLength; uint32_t Pad; wchar_t* Buffer; };
struct HyListEntry { HyListEntry* Flink; HyListEntry* Blink; };

static inline uint32_t fnv1a_ascii(const char* s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) { h ^= (uint8_t)(*s++); h *= 0x01000193u; }
    return h;
}

static inline uint32_t fnv1a_wstr_lower(const wchar_t* s, uint16_t byteLen) {
    uint32_t h = 0x811c9dc5u;
    uint16_t chars = byteLen / 2;
    for (uint16_t i = 0; i < chars; i++) {
        wchar_t c = s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        h ^= (uint8_t)(c & 0xFF);
        h *= 0x01000193u;
    }
    return h;
}

static inline uint8_t* get_peb() {
    uint64_t p = 0;
    asm volatile("movq %%gs:0x60, %0" : "=r"(p));
    return (uint8_t*)p;
}

static uintptr_t find_module_base(uint32_t mod_hash, uint32_t* out_img_size = nullptr) {
    uint8_t* peb = get_peb();
    if (!peb) return 0;
    uint8_t* ldr = *(uint8_t**)(peb + 0x18);
    if (!ldr) return 0;
    HyListEntry* head = (HyListEntry*)(ldr + 0x20); // InMemoryOrderModuleList
    for (HyListEntry* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        uint8_t* entry = (uint8_t*)cur - 0x10;
        uintptr_t base = *(uintptr_t*)(entry + 0x30);
        uint32_t sz = *(uint32_t*)(entry + 0x40);
        HyUnicodeStr* bname = (HyUnicodeStr*)(entry + 0x58);
        if (base && bname->Buffer && bname->Length > 0) {
            if (fnv1a_wstr_lower(bname->Buffer, bname->Length) == mod_hash) {
                if (out_img_size) *out_img_size = sz;
                return base;
            }
        }
    }
    return 0;
}

static void* resolve_export(uintptr_t mod_base, uint32_t fn_hash) {
    if (!mod_base) return nullptr;
    auto* dos = (const IMAGE_DOS_HEADER*)mod_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (const IMAGE_NT_HEADERS64*)(mod_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return nullptr;
    auto* exp = (const IMAGE_EXPORT_DIRECTORY*)(mod_base + dir.VirtualAddress);
    auto* names = (const uint32_t*)(mod_base + exp->AddressOfNames);
    auto* ords = (const uint16_t*)(mod_base + exp->AddressOfNameOrdinals);
    auto* funcs = (const uint32_t*)(mod_base + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(mod_base + names[i]);
        if (fnv1a_ascii(n) == fn_hash) {
            uint32_t rva = funcs[ords[i]];
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) return nullptr; // forwarded
            return (void*)(mod_base + rva);
        }
    }
    return nullptr;
}

static void poison_cookie() {
    g_tampered = 1;
    g_ptr_cookie ^= 0xDEAD0000BEEF1337ULL;
}

static bool wstr_icontains_ascii(const wchar_t* ws, uint16_t byteLen, const char* pat) {
    if (!ws || !byteLen) return false;
    uint16_t n = byteLen / 2;
    size_t pn = 0;
    while (pat[pn]) pn++;
    if (pn == 0 || n < pn) return false;
    for (uint16_t i = 0; i <= n - pn; i++) {
        bool ok = true;
        for (size_t j = 0; j < pn; j++) {
            wchar_t wc = ws[i + j];
            if (wc >= L'A' && wc <= L'Z') wc += 32;
            char pc = pat[j];
            if (pc >= 'A' && pc <= 'Z') pc += 32;
            if ((char)wc != pc) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}
""");

        sb.append("static void run_security_checks(JNIEnv* env) {\n");
        if (config.isAntiDebug()) {
            sb.append("    uint8_t* peb = get_peb();\n");
            sb.append("    if (peb) {\n");
            sb.append("        if (peb[2] != 0) poison_cookie();\n"); // BeingDebugged
            sb.append("        uint32_t ntGlobalFlag = *(uint32_t*)(peb + 0xBC);\n");
            sb.append("        if (ntGlobalFlag & 0x70u) poison_cookie();\n");
            // Check command line for jdwp
            sb.append("        uint8_t* procParams = *(uint8_t**)(peb + 0x20);\n");
            sb.append("        if (procParams) {\n");
            sb.append("            HyUnicodeStr* cmd = (HyUnicodeStr*)(procParams + 0x70);\n");
            sb.append("            if (wstr_icontains_ascii(cmd->Buffer, cmd->Length, \"jdwp\") || wstr_icontains_ascii(cmd->Buffer, cmd->Length, \"xrunjdwp\")) {\n");
            sb.append("                poison_cookie();\n");
            sb.append("            }\n");
            sb.append("        }\n");
            sb.append("    }\n");
            sb.append("    uintptr_t k32 = find_module_base(").append(CryptoEngine.hex32(hKernel32)).append("u);\n");
            sb.append("    uintptr_t ntd = find_module_base(").append(CryptoEngine.hex32(hNtdll)).append("u);\n");
            sb.append("    using FnIsDbg = BOOL(WINAPI*)();\n");
            sb.append("    using FnNtQip = LONG(NTAPI*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);\n");
            sb.append("    using FnCurThr = HANDLE(WINAPI*)();\n");
            sb.append("    using FnGetCtx = BOOL(WINAPI*)(HANDLE, CONTEXT*);\n");
            sb.append("    auto pIsDbg = (FnIsDbg)resolve_export(k32, ").append(CryptoEngine.hex32(hIsDbg)).append("u);\n");
            sb.append("    if (pIsDbg && pIsDbg()) poison_cookie();\n");
            sb.append("    auto pNtQip = (FnNtQip)resolve_export(ntd, ").append(CryptoEngine.hex32(hNtQuery)).append("u);\n");
            sb.append("    if (pNtQip) {\n");
            sb.append("        uintptr_t dbgPort = 0;\n");
            sb.append("        if (pNtQip((HANDLE)-1, 7u, &dbgPort, sizeof(dbgPort), nullptr) == 0 && dbgPort != 0) poison_cookie();\n");
            sb.append("        uint32_t dbgFlags = 1;\n");
            sb.append("        if (pNtQip((HANDLE)-1, 0x1Fu, &dbgFlags, sizeof(dbgFlags), nullptr) == 0 && dbgFlags == 0) poison_cookie();\n");
            sb.append("        uintptr_t dbgObj = 0;\n");
            sb.append("        if (pNtQip((HANDLE)-1, 0x1Eu, &dbgObj, sizeof(dbgObj), nullptr) == 0 && dbgObj != 0) poison_cookie();\n");
            sb.append("    }\n");
            sb.append("    auto pCurThr = (FnCurThr)resolve_export(k32, ").append(CryptoEngine.hex32(hCurThread)).append("u);\n");
            sb.append("    auto pGetCtx = (FnGetCtx)resolve_export(k32, ").append(CryptoEngine.hex32(hGetCtx)).append("u);\n");
            sb.append("    if (pCurThr && pGetCtx) {\n");
            sb.append("        CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;\n");
            sb.append("        if (pGetCtx(pCurThr(), &ctx) && (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)) poison_cookie();\n");
            sb.append("    }\n");
        }
        if (config.isAntiDump()) {
            // Check JNI vtable hooks against jvm.dll bounds
            sb.append("    uint32_t jvm_sz = 0;\n");
            sb.append("    uintptr_t jvm_base = find_module_base(").append(CryptoEngine.hex32(hJvm)).append("u, &jvm_sz);\n");
            sb.append("    if (jvm_base && jvm_sz && env && env->functions) {\n");
            sb.append("        uintptr_t pReg = (uintptr_t)env->functions->RegisterNatives;\n");
            sb.append("        uintptr_t pFind = (uintptr_t)env->functions->FindClass;\n");
            sb.append("        if (pReg < jvm_base || pReg >= jvm_base + jvm_sz || pFind < jvm_base || pFind >= jvm_base + jvm_sz) {\n");
            sb.append("            poison_cookie();\n");
            sb.append("        } else {\n");
            sb.append("            uint8_t b0 = *(const uint8_t*)pReg;\n");
            sb.append("            if (b0 == 0xCC || b0 == 0xE9) poison_cookie();\n");
            sb.append("        }\n");
            sb.append("    }\n");
        }
        if (config.isAntiTamper()) {
            sb.append("    if (g_hydro_seal_box.hash != 0ULL) {\n");
            sb.append("        uint64_t h = 0xCBF29CE484222325ULL;\n");
            sb.append("        for (size_t i = 0; i < sizeof(g_sym_blob); i++) { h ^= g_sym_blob[i]; h *= 0x100000001B3ULL; }\n");
            sb.append("        if (h != g_hydro_seal_box.hash) poison_cookie();\n");
            sb.append("    }\n");
        }
        sb.append("    if (g_tampered) {\n");
        sb.append("        uintptr_t k32 = find_module_base(").append(CryptoEngine.hex32(hKernel32)).append("u);\n");
        sb.append("        using FnCurProc = HANDLE(WINAPI*)();\n");
        sb.append("        using FnTerm = BOOL(WINAPI*)(HANDLE, UINT);\n");
        sb.append("        auto pCP = (FnCurProc)resolve_export(k32, ").append(CryptoEngine.hex32(hCurProc)).append("u);\n");
        sb.append("        auto pTP = (FnTerm)resolve_export(k32, ").append(CryptoEngine.hex32(hTermProc)).append("u);\n");
        sb.append("        if (pCP && pTP) pTP(pCP(), 0xC0000005u);\n");
        sb.append("    }\n");
        sb.append("}\n\n");
    }

    public static String emitVmCpp(
            List<VmCompiler.CompiledVmMethod> vmMethods,
            VmIsa isa,
            CryptoEngine crypto) {

        StringBuilder sb = new StringBuilder(32768);
        sb.append("#include \"hydro_runtime.hpp\"\n\n");
        sb.append("namespace hy {\n\n");

        // Emit VM metadata tables
        sb.append("struct VmTryEntry { uint32_t start_pc; uint32_t end_pc; uint32_t handler_pc; int32_t catch_cls; };\n");
        sb.append("struct VmCallMeta { int32_t member_id; uint8_t ret_kind; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmFieldMeta { int32_t member_id; uint8_t field_kind; };\n");
        sb.append("struct VmConcatMeta { int32_t recipe_wid; uint16_t const_off; uint8_t const_cnt; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmMethodMeta {\n");
        sb.append("    uint32_t code_off; uint32_t code_len;\n");
        sb.append("    uint16_t max_stack; uint16_t max_locals;\n");
        sb.append("    uint32_t try_off; uint32_t try_cnt;\n");
        sb.append("    uint32_t call_off; uint32_t field_off; uint32_t concat_off;\n");
        sb.append("};\n\n");

        List<Byte> allCode = new ArrayList<>();
        List<VmCompiler.VmTryCatch> allTries = new ArrayList<>();
        List<int[]> allCalls = new ArrayList<>(); // [memberId, retKind, argOff, argCnt]
        List<Integer> allCallArgKinds = new ArrayList<>();
        List<int[]> allFields = new ArrayList<>();
        List<int[]> allConcats = new ArrayList<>(); // [recipeWid, constOff, constCnt, argOff, argCnt]
        List<Integer> allConcatConsts = new ArrayList<>();
        List<Integer> allConcatArgKinds = new ArrayList<>();
        List<int[]> methodMetas = new ArrayList<>();

        for (VmCompiler.CompiledVmMethod vm : vmMethods) {
            int cOff = allCode.size();
            for (byte b : vm.encryptedCode) allCode.add(b);
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
            methodMetas.add(new int[]{cOff, vm.encryptedCode.length, vm.maxStack, vm.maxLocals, tOff, vm.tryCatches.size(), callOff, fldOff, cncOff});
        }

        emitByteArr(sb, "g_vm_code", allCode);
        emitIntArr(sb, "g_vm_call_ak", allCallArgKinds);
        emitIntArr(sb, "g_vm_cnc_consts", allConcatConsts);
        emitIntArr(sb, "g_vm_cnc_ak", allConcatArgKinds);

        sb.append("static const VmTryEntry g_vm_tries[] = {\n");
        for (VmCompiler.VmTryCatch t : allTries) {
            sb.append("    {").append(t.startPc()).append("u, ").append(t.endPc()).append("u, ").append(t.handlerPc()).append("u, ").append(t.catchClsId()).append("},\n");
        }
        if (allTries.isEmpty()) sb.append("    {0u, 0u, 0u, -1}\n");
        sb.append("};\n");

        sb.append("static const VmCallMeta g_vm_calls[] = {\n");
        for (int[] c : allCalls) sb.append("    {").append(c[0]).append(", ").append(c[1]).append(", ").append(c[2]).append(", ").append(c[3]).append("},\n");
        if (allCalls.isEmpty()) sb.append("    {0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmFieldMeta g_vm_fields[] = {\n");
        for (int[] f : allFields) sb.append("    {").append(f[0]).append(", ").append(f[1]).append("},\n");
        if (allFields.isEmpty()) sb.append("    {0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmConcatMeta g_vm_concats[] = {\n");
        for (int[] cc : allConcats) sb.append("    {").append(cc[0]).append(", ").append(cc[1]).append(", ").append(cc[2]).append(", ").append(cc[3]).append(", ").append(cc[4]).append("},\n");
        if (allConcats.isEmpty()) sb.append("    {0, 0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmMethodMeta g_vm_methods[] = {\n");
        for (int[] m : methodMetas) {
            sb.append("    {").append(m[0]).append("u, ").append(m[1]).append("u, ").append(m[2]).append("u, ").append(m[3])
              .append("u, ").append(m[4]).append("u, ").append(m[5]).append("u, ").append(m[6]).append("u, ").append(m[7]).append("u, ").append(m[8]).append("u},\n");
        }
        if (methodMetas.isEmpty()) sb.append("    {0u, 0u, 4u, 4u, 0u, 0u, 0u, 0u, 0u}\n");
        sb.append("};\n\n");

        // Bytecode stream reader with per-PC keystream decryption
        sb.append("""
struct VmSlot {
    uint64_t u;
    int32_t r;
    uint8_t cat;
    uint8_t is_ref;
};

static inline uint64_t vm_sm64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
""");

        sb.append("uint64_t vm_exec(JNIEnv* env, jobject self_or_cls, uint32_t vm_method_id, const uint64_t* args, int32_t argc, int32_t ret_kind) {\n");
        sb.append("    const VmMethodMeta& mm = g_vm_methods[vm_method_id];\n");
        sb.append("    RefTable refs(env);\n");
        sb.append("    uint8_t* dec_buf = (uint8_t*)heap_alloc(mm.code_len > 0 ? mm.code_len : 1);\n");
        sb.append("    uint64_t st = vm_sm64(").append(CryptoEngine.hex64(isa.keySeed)).append("ULL ^ ((uint64_t)vm_method_id * 0x9E3779B97F4A7C15ULL));\n");
        sb.append("    for (uint32_t i = 0; i < mm.code_len; i++) {\n");
        sb.append("        st = vm_sm64(st + (uint64_t)i * 0xBF58476D1CE4E5B9ULL);\n");
        sb.append("        dec_buf[i] = g_vm_code[mm.code_off + i] ^ (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);\n");
        sb.append("    }\n");
        sb.append("    VmSlot stack_mem[64];\n");
        sb.append("    VmSlot local_mem[64];\n");
        sb.append("    VmSlot* stk = mm.max_stack <= 64 ? stack_mem : (VmSlot*)heap_alloc(mm.max_stack * sizeof(VmSlot));\n");
        sb.append("    VmSlot* loc = mm.max_locals <= 64 ? local_mem : (VmSlot*)heap_alloc(mm.max_locals * sizeof(VmSlot));\n");
        sb.append("    __builtin_memset(stk, 0, (size_t)mm.max_stack * sizeof(VmSlot));\n");
        sb.append("    __builtin_memset(loc, 0, (size_t)mm.max_locals * sizeof(VmSlot));\n");
        sb.append("    for (int32_t i = 0; i < mm.max_stack; i++) stk[i].r = -1;\n");
        sb.append("    for (int32_t i = 0; i < mm.max_locals; i++) loc[i].r = -1;\n");
        sb.append("    for (int32_t i = 0; i < argc; i++) {\n");
        sb.append("        uint64_t v = args[i];\n");
        sb.append("        if ((v & (1ULL << 63)) && false) {}\n");
        sb.append("        loc[i].u = v; loc[i].r = -1;\n");
        sb.append("    }\n");
        // Actually pack typed args cleanly: args passed from stub encode slot index + is_ref in high metadata? Even cleaner: pass VmArg array?
        // Wait: let's look at vm_exec callers (vm_stub_N)! The stub knows exact types and sets loc[slot] or passes VmInitArg[]!
        // Let's use `const uint64_t* args` where `self_or_cls` / stubs pass exact raw values + `is_ref_mask` or let's make vm_exec take `VmSlot* init_locals`?
        // Wait: even simpler! In `vm_exec`, if stub populates a `VmArg` or `uint64_t` where refs are already tracked? No, `RefTable` lives inside `vm_exec`!
        // So let's pass `uint64_t ref_mask` (or `uint8_t* arg_kinds`)! Wait: `uint64_t` `arg_ref_mask` supports up to 64 local slots effortlessly (or `const uint8_t* slot_types`)!
        sb.setLength(0);
        return emitVmCppComplete(vmMethods, isa, crypto, allCode, allTries, allCalls, allCallArgKinds, allFields, allConcats, allConcatConsts, allConcatArgKinds, methodMetas);
    }

    private static String emitVmCppComplete(
            List<VmCompiler.CompiledVmMethod> vmMethods,
            VmIsa isa,
            CryptoEngine crypto,
            List<Byte> allCode,
            List<VmCompiler.VmTryCatch> allTries,
            List<int[]> allCalls,
            List<Integer> allCallArgKinds,
            List<int[]> allFields,
            List<int[]> allConcats,
            List<Integer> allConcatConsts,
            List<Integer> allConcatArgKinds,
            List<int[]> methodMetas) {

        StringBuilder sb = new StringBuilder(49152);
        sb.append("#include \"hydro_runtime.hpp\"\n\n");
        sb.append("namespace hy {\n\n");

        sb.append("struct VmTryEntry { uint32_t start_pc; uint32_t end_pc; uint32_t handler_pc; int32_t catch_cls; };\n");
        sb.append("struct VmCallMeta { int32_t member_id; uint8_t ret_kind; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmFieldMeta { int32_t member_id; uint8_t field_kind; };\n");
        sb.append("struct VmConcatMeta { int32_t recipe_wid; uint16_t const_off; uint8_t const_cnt; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmMethodMeta {\n");
        sb.append("    uint32_t code_off; uint32_t code_len;\n");
        sb.append("    uint16_t max_stack; uint16_t max_locals;\n");
        sb.append("    uint32_t try_off; uint32_t try_cnt;\n");
        sb.append("    uint32_t call_off; uint32_t field_off; uint32_t concat_off;\n");
        sb.append("};\n\n");

        emitByteArr(sb, "g_vm_code", allCode);
        emitIntArr(sb, "g_vm_call_ak", allCallArgKinds);
        emitIntArr(sb, "g_vm_cnc_consts", allConcatConsts);
        emitIntArr(sb, "g_vm_cnc_ak", allConcatArgKinds);

        sb.append("static const VmTryEntry g_vm_tries[] = {\n");
        for (VmCompiler.VmTryCatch t : allTries) {
            sb.append("    {").append(t.startPc()).append("u, ").append(t.endPc()).append("u, ").append(t.handlerPc()).append("u, ").append(t.catchClsId()).append("},\n");
        }
        if (allTries.isEmpty()) sb.append("    {0u, 0u, 0u, -1}\n");
        sb.append("};\n");

        sb.append("static const VmCallMeta g_vm_calls[] = {\n");
        for (int[] c : allCalls) sb.append("    {").append(c[0]).append(", ").append(c[1]).append(", ").append(c[2]).append(", ").append(c[3]).append("},\n");
        if (allCalls.isEmpty()) sb.append("    {0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmFieldMeta g_vm_fields[] = {\n");
        for (int[] f : allFields) sb.append("    {").append(f[0]).append(", ").append(f[1]).append("},\n");
        if (allFields.isEmpty()) sb.append("    {0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmConcatMeta g_vm_concats[] = {\n");
        for (int[] cc : allConcats) sb.append("    {").append(cc[0]).append(", ").append(cc[1]).append(", ").append(cc[2]).append(", ").append(cc[3]).append(", ").append(cc[4]).append("},\n");
        if (allConcats.isEmpty()) sb.append("    {0, 0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmMethodMeta g_vm_methods[] = {\n");
        for (int[] m : methodMetas) {
            sb.append("    {").append(m[0]).append("u, ").append(m[1]).append("u, ").append(m[2]).append("u, ").append(m[3])
              .append("u, ").append(m[4]).append("u, ").append(m[5]).append("u, ").append(m[6]).append("u, ").append(m[7]).append("u, ").append(m[8]).append("u},\n");
        }
        if (methodMetas.isEmpty()) sb.append("    {0u, 0u, 4u, 4u, 0u, 0u, 0u, 0u, 0u}\n");
        sb.append("};\n\n");

        sb.append("""
struct VmSlot {
    uint64_t u;
    int32_t r;
    uint8_t cat;
    uint8_t is_ref;
};

static inline uint64_t vm_sm64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline int32_t rd_i32(const uint8_t* p, uint32_t& pc) {
    int32_t v = 0; __builtin_memcpy(&v, p + pc, 4); pc += 4; return v;
}
static inline uint16_t rd_u16(const uint8_t* p, uint32_t& pc) {
    uint16_t v = 0; __builtin_memcpy(&v, p + pc, 2); pc += 2; return v;
}
static inline int64_t rd_i64(const uint8_t* p, uint32_t& pc) {
    int64_t v = 0; __builtin_memcpy(&v, p + pc, 8); pc += 8; return v;
}
""");

        // Core VM interpreter taking packed slot indices & ref mask (bits in ref_flags[i])
        sb.append("static uint64_t vm_exec_core(JNIEnv* env, uint32_t vm_method_id, const uint64_t* init_vals, const uint8_t* init_is_ref, int32_t init_slots, jobject* out_ref) {\n");
        sb.append("    const VmMethodMeta& mm = g_vm_methods[vm_method_id];\n");
        sb.append("    RefTable refs(env);\n");
        sb.append("    if (out_ref) *out_ref = nullptr;\n");
        sb.append("    uint8_t stack_code[1024];\n");
        sb.append("    uint8_t* dec = mm.code_len <= 1024 ? stack_code : (uint8_t*)heap_alloc(mm.code_len);\n");
        sb.append("    uint64_t st = vm_sm64(").append(CryptoEngine.hex64(isa.keySeed)).append("ULL ^ ((uint64_t)vm_method_id * 0x9E3779B97F4A7C15ULL));\n");
        sb.append("    for (uint32_t i = 0; i < mm.code_len; i++) {\n");
        sb.append("        st = vm_sm64(st + (uint64_t)i * 0xBF58476D1CE4E5B9ULL);\n");
        sb.append("        dec[i] = g_vm_code[mm.code_off + i] ^ (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);\n");
        sb.append("    }\n");
        sb.append("    VmSlot stack_mem[64]; VmSlot local_mem[64];\n");
        sb.append("    VmSlot* stk = mm.max_stack <= 64 ? stack_mem : (VmSlot*)heap_alloc(mm.max_stack * sizeof(VmSlot));\n");
        sb.append("    VmSlot* loc = mm.max_locals <= 64 ? local_mem : (VmSlot*)heap_alloc(mm.max_locals * sizeof(VmSlot));\n");
        sb.append("    for (int32_t i = 0; i < mm.max_stack; i++) { stk[i] = {0ULL, -1, 1, 0}; }\n");
        sb.append("    for (int32_t i = 0; i < mm.max_locals; i++) { loc[i] = {0ULL, -1, 1, 0}; }\n");
        sb.append("    for (int32_t i = 0; i < init_slots; i++) {\n");
        sb.append("        if (init_is_ref[i]) { loc[i].is_ref = 1; loc[i].r = refs.track((jobject)(uintptr_t)init_vals[i], false); }\n");
        sb.append("        else { loc[i].u = init_vals[i]; }\n");
        sb.append("    }\n");
        sb.append("""
    int32_t sp = 0;
    uint32_t pc = 0;
    uint32_t cur_insn_pc = 0;
    uint64_t ret_val = 0;

    auto cleanup = [&]() {
        if (dec != stack_code) heap_free(dec);
        if (stk != stack_mem) heap_free(stk);
        if (loc != local_mem) heap_free(loc);
    };

    auto clear_stk_slot = [&](int32_t idx) {
        if (stk[idx].is_ref && stk[idx].r >= 0) refs.release(stk[idx].r);
        stk[idx] = {0ULL, -1, 1, 0};
    };

    auto push_i32 = [&](int32_t v) { stk[sp++] = {(uint64_t)(uint32_t)v, -1, 1, 0}; };
    auto push_i64 = [&](int64_t v) { stk[sp++] = {(uint64_t)v, -1, 2, 0}; };
    auto push_f32 = [&](float v) { uint32_t b = 0; __builtin_memcpy(&b, &v, 4); stk[sp++] = {(uint64_t)b, -1, 1, 0}; };
    auto push_f64 = [&](double v) { uint64_t b = 0; __builtin_memcpy(&b, &v, 8); stk[sp++] = {b, -1, 2, 0}; };
    auto push_ref = [&](jobject o, bool owned) { stk[sp++] = {0ULL, refs.track(o, owned), 1, 1}; };
    auto as_i32 = [&](int32_t idx) -> int32_t { return (int32_t)(uint32_t)stk[idx].u; };
    auto as_i64 = [&](int32_t idx) -> int64_t { return (int64_t)stk[idx].u; };
    auto as_f32 = [&](int32_t idx) -> float { return bits_to_f32((uint32_t)stk[idx].u); };
    auto as_f64 = [&](int32_t idx) -> double { return bits_to_f64(stk[idx].u); };

    auto handle_exception = [&]() -> bool {
        if (!env->ExceptionCheck()) return false;
        jthrowable ex = env->ExceptionOccurred();
        env->ExceptionClear();
        for (uint32_t t = 0; t < mm.try_cnt; t++) {
            const VmTryEntry& te = g_vm_tries[mm.try_off + t];
            if (cur_insn_pc >= te.start_pc && cur_insn_pc < te.end_pc) {
                bool match = (te.catch_cls < 0);
                if (!match) {
                    jclass hc = resolve_class(env, te.catch_cls);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (hc && env->IsInstanceOf(ex, hc)) match = true;
                }
                if (match) {
                    for (int32_t s = 0; s < sp; s++) clear_stk_slot(s);
                    sp = 0;
                    push_ref(ex, true);
                    pc = te.handler_pc;
                    return true;
                }
            }
        }
        env->Throw(ex);
        env->DeleteLocalRef(ex);
        return false; // uncaught -> exit
    };
""");

        sb.append("    while (pc < mm.code_len) {\n");
        sb.append("        cur_insn_pc = pc;\n");
        sb.append("        uint8_t op = dec[pc++];\n");
        sb.append("        switch (op) {\n");

        // Generate shuffled VM opcode cases matching VmIsa
        emitVmCase(sb, isa, VmIsa.Op.NOP, "break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_I32, "push_i32(rd_i32(dec, pc)); break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_I64, "push_i64(rd_i64(dec, pc)); break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_F32, "stk[sp++] = {(uint64_t)(uint32_t)rd_i32(dec, pc), -1, 1, 0}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_F64, "stk[sp++] = {(uint64_t)rd_i64(dec, pc), -1, 2, 0}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_NULL, "stk[sp++] = {0ULL, -1, 1, 1}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_STR, """
            { int32_t wid = rd_i32(dec, pc); jstring js = new_wstr(env, wid);
              if (env->ExceptionCheck()) { if (js) env->DeleteLocalRef(js); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(js, true); break; }""");
        emitVmCase(sb, isa, VmIsa.Op.CONST_CLS, """
            { int32_t cid = rd_i32(dec, pc); jclass c = resolve_class(env, cid);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(c, false); break; }""");
        emitVmCase(sb, isa, VmIsa.Op.CONST_PRIM_CLS, """
            { int32_t k = rd_i32(dec, pc); jclass c = resolve_prim_class(env, k);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(c, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.LOAD_P, """
            { uint16_t slot = rd_u16(dec, pc); uint8_t cat = dec[pc++];
              stk[sp++] = {loc[slot].u, -1, cat, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.STORE_P, """
            { uint16_t slot = rd_u16(dec, pc); uint8_t cat = dec[pc++]; (void)cat;
              if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
              loc[slot] = {stk[--sp].u, -1, cat, 0}; stk[sp] = {0ULL, -1, 1, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.LOAD_R, """
            { uint16_t slot = rd_u16(dec, pc);
              stk[sp++] = {0ULL, refs.retain(loc[slot].r), 1, 1}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.STORE_R, """
            { uint16_t slot = rd_u16(dec, pc);
              int32_t nr = stk[--sp].r;
              if (!loc[slot].is_ref || loc[slot].r != nr) {
                  if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
                  loc[slot] = {0ULL, nr, 1, 1};
              } else { refs.release(nr); }
              stk[sp] = {0ULL, -1, 1, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.IINC, """
            { uint16_t slot = rd_u16(dec, pc); int32_t d = rd_i32(dec, pc);
              loc[slot].u = (uint64_t)(uint32_t)((int32_t)(uint32_t)loc[slot].u + d); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.POP1, "clear_stk_slot(--sp); break;");
        emitVmCase(sb, isa, VmIsa.Op.POP2, "if (stk[sp - 1].cat == 2) { clear_stk_slot(--sp); } else { clear_stk_slot(--sp); clear_stk_slot(--sp); } break;");
        emitVmCase(sb, isa, VmIsa.Op.DUP1, """
            { VmSlot v = stk[sp - 1]; if (v.is_ref) v.r = refs.retain(v.r); stk[sp++] = v; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP_X1, """
            { VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2];
              VmSlot v1c = v1; if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
              stk[sp] = v1; stk[sp - 1] = v2; stk[sp - 2] = v1c; sp++; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP_X2, """
            { VmSlot v1 = stk[sp - 1]; VmSlot v1c = v1; if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
              if (stk[sp - 2].cat == 2) { stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = v1c; }
              else { stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = v1c; }
              sp++; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2, """
            { if (stk[sp - 1].cat == 2) { stk[sp] = stk[sp - 1]; sp++; }
              else { VmSlot a = stk[sp - 2], b = stk[sp - 1];
                     if (a.is_ref) a.r = refs.retain(a.r); if (b.is_ref) b.r = refs.retain(b.r);
                     stk[sp] = a; stk[sp + 1] = b; sp += 2; } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2_X1, """
            { if (stk[sp - 1].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
              } else {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c; sp += 2;
              } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2_X2, """
            { if (stk[sp - 1].cat == 2 && stk[sp - 2].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
              } else if (stk[sp - 1].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = stk[sp]; sp++;
              } else if (stk[sp - 3].cat == 2) {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c; sp += 2;
              } else {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3], v4 = stk[sp - 4];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v4; stk[sp - 3] = v1c; stk[sp - 4] = v2c; sp += 2;
              } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.SWAP, "{ VmSlot t = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.IADD, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a + (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISUB, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a - (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IMUL, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a * (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IDIV, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_idiv(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IREM, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_irem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.INEG, "{ int32_t a = as_i32(--sp); push_i32((int32_t)(0u - (uint32_t)a)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISHL, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a << (b & 31))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISHR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a >> (b & 31)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IUSHR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a >> (b & 31))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IAND, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a & b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IOR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a | b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IXOR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a ^ b); break; }");

        emitVmCase(sb, isa, VmIsa.Op.LADD, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a + (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSUB, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a - (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LMUL, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a * (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LDIV, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_ldiv(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LREM, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_lrem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LNEG, "{ int64_t a = as_i64(--sp); push_i64((int64_t)(0ULL - (uint64_t)a)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSHL, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a << (b & 63))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSHR, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64(a >> (b & 63)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LUSHR, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a >> (b & 63))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LAND, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a & b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LOR, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a | b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LXOR, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a ^ b); break; }");

        emitVmCase(sb, isa, VmIsa.Op.FADD, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a + b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FSUB, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a - b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FMUL, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a * b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FDIV, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a / b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FREM, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(j_frem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FNEG, "{ float a = as_f32(--sp); push_f32(-a); break; }");

        emitVmCase(sb, isa, VmIsa.Op.DADD, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a + b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DSUB, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a - b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DMUL, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a * b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DDIV, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a / b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DREM, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(j_drem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DNEG, "{ double a = as_f64(--sp); push_f64(-a); break; }");

        emitVmCase(sb, isa, VmIsa.Op.I2L, "{ push_i64((int64_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2F, "{ push_f32((float)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2D, "{ push_f64((double)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2I, "{ push_i32((int32_t)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2F, "{ push_f32((float)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2D, "{ push_f64((double)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2I, "{ push_i32(j_f2i(as_f32(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2L, "{ push_i64(j_f2l(as_f32(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2D, "{ push_f64((double)as_f32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2I, "{ push_i32(j_d2i(as_f64(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2L, "{ push_i64(j_d2l(as_f64(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2F, "{ push_f32((float)as_f64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2B, "{ push_i32((int32_t)(int8_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2C, "{ push_i32((int32_t)(uint16_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2S, "{ push_i32((int32_t)(int16_t)as_i32(--sp)); break; }");

        emitVmCase(sb, isa, VmIsa.Op.LCMP, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i32(a > b ? 1 : (a < b ? -1 : 0)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FCMPL, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_i32(j_fcmpl(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FCMPG, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_i32(j_fcmpg(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DCMPL, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_i32(j_dcmpl(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DCMPG, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_i32(j_dcmpg(a, b)); break; }");

        emitVmCase(sb, isa, VmIsa.Op.JMP, "pc = (uint32_t)rd_i32(dec, pc); break;");
        emitVmCase(sb, isa, VmIsa.Op.IF_ZERO, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) == 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) != 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_LTZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) < 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_GEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) >= 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_GTZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) > 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_LEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) <= 0) pc = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPEQ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a == b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPNE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a != b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPLT, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a < b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPGE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a >= b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPGT, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a > b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPLE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a <= b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ACMPEQ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool eq = env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (eq) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ACMPNE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool ne = !env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (ne) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NULL, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool z = (refs.raw(stk[sp-1].r) == nullptr); clear_stk_slot(--sp); if (z) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NONNULL, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool nz = (refs.raw(stk[sp-1].r) != nullptr); clear_stk_slot(--sp); if (nz) pc = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.SWITCH_TABLE, """
            { int32_t key = as_i32(--sp); int32_t mn = rd_i32(dec, pc); int32_t mx = rd_i32(dec, pc); uint32_t dflt = (uint32_t)rd_i32(dec, pc);
              int32_t cnt = mx - mn + 1;
              if (key >= mn && key <= mx) { pc = (uint32_t)rd_i32(dec, pc + (uint32_t)(key - mn) * 4u); } else { pc = dflt; }
              (void)cnt; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.SWITCH_LOOKUP, """
            { int32_t key = as_i32(--sp); int32_t cnt = rd_i32(dec, pc); uint32_t dflt = (uint32_t)rd_i32(dec, pc);
              uint32_t target = dflt;
              for (int32_t i = 0; i < cnt; i++) {
                  int32_t k = rd_i32(dec, pc); uint32_t dst = (uint32_t)rd_i32(dec, pc);
                  if (k == key) { target = dst; break; }
              }
              pc = target; break; }""");

        emitVmCase(sb, isa, VmIsa.Op.GETSTATIC, """
            { const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32(dec, pc)];
              jfieldID fid = resolve_sfield(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jclass cls = resolve_class(env, (int32_t)0); (void)cls;
              // Resolve class via field meta indirectly via resolve_sfield owner? Let's pass cls_id in runtime helper!
              break; }""");
        // Wait: Notice `resolve_sfield` in runtime already knows `g_field_meta[fm.member_id].cls_id`!
        // Let's add tiny helper `get_field_cls(env, fm.member_id)` in `hydro_vm.cpp` or expose `vm_get_static` / `vm_put_static` / `vm_invoke` in `hydro_runtime.hpp`!
        // Wait: exposing `resolve_field_owner(JNIEnv* env, int32_t fid_id)` and `resolve_method_owner(JNIEnv* env, int32_t mid_id)` in `hydro_runtime.hpp` is 4 lines and 100% clean!
        // Let's finish all VM cases cleanly and add `resolve_field_owner` + `resolve_method_owner`!

        sb.setLength(0); // Rewrite cleanly with `resolve_field_owner` & `resolve_method_owner`!
        return null;
    }

    public static String emitVmCppWithHelpers(
            List<VmCompiler.CompiledVmMethod> vmMethods,
            VmIsa isa,
            CryptoEngine crypto) {

        List<Byte> allCode = new ArrayList<>();
        List<VmCompiler.VmTryCatch> allTries = new ArrayList<>();
        List<int[]> allCalls = new ArrayList<>();
        List<Integer> allCallArgKinds = new ArrayList<>();
        List<int[]> allFields = new ArrayList<>();
        List<int[]> allConcats = new ArrayList<>();
        List<Integer> allConcatConsts = new ArrayList<>();
        List<Integer> allConcatArgKinds = new ArrayList<>();
        List<int[]> methodMetas = new ArrayList<>();

        for (VmCompiler.CompiledVmMethod vm : vmMethods) {
            int cOff = allCode.size();
            for (byte b : vm.encryptedCode) allCode.add(b);
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
            methodMetas.add(new int[]{cOff, vm.encryptedCode.length, vm.maxStack, vm.maxLocals, tOff, vm.tryCatches.size(), callOff, fldOff, cncOff});
        }

        StringBuilder sb = new StringBuilder(65536);
        sb.append("#include \"hydro_runtime.hpp\"\n\n");
        sb.append("namespace hy {\n\n");
        sb.append("jclass resolve_field_owner(JNIEnv* env, int32_t fid_id);\n");
        sb.append("jclass resolve_method_owner(JNIEnv* env, int32_t mid_id);\n\n");

        sb.append("struct VmTryEntry { uint32_t start_pc; uint32_t end_pc; uint32_t handler_pc; int32_t catch_cls; };\n");
        sb.append("struct VmCallMeta { int32_t member_id; uint8_t ret_kind; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmFieldMeta { int32_t member_id; uint8_t field_kind; };\n");
        sb.append("struct VmConcatMeta { int32_t recipe_wid; uint16_t const_off; uint8_t const_cnt; uint16_t arg_off; uint8_t arg_cnt; };\n");
        sb.append("struct VmMethodMeta {\n");
        sb.append("    uint32_t code_off; uint32_t code_len;\n");
        sb.append("    uint16_t max_stack; uint16_t max_locals;\n");
        sb.append("    uint32_t try_off; uint32_t try_cnt;\n");
        sb.append("    uint32_t call_off; uint32_t field_off; uint32_t concat_off;\n");
        sb.append("};\n\n");

        emitByteArr(sb, "g_vm_code", allCode);
        emitIntArr(sb, "g_vm_call_ak", allCallArgKinds);
        emitIntArr(sb, "g_vm_cnc_consts", allConcatConsts);
        emitIntArr(sb, "g_vm_cnc_ak", allConcatArgKinds);

        sb.append("static const VmTryEntry g_vm_tries[] = {\n");
        for (VmCompiler.VmTryCatch t : allTries) {
            sb.append("    {").append(t.startPc()).append("u, ").append(t.endPc()).append("u, ").append(t.handlerPc()).append("u, ").append(t.catchClsId()).append("},\n");
        }
        if (allTries.isEmpty()) sb.append("    {0u, 0u, 0u, -1}\n");
        sb.append("};\n");

        sb.append("static const VmCallMeta g_vm_calls[] = {\n");
        for (int[] c : allCalls) sb.append("    {").append(c[0]).append(", ").append(c[1]).append(", ").append(c[2]).append(", ").append(c[3]).append("},\n");
        if (allCalls.isEmpty()) sb.append("    {0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmFieldMeta g_vm_fields[] = {\n");
        for (int[] f : allFields) sb.append("    {").append(f[0]).append(", ").append(f[1]).append("},\n");
        if (allFields.isEmpty()) sb.append("    {0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmConcatMeta g_vm_concats[] = {\n");
        for (int[] cc : allConcats) sb.append("    {").append(cc[0]).append(", ").append(cc[1]).append(", ").append(cc[2]).append(", ").append(cc[3]).append(", ").append(cc[4]).append("},\n");
        if (allConcats.isEmpty()) sb.append("    {0, 0, 0, 0, 0}\n");
        sb.append("};\n");

        sb.append("static const VmMethodMeta g_vm_methods[] = {\n");
        for (int[] m : methodMetas) {
            sb.append("    {").append(m[0]).append("u, ").append(m[1]).append("u, ").append(m[2]).append("u, ").append(m[3])
              .append("u, ").append(m[4]).append("u, ").append(m[5]).append("u, ").append(m[6]).append("u, ").append(m[7]).append("u, ").append(m[8]).append("u},\n");
        }
        if (methodMetas.isEmpty()) sb.append("    {0u, 0u, 4u, 4u, 0u, 0u, 0u, 0u, 0u}\n");
        sb.append("};\n\n");

        sb.append("""
struct VmSlot {
    uint64_t u;
    int32_t r;
    uint8_t cat;
    uint8_t is_ref;
};

static inline uint64_t vm_sm64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static inline int32_t rd_i32(const uint8_t* p, uint32_t& pc) {
    int32_t v = 0; __builtin_memcpy(&v, p + pc, 4); pc += 4; return v;
}
static inline uint16_t rd_u16(const uint8_t* p, uint32_t& pc) {
    uint16_t v = 0; __builtin_memcpy(&v, p + pc, 2); pc += 2; return v;
}
static inline int64_t rd_i64(const uint8_t* p, uint32_t& pc) {
    int64_t v = 0; __builtin_memcpy(&v, p + pc, 8); pc += 8; return v;
}
""");

        sb.append("static uint64_t vm_exec_core(JNIEnv* env, uint32_t vm_method_id, const uint64_t* init_vals, const uint8_t* init_is_ref, int32_t init_slots, jobject* out_ref) {\n");
        sb.append("    const VmMethodMeta& mm = g_vm_methods[vm_method_id];\n");
        sb.append("    RefTable refs(env);\n");
        sb.append("    if (out_ref) *out_ref = nullptr;\n");
        sb.append("    uint8_t stack_code[1024];\n");
        sb.append("    uint8_t* dec = mm.code_len <= 1024 ? stack_code : (uint8_t*)heap_alloc(mm.code_len);\n");
        sb.append("    uint64_t st = vm_sm64(").append(CryptoEngine.hex64(isa.keySeed)).append("ULL ^ ((uint64_t)vm_method_id * 0x9E3779B97F4A7C15ULL));\n");
        sb.append("    for (uint32_t i = 0; i < mm.code_len; i++) {\n");
        sb.append("        st = vm_sm64(st + (uint64_t)i * 0xBF58476D1CE4E5B9ULL);\n");
        sb.append("        dec[i] = g_vm_code[mm.code_off + i] ^ (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);\n");
        sb.append("    }\n");
        sb.append("    VmSlot stack_mem[64]; VmSlot local_mem[64];\n");
        sb.append("    VmSlot* stk = mm.max_stack <= 64 ? stack_mem : (VmSlot*)heap_alloc(mm.max_stack * sizeof(VmSlot));\n");
        sb.append("    VmSlot* loc = mm.max_locals <= 64 ? local_mem : (VmSlot*)heap_alloc(mm.max_locals * sizeof(VmSlot));\n");
        sb.append("    for (int32_t i = 0; i < mm.max_stack; i++) { stk[i] = {0ULL, -1, 1, 0}; }\n");
        sb.append("    for (int32_t i = 0; i < mm.max_locals; i++) { loc[i] = {0ULL, -1, 1, 0}; }\n");
        sb.append("    for (int32_t i = 0; i < init_slots; i++) {\n");
        sb.append("        if (init_is_ref[i]) { loc[i].is_ref = 1; loc[i].r = refs.track((jobject)(uintptr_t)init_vals[i], false); }\n");
        sb.append("        else { loc[i].u = init_vals[i]; }\n");
        sb.append("    }\n");

        sb.append("""
    int32_t sp = 0;
    uint32_t pc = 0;
    uint32_t cur_insn_pc = 0;

    auto cleanup = [&]() {
        if (dec != stack_code) heap_free(dec);
        if (stk != stack_mem) heap_free(stk);
        if (loc != local_mem) heap_free(loc);
    };

    auto clear_stk_slot = [&](int32_t idx) {
        if (stk[idx].is_ref && stk[idx].r >= 0) refs.release(stk[idx].r);
        stk[idx] = {0ULL, -1, 1, 0};
    };

    auto push_i32 = [&](int32_t v) { stk[sp++] = {(uint64_t)(uint32_t)v, -1, 1, 0}; };
    auto push_i64 = [&](int64_t v) { stk[sp++] = {(uint64_t)v, -1, 2, 0}; };
    auto push_f32 = [&](float v) { uint32_t b = 0; __builtin_memcpy(&b, &v, 4); stk[sp++] = {(uint64_t)b, -1, 1, 0}; };
    auto push_f64 = [&](double v) { uint64_t b = 0; __builtin_memcpy(&b, &v, 8); stk[sp++] = {b, -1, 2, 0}; };
    auto push_ref = [&](jobject o, bool owned) { stk[sp++] = {0ULL, refs.track(o, owned), 1, 1}; };
    auto as_i32 = [&](int32_t idx) -> int32_t { return (int32_t)(uint32_t)stk[idx].u; };
    auto as_i64 = [&](int32_t idx) -> int64_t { return (int64_t)stk[idx].u; };
    auto as_f32 = [&](int32_t idx) -> float { return bits_to_f32((uint32_t)stk[idx].u); };
    auto as_f64 = [&](int32_t idx) -> double { return bits_to_f64(stk[idx].u); };

    auto handle_exception = [&]() -> bool {
        if (!env->ExceptionCheck()) return false;
        jthrowable ex = env->ExceptionOccurred();
        env->ExceptionClear();
        for (uint32_t t = 0; t < mm.try_cnt; t++) {
            const VmTryEntry& te = g_vm_tries[mm.try_off + t];
            if (cur_insn_pc >= te.start_pc && cur_insn_pc < te.end_pc) {
                bool match = (te.catch_cls < 0);
                if (!match) {
                    jclass hc = resolve_class(env, te.catch_cls);
                    if (env->ExceptionCheck()) env->ExceptionClear();
                    if (hc && env->IsInstanceOf(ex, hc)) match = true;
                }
                if (match) {
                    for (int32_t s = 0; s < sp; s++) clear_stk_slot(s);
                    sp = 0;
                    push_ref(ex, true);
                    pc = te.handler_pc;
                    return true;
                }
            }
        }
        env->Throw(ex);
        env->DeleteLocalRef(ex);
        return false;
    };
""");

        sb.append("    while (pc < mm.code_len) {\n");
        sb.append("        cur_insn_pc = pc;\n");
        sb.append("        uint8_t op = dec[pc++];\n");
        sb.append("        switch (op) {\n");

        emitVmCase(sb, isa, VmIsa.Op.NOP, "break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_I32, "push_i32(rd_i32(dec, pc)); break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_I64, "push_i64(rd_i64(dec, pc)); break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_F32, "stk[sp++] = {(uint64_t)(uint32_t)rd_i32(dec, pc), -1, 1, 0}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_F64, "stk[sp++] = {(uint64_t)rd_i64(dec, pc), -1, 2, 0}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_NULL, "stk[sp++] = {0ULL, -1, 1, 1}; break;");
        emitVmCase(sb, isa, VmIsa.Op.CONST_STR, """
            { int32_t wid = rd_i32(dec, pc); jstring js = new_wstr(env, wid);
              if (env->ExceptionCheck()) { if (js) env->DeleteLocalRef(js); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(js, true); break; }""");
        emitVmCase(sb, isa, VmIsa.Op.CONST_CLS, """
            { int32_t cid = rd_i32(dec, pc); jclass c = resolve_class(env, cid);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(c, false); break; }""");
        emitVmCase(sb, isa, VmIsa.Op.CONST_PRIM_CLS, """
            { int32_t k = rd_i32(dec, pc); jclass c = resolve_prim_class(env, k);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(c, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.LOAD_P, """
            { uint16_t slot = rd_u16(dec, pc); uint8_t cat = dec[pc++];
              stk[sp++] = {loc[slot].u, -1, cat, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.STORE_P, """
            { uint16_t slot = rd_u16(dec, pc); uint8_t cat = dec[pc++];
              if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
              loc[slot] = {stk[--sp].u, -1, cat, 0}; stk[sp] = {0ULL, -1, 1, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.LOAD_R, """
            { uint16_t slot = rd_u16(dec, pc);
              stk[sp++] = {0ULL, refs.retain(loc[slot].r), 1, 1}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.STORE_R, """
            { uint16_t slot = rd_u16(dec, pc);
              int32_t nr = stk[--sp].r;
              if (!loc[slot].is_ref || loc[slot].r != nr) {
                  if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
                  loc[slot] = {0ULL, nr, 1, 1};
              } else { refs.release(nr); }
              stk[sp] = {0ULL, -1, 1, 0}; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.IINC, """
            { uint16_t slot = rd_u16(dec, pc); int32_t d = rd_i32(dec, pc);
              loc[slot].u = (uint64_t)(uint32_t)((int32_t)(uint32_t)loc[slot].u + d); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.POP1, "clear_stk_slot(--sp); break;");
        emitVmCase(sb, isa, VmIsa.Op.POP2, "if (stk[sp - 1].cat == 2) { clear_stk_slot(--sp); } else { clear_stk_slot(--sp); clear_stk_slot(--sp); } break;");
        emitVmCase(sb, isa, VmIsa.Op.DUP1, "{ VmSlot v = stk[sp - 1]; if (v.is_ref) v.r = refs.retain(v.r); stk[sp++] = v; break; }");
        emitVmCase(sb, isa, VmIsa.Op.DUP_X1, """
            { VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2]; VmSlot v1c = v1; if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
              stk[sp] = v1; stk[sp - 1] = v2; stk[sp - 2] = v1c; sp++; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP_X2, """
            { VmSlot v1 = stk[sp - 1]; VmSlot v1c = v1; if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
              if (stk[sp - 2].cat == 2) { stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = v1c; }
              else { stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = v1c; }
              sp++; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2, """
            { if (stk[sp - 1].cat == 2) { stk[sp] = stk[sp - 1]; sp++; }
              else { VmSlot a = stk[sp - 2], b = stk[sp - 1];
                     if (a.is_ref) a.r = refs.retain(a.r); if (b.is_ref) b.r = refs.retain(b.r);
                     stk[sp] = a; stk[sp + 1] = b; sp += 2; } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2_X1, """
            { if (stk[sp - 1].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
              } else {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c; sp += 2;
              } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.DUP2_X2, """
            { if (stk[sp - 1].cat == 2 && stk[sp - 2].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
              } else if (stk[sp - 1].cat == 2) {
                  stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = stk[sp]; sp++;
              } else if (stk[sp - 3].cat == 2) {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c; sp += 2;
              } else {
                  VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3], v4 = stk[sp - 4];
                  VmSlot v1c = v1, v2c = v2;
                  if (v1c.is_ref) v1c.r = refs.retain(v1c.r); if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                  stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v4; stk[sp - 3] = v1c; stk[sp - 4] = v2c; sp += 2;
              } break; }""");
        emitVmCase(sb, isa, VmIsa.Op.SWAP, "{ VmSlot t = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.IADD, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a + (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISUB, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a - (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IMUL, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a * (uint32_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IDIV, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_idiv(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IREM, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_irem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.INEG, "{ int32_t a = as_i32(--sp); push_i32((int32_t)(0u - (uint32_t)a)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISHL, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a << (b & 31))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.ISHR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a >> (b & 31)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IUSHR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32((int32_t)((uint32_t)a >> (b & 31))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IAND, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a & b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IOR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a | b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.IXOR, "{ int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); push_i32(a ^ b); break; }");

        emitVmCase(sb, isa, VmIsa.Op.LADD, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a + (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSUB, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a - (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LMUL, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a * (uint64_t)b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LDIV, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_ldiv(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LREM, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_lrem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LNEG, "{ int64_t a = as_i64(--sp); push_i64((int64_t)(0ULL - (uint64_t)a)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSHL, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a << (b & 63))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LSHR, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64(a >> (b & 63)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LUSHR, "{ int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a >> (b & 63))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LAND, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a & b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LOR, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a | b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.LXOR, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i64(a ^ b); break; }");

        emitVmCase(sb, isa, VmIsa.Op.FADD, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a + b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FSUB, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a - b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FMUL, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a * b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FDIV, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(a / b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FREM, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_f32(j_frem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FNEG, "{ float a = as_f32(--sp); push_f32(-a); break; }");

        emitVmCase(sb, isa, VmIsa.Op.DADD, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a + b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DSUB, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a - b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DMUL, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a * b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DDIV, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(a / b); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DREM, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_f64(j_drem(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DNEG, "{ double a = as_f64(--sp); push_f64(-a); break; }");

        emitVmCase(sb, isa, VmIsa.Op.I2L, "{ push_i64((int64_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2F, "{ push_f32((float)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2D, "{ push_f64((double)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2I, "{ push_i32((int32_t)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2F, "{ push_f32((float)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.L2D, "{ push_f64((double)as_i64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2I, "{ push_i32(j_f2i(as_f32(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2L, "{ push_i64(j_f2l(as_f32(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.F2D, "{ push_f64((double)as_f32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2I, "{ push_i32(j_d2i(as_f64(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2L, "{ push_i64(j_d2l(as_f64(--sp))); break; }");
        emitVmCase(sb, isa, VmIsa.Op.D2F, "{ push_f32((float)as_f64(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2B, "{ push_i32((int32_t)(int8_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2C, "{ push_i32((int32_t)(uint16_t)as_i32(--sp)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.I2S, "{ push_i32((int32_t)(int16_t)as_i32(--sp)); break; }");

        emitVmCase(sb, isa, VmIsa.Op.LCMP, "{ int64_t b = as_i64(--sp); int64_t a = as_i64(--sp); push_i32(a > b ? 1 : (a < b ? -1 : 0)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FCMPL, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_i32(j_fcmpl(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.FCMPG, "{ float b = as_f32(--sp); float a = as_f32(--sp); push_i32(j_fcmpg(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DCMPL, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_i32(j_dcmpl(a, b)); break; }");
        emitVmCase(sb, isa, VmIsa.Op.DCMPG, "{ double b = as_f64(--sp); double a = as_f64(--sp); push_i32(j_dcmpg(a, b)); break; }");

        emitVmCase(sb, isa, VmIsa.Op.JMP, "pc = (uint32_t)rd_i32(dec, pc); break;");
        emitVmCase(sb, isa, VmIsa.Op.IF_ZERO, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) == 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) != 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_LTZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) < 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_GEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) >= 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_GTZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) > 0) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_LEZ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); if (as_i32(--sp) <= 0) pc = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPEQ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a == b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPNE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a != b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPLT, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a < b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPGE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a >= b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPGT, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a > b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ICMPLE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); int32_t b = as_i32(--sp); int32_t a = as_i32(--sp); if (a <= b) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ACMPEQ, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool eq = env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (eq) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_ACMPNE, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool ne = !env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (ne) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NULL, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool z = (refs.raw(stk[sp-1].r) == nullptr); clear_stk_slot(--sp); if (z) pc = t; break; }");
        emitVmCase(sb, isa, VmIsa.Op.IF_NONNULL, "{ uint32_t t = (uint32_t)rd_i32(dec, pc); bool nz = (refs.raw(stk[sp-1].r) != nullptr); clear_stk_slot(--sp); if (nz) pc = t; break; }");

        emitVmCase(sb, isa, VmIsa.Op.SWITCH_TABLE, """
            { int32_t key = as_i32(--sp); int32_t mn = rd_i32(dec, pc); int32_t mx = rd_i32(dec, pc); uint32_t dflt = (uint32_t)rd_i32(dec, pc);
              if (key >= mn && key <= mx) { uint32_t toff = pc + (uint32_t)(key - mn) * 4u; pc = (uint32_t)rd_i32(dec, toff); } else pc = dflt; break; }""");
        emitVmCase(sb, isa, VmIsa.Op.SWITCH_LOOKUP, """
            { int32_t key = as_i32(--sp); int32_t cnt = rd_i32(dec, pc); uint32_t dflt = (uint32_t)rd_i32(dec, pc);
              uint32_t target = dflt;
              for (int32_t i = 0; i < cnt; i++) {
                  int32_t k = rd_i32(dec, pc); uint32_t dst = (uint32_t)rd_i32(dec, pc);
                  if (k == key && target == dflt) target = dst;
              }
              pc = target; break; }""");

        emitVmCase(sb, isa, VmIsa.Op.GETSTATIC, """
            { const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32(dec, pc)];
              jclass cls = resolve_field_owner(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jfieldID fid = resolve_sfield(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              switch (fm.field_kind) {
                  case 1: push_i32(env->GetStaticBooleanField(cls, fid) ? 1 : 0); break;
                  case 2: push_i32((int32_t)(int8_t)env->GetStaticByteField(cls, fid)); break;
                  case 3: push_i32((int32_t)(uint16_t)env->GetStaticCharField(cls, fid)); break;
                  case 4: push_i32((int32_t)(int16_t)env->GetStaticShortField(cls, fid)); break;
                  case 5: push_i32((int32_t)env->GetStaticIntField(cls, fid)); break;
                  case 6: push_i64((int64_t)env->GetStaticLongField(cls, fid)); break;
                  case 7: push_f32((float)env->GetStaticFloatField(cls, fid)); break;
                  case 8: push_f64((double)env->GetStaticDoubleField(cls, fid)); break;
                  default: push_ref(env->GetStaticObjectField(cls, fid), true); break;
              }
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.PUTSTATIC, """
            { const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32(dec, pc)];
              jclass cls = resolve_field_owner(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jfieldID fid = resolve_sfield(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              sp--;
              switch (fm.field_kind) {
                  case 1: env->SetStaticBooleanField(cls, fid, (stk[sp].u & 1) ? JNI_TRUE : JNI_FALSE); break;
                  case 2: env->SetStaticByteField(cls, fid, (jbyte)stk[sp].u); break;
                  case 3: env->SetStaticCharField(cls, fid, (jchar)stk[sp].u); break;
                  case 4: env->SetStaticShortField(cls, fid, (jshort)stk[sp].u); break;
                  case 5: env->SetStaticIntField(cls, fid, (jint)stk[sp].u); break;
                  case 6: env->SetStaticLongField(cls, fid, (jlong)stk[sp].u); break;
                  case 7: env->SetStaticFloatField(cls, fid, as_f32(sp)); break;
                  case 8: env->SetStaticDoubleField(cls, fid, as_f64(sp)); break;
                  default: env->SetStaticObjectField(cls, fid, refs.raw(stk[sp].r)); clear_stk_slot(sp); break;
              }
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.GETFIELD, """
            { const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32(dec, pc)];
              jobject obj = refs.raw(stk[sp - 1].r);
              if (!obj) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              jfieldID fid = resolve_ifield(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              uint64_t fval = 0; jobject fobj = nullptr; uint8_t fcat = 1; bool is_o = false;
              switch (fm.field_kind) {
                  case 1: fval = env->GetBooleanField(obj, fid) ? 1 : 0; break;
                  case 2: fval = (uint64_t)(uint32_t)(int32_t)(int8_t)env->GetByteField(obj, fid); break;
                  case 3: fval = (uint64_t)(uint32_t)(uint16_t)env->GetCharField(obj, fid); break;
                  case 4: fval = (uint64_t)(uint32_t)(int32_t)(int16_t)env->GetShortField(obj, fid); break;
                  case 5: fval = (uint64_t)(uint32_t)env->GetIntField(obj, fid); break;
                  case 6: fval = (uint64_t)env->GetLongField(obj, fid); fcat = 2; break;
                  case 7: { float rv = env->GetFloatField(obj, fid); __builtin_memcpy(&fval, &rv, 4); break; }
                  case 8: { double rv = env->GetDoubleField(obj, fid); __builtin_memcpy(&fval, &rv, 8); fcat = 2; break; }
                  default: fobj = env->GetObjectField(obj, fid); is_o = true; break;
              }
              clear_stk_slot(--sp);
              if (is_o) push_ref(fobj, true);
              else stk[sp++] = {fval, -1, fcat, 0};
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.PUTFIELD, """
            { const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32(dec, pc)];
              jobject obj = refs.raw(stk[sp - 2].r);
              if (!obj) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              jfieldID fid = resolve_ifield(env, fm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              int32_t vs = --sp; int32_t os = --sp;
              switch (fm.field_kind) {
                  case 1: env->SetBooleanField(obj, fid, (stk[vs].u & 1) ? JNI_TRUE : JNI_FALSE); break;
                  case 2: env->SetByteField(obj, fid, (jbyte)stk[vs].u); break;
                  case 3: env->SetCharField(obj, fid, (jchar)stk[vs].u); break;
                  case 4: env->SetShortField(obj, fid, (jshort)stk[vs].u); break;
                  case 5: env->SetIntField(obj, fid, (jint)stk[vs].u); break;
                  case 6: env->SetLongField(obj, fid, (jlong)stk[vs].u); break;
                  case 7: env->SetFloatField(obj, fid, as_f32(vs)); break;
                  case 8: env->SetDoubleField(obj, fid, as_f64(vs)); break;
                  default: env->SetObjectField(obj, fid, refs.raw(stk[vs].r)); clear_stk_slot(vs); break;
              }
              clear_stk_slot(os); break; }""");

        String invokeBodyTemplate = """
            { const VmCallMeta& cm = g_vm_calls[mm.call_off + (uint32_t)rd_i32(dec, pc)];
              int32_t base = sp - cm.arg_cnt - (%IS_STATIC% ? 0 : 1);
              jobject recv = %IS_STATIC% ? nullptr : refs.raw(stk[base].r);
              if (!%IS_STATIC% && !recv) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              jmethodID mid = %IS_STATIC% ? resolve_smethod(env, cm.member_id) : resolve_imethod(env, cm.member_id);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jclass cls = (%IS_STATIC% || %IS_SPECIAL%) ? resolve_method_owner(env, cm.member_id) : nullptr;
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jvalue jargs[32];
              for (uint8_t k = 0; k < cm.arg_cnt; k++) {
                  int32_t s = base + (%IS_STATIC% ? 0 : 1) + k;
                  switch (g_vm_call_ak[cm.arg_off + k]) {
                      case 1: jargs[k].z = (stk[s].u & 1) ? JNI_TRUE : JNI_FALSE; break;
                      case 2: jargs[k].b = (jbyte)stk[s].u; break;
                      case 3: jargs[k].c = (jchar)stk[s].u; break;
                      case 4: jargs[k].s = (jshort)stk[s].u; break;
                      case 5: jargs[k].i = (jint)stk[s].u; break;
                      case 6: jargs[k].j = (jlong)stk[s].u; break;
                      case 7: jargs[k].f = as_f32(s); break;
                      case 8: jargs[k].d = as_f64(s); break;
                      default: jargs[k].l = refs.raw(stk[s].r); break;
                  }
              }
              const jvalue* ap = cm.arg_cnt > 0 ? jargs : nullptr;
              uint64_t rbits = 0; jobject robj = nullptr;
              switch (cm.ret_kind) {
                  case 0: %CALL_V%; break;
                  case 1: rbits = (%CALL_Z%) ? 1ULL : 0ULL; break;
                  case 2: rbits = (uint64_t)(uint32_t)(int32_t)(int8_t)(%CALL_B%); break;
                  case 3: rbits = (uint64_t)(uint32_t)(uint16_t)(%CALL_C%); break;
                  case 4: rbits = (uint64_t)(uint32_t)(int32_t)(int16_t)(%CALL_S%); break;
                  case 5: rbits = (uint64_t)(uint32_t)(int32_t)(%CALL_I%); break;
                  case 6: rbits = (uint64_t)(int64_t)(%CALL_J%); break;
                  case 7: { float rv = %CALL_F%; __builtin_memcpy(&rbits, &rv, 4); break; }
                  case 8: { double rv = %CALL_D%; __builtin_memcpy(&rbits, &rv, 8); break; }
                  default: robj = %CALL_L%; break;
              }
              if (env->ExceptionCheck()) { if (robj) env->DeleteLocalRef(robj); if (!handle_exception()) { cleanup(); return 0; } break; }
              while (sp > base) clear_stk_slot(--sp);
              if (cm.ret_kind == 9) push_ref(robj, true);
              else if (cm.ret_kind != 0) stk[sp++] = {rbits, -1, (uint8_t)((cm.ret_kind == 6 || cm.ret_kind == 8) ? 2 : 1), 0};
              break; }""";

        emitVmCase(sb, isa, VmIsa.Op.INVOKE_STATIC, formatInvoke(invokeBodyTemplate, true, false));
        emitVmCase(sb, isa, VmIsa.Op.INVOKE_VIRTUAL, formatInvoke(invokeBodyTemplate, false, false));
        emitVmCase(sb, isa, VmIsa.Op.INVOKE_INTERFACE, formatInvoke(invokeBodyTemplate, false, false));
        emitVmCase(sb, isa, VmIsa.Op.INVOKE_SPECIAL, formatInvoke(invokeBodyTemplate, false, true));

        emitVmCase(sb, isa, VmIsa.Op.STRING_CONCAT, """
            { const VmConcatMeta& cc = g_vm_concats[mm.concat_off + (uint32_t)rd_i32(dec, pc)];
              int32_t base = sp - cc.arg_cnt;
              ConcatArg cargs[32];
              for (uint8_t k = 0; k < cc.arg_cnt; k++) {
                  int32_t s = base + k;
                  int32_t ak = g_vm_cnc_ak[cc.arg_off + k];
                  cargs[k].kind = ak;
                  if (ak == 6) cargs[k].j = as_i64(s);
                  else if (ak == 7) cargs[k].f = as_f32(s);
                  else if (ak == 8) cargs[k].d = as_f64(s);
                  else if (ak == 9) cargs[k].obj = refs.raw(stk[s].r);
                  else cargs[k].i = as_i32(s);
              }
              const int32_t* cptr = cc.const_cnt > 0 ? &g_vm_cnc_consts[cc.const_off] : nullptr;
              jstring js = string_concat(env, cc.recipe_wid, cptr, cc.const_cnt, cargs, cc.arg_cnt);
              if (env->ExceptionCheck()) { if (js) env->DeleteLocalRef(js); if (!handle_exception()) { cleanup(); return 0; } break; }
              while (sp > base) clear_stk_slot(--sp);
              push_ref(js, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.NEW_ALLOC, """
            { jclass c = resolve_class(env, rd_i32(dec, pc));
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jobject o = env->AllocObject(c);
              if (env->ExceptionCheck()) { if (o) env->DeleteLocalRef(o); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(o, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.NEWARRAY, """
            { uint8_t at = dec[pc++]; int32_t len = as_i32(--sp);
              if (len < 0) { throw_neg_arr(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              jarray a = nullptr;
              switch (at) {
                  case 4: a = env->NewBooleanArray(len); break;
                  case 5: a = env->NewCharArray(len); break;
                  case 6: a = env->NewFloatArray(len); break;
                  case 7: a = env->NewDoubleArray(len); break;
                  case 8: a = env->NewByteArray(len); break;
                  case 9: a = env->NewShortArray(len); break;
                  case 10: a = env->NewIntArray(len); break;
                  default: a = env->NewLongArray(len); break;
              }
              if (env->ExceptionCheck()) { if (a) env->DeleteLocalRef(a); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(a, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.ANEWARRAY, """
            { int32_t cid = rd_i32(dec, pc); int32_t len = as_i32(--sp);
              if (len < 0) { throw_neg_arr(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              jclass ec = resolve_class(env, cid);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              jobjectArray a = env->NewObjectArray(len, ec, nullptr);
              if (env->ExceptionCheck()) { if (a) env->DeleteLocalRef(a); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(a, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.MULTIANEWARRAY, """
            { uint8_t dims = dec[pc++];
              int32_t dvals[16]; int32_t cids[16];
              for (int32_t d = 0; d < dims; d++) cids[d] = rd_i32(dec, pc);
              uint8_t elem_kind = dec[pc++];
              for (int32_t d = dims - 1; d >= 0; d--) dvals[d] = as_i32(--sp);
              jobject marr = new_multi_array(env, cids, dvals, (int32_t)dims, (int32_t)elem_kind);
              if (env->ExceptionCheck()) { if (marr) env->DeleteLocalRef(marr); if (!handle_exception()) { cleanup(); return 0; } break; }
              push_ref(marr, true); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.ARRAYLENGTH, """
            { jarray a = (jarray)refs.raw(stk[sp - 1].r);
              if (!a) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              int32_t len = (int32_t)env->GetArrayLength(a);
              clear_stk_slot(--sp); push_i32(len); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.ARR_LOAD, """
            { uint8_t k = dec[pc++]; int32_t idx = as_i32(--sp);
              jarray a = (jarray)refs.raw(stk[sp - 1].r);
              if (!a) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              if (k == 9) {
                  jobject el = env->GetObjectArrayElement((jobjectArray)a, idx);
                  if (env->ExceptionCheck()) { if (el) env->DeleteLocalRef(el); if (!handle_exception()) { cleanup(); return 0; } break; }
                  clear_stk_slot(--sp); push_ref(el, true);
              } else {
                  uint64_t val = 0; uint8_t cat = 1;
                  switch (k) {
                      case 1: { jboolean v = 0; env->GetBooleanArrayRegion((jbooleanArray)a, idx, 1, &v); val = v ? 1 : 0; break; }
                      case 2: { jbyte v = 0; env->GetByteArrayRegion((jbyteArray)a, idx, 1, &v); val = (uint64_t)(uint32_t)(int32_t)(int8_t)v; break; }
                      case 10: { val = (uint64_t)(uint32_t)baload_dyn(env, a, idx); break; }
                      case 3: { jchar v = 0; env->GetCharArrayRegion((jcharArray)a, idx, 1, &v); val = (uint64_t)(uint32_t)(uint16_t)v; break; }
                      case 4: { jshort v = 0; env->GetShortArrayRegion((jshortArray)a, idx, 1, &v); val = (uint64_t)(uint32_t)(int32_t)(int16_t)v; break; }
                      case 5: { jint v = 0; env->GetIntArrayRegion((jintArray)a, idx, 1, &v); val = (uint64_t)(uint32_t)v; break; }
                      case 6: { jlong v = 0; env->GetLongArrayRegion((jlongArray)a, idx, 1, &v); val = (uint64_t)v; cat = 2; break; }
                      case 7: { jfloat v = 0; env->GetFloatArrayRegion((jfloatArray)a, idx, 1, &v); uint32_t b = 0; __builtin_memcpy(&b, &v, 4); val = b; break; }
                      default: { jdouble v = 0; env->GetDoubleArrayRegion((jdoubleArray)a, idx, 1, &v); __builtin_memcpy(&val, &v, 8); cat = 2; break; }
                  }
                  if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                  clear_stk_slot(--sp); stk[sp++] = {val, -1, cat, 0};
              }
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.ARR_STORE, """
            { uint8_t k = dec[pc++];
              int32_t vs = --sp; int32_t idx = as_i32(--sp);
              jarray a = (jarray)refs.raw(stk[sp - 1].r);
              if (!a) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              switch (k) {
                  case 1: { jboolean v = (stk[vs].u & 1) ? JNI_TRUE : JNI_FALSE; env->SetBooleanArrayRegion((jbooleanArray)a, idx, 1, &v); break; }
                  case 2: { jbyte v = (jbyte)stk[vs].u; env->SetByteArrayRegion((jbyteArray)a, idx, 1, &v); break; }
                  case 10: { bastore_dyn(env, a, idx, (int32_t)(uint32_t)stk[vs].u); break; }
                  case 3: { jchar v = (jchar)stk[vs].u; env->SetCharArrayRegion((jcharArray)a, idx, 1, &v); break; }
                  case 4: { jshort v = (jshort)stk[vs].u; env->SetShortArrayRegion((jshortArray)a, idx, 1, &v); break; }
                  case 5: { jint v = (jint)stk[vs].u; env->SetIntArrayRegion((jintArray)a, idx, 1, &v); break; }
                  case 6: { jlong v = (jlong)stk[vs].u; env->SetLongArrayRegion((jlongArray)a, idx, 1, &v); break; }
                  case 7: { jfloat v = as_f32(vs); env->SetFloatArrayRegion((jfloatArray)a, idx, 1, &v); break; }
                  case 8: { jdouble v = as_f64(vs); env->SetDoubleArrayRegion((jdoubleArray)a, idx, 1, &v); break; }
                  default: { env->SetObjectArrayElement((jobjectArray)a, idx, refs.raw(stk[vs].r)); break; }
              }
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
              if (k == 9) clear_stk_slot(vs);
              clear_stk_slot(--sp); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.CHECKCAST, """
            { int32_t cid = rd_i32(dec, pc); jobject o = refs.raw(stk[sp - 1].r);
              if (o != nullptr) {
                  jclass c = resolve_class(env, cid);
                  if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                  if (!env->IsInstanceOf(o, c)) { throw_cce(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              } break; }""");

        emitVmCase(sb, isa, VmIsa.Op.INSTANCEOF, """
            { int32_t cid = rd_i32(dec, pc); jobject o = refs.raw(stk[sp - 1].r);
              int32_t res = 0;
              if (o != nullptr) {
                  jclass c = resolve_class(env, cid);
                  if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                  res = env->IsInstanceOf(o, c) ? 1 : 0;
              }
              clear_stk_slot(--sp); push_i32(res); break; }""");

        emitVmCase(sb, isa, VmIsa.Op.MONITORENTER, """
            { jobject o = refs.raw(stk[sp - 1].r);
              if (!o) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              env->MonitorEnter(o); clear_stk_slot(--sp);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } }
              break; }""");
        emitVmCase(sb, isa, VmIsa.Op.MONITOREXIT, """
            { jobject o = refs.raw(stk[sp - 1].r);
              if (!o) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
              env->MonitorExit(o); clear_stk_slot(--sp);
              if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } }
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.ATHROW, """
            { jthrowable ex = (jthrowable)refs.raw(stk[sp - 1].r);
              if (!ex) throw_npe(env); else env->Throw(ex);
              clear_stk_slot(--sp);
              if (!handle_exception()) { cleanup(); return 0; }
              break; }""");

        emitVmCase(sb, isa, VmIsa.Op.RET_VOID, "cleanup(); return 0;");
        emitVmCase(sb, isa, VmIsa.Op.RET_I32, "{ uint64_t r = (uint64_t)(uint32_t)as_i32(sp - 1); cleanup(); return r; }");
        emitVmCase(sb, isa, VmIsa.Op.RET_I64, "{ uint64_t r = stk[sp - 1].u; cleanup(); return r; }");
        emitVmCase(sb, isa, VmIsa.Op.RET_F32, "{ uint64_t r = (uint64_t)(uint32_t)stk[sp - 1].u; cleanup(); return r; }");
        emitVmCase(sb, isa, VmIsa.Op.RET_F64, "{ uint64_t r = stk[sp - 1].u; cleanup(); return r; }");
        emitVmCase(sb, isa, VmIsa.Op.RET_REF, "{ if (out_ref) *out_ref = refs.detach_return(stk[sp - 1].r); cleanup(); return 0; }");

        sb.append("            default: cleanup(); return 0;\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("    cleanup(); return 0;\n");
        sb.append("}\n\n");
        sb.append("} // namespace hy\n\n");

        // Emit JNI native stubs for every VM-protected method
        for (VmCompiler.CompiledVmMethod vm : vmMethods) {
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
                    case Type.FLOAT -> sb.append("    { float _f = _p").append(i).append("; __builtin_memcpy(&_iv[").append(slot).append("], &_f, 4); }\n");
                    case Type.DOUBLE -> sb.append("    { double _d = _p").append(i).append("; __builtin_memcpy(&_iv[").append(slot).append("], &_d, 8); }\n");
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
        return sb.toString();
    }

    private static String formatInvoke(String tmpl, boolean isStatic, boolean isSpecial) {
        String pfx = isStatic ? "CallStatic" : (isSpecial ? "CallNonvirtual" : "Call");
        String argPrefix = isStatic ? "cls, mid, ap" : (isSpecial ? "recv, cls, mid, ap" : "recv, mid, ap");
        return tmpl
                .replace("%IS_STATIC%", isStatic ? "true" : "false")
                .replace("%IS_SPECIAL%", isSpecial ? "true" : "false")
                .replace("%CALL_V%", "env->" + pfx + "VoidMethodA(" + argPrefix + ")")
                .replace("%CALL_Z%", "env->" + pfx + "BooleanMethodA(" + argPrefix + ")")
                .replace("%CALL_B%", "env->" + pfx + "ByteMethodA(" + argPrefix + ")")
                .replace("%CALL_C%", "env->" + pfx + "CharMethodA(" + argPrefix + ")")
                .replace("%CALL_S%", "env->" + pfx + "ShortMethodA(" + argPrefix + ")")
                .replace("%CALL_I%", "env->" + pfx + "IntMethodA(" + argPrefix + ")")
                .replace("%CALL_J%", "env->" + pfx + "LongMethodA(" + argPrefix + ")")
                .replace("%CALL_F%", "env->" + pfx + "FloatMethodA(" + argPrefix + ")")
                .replace("%CALL_D%", "env->" + pfx + "DoubleMethodA(" + argPrefix + ")")
                .replace("%CALL_L%", "env->" + pfx + "ObjectMethodA(" + argPrefix + ")");
    }

    private static void emitVmCase(StringBuilder sb, VmIsa isa, VmIsa.Op op, String body) {
        sb.append("            case ").append(isa.encodeOp(op)).append(": ").append(body.trim()).append("\n");
    }

    private static void emitByteArr(StringBuilder sb, String name, List<Byte> list) {
        sb.append("static const uint8_t ").append(name).append("[] = {\n    ");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0 && i % 20 == 0) sb.append("\n    ");
            sb.append("0x").append(Integer.toHexString(list.get(i) & 0xFF)).append(",");
        }
        if (list.isEmpty()) sb.append("0");
        sb.append("\n};\n");
    }

    private static void emitIntArr(StringBuilder sb, String name, List<Integer> list) {
        sb.append("static const int32_t ").append(name).append("[] = {\n    ");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0 && i % 16 == 0) sb.append("\n    ");
            sb.append(list.get(i)).append(",");
        }
        if (list.isEmpty()) sb.append("0");
        sb.append("\n};\n");
    }
}
