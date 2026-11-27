#include "hydro_runtime.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <stdlib.h>
#endif

namespace hy {

uintptr_t g_ptr_cookie = 0;
volatile int32_t g_tampered = 0;
jobject g_mod_loader = nullptr;
volatile int32_t g_jar_verified = HY_INITIAL_JAR_VERIFIED;

#ifdef _WIN32
static HANDLE g_heap = nullptr;
#endif

void* heap_alloc(size_t sz) {
    size_t n = sz > 0 ? sz : 1;
#ifdef _WIN32
    if (!g_heap) g_heap = GetProcessHeap();
    return HeapAlloc(g_heap, HEAP_ZERO_MEMORY, n);
#else
    return calloc(1, n);
#endif
}

void heap_free(void* p) {
    if (!p) return;
#ifdef _WIN32
    if (g_heap) HeapFree(g_heap, 0, p);
#else
    free(p);
#endif
}

char* decrypt_sym(uint32_t id, SymBuf& sb) {
    const SymMeta& m = g_sym_meta[id];
    uint32_t n = m.len;
    char* out = sb.ensure(n > 0u ? n : 1u);
    const uint64_t _op = opaque_seed();
    uint64_t ms = HY_MBA_MASTER_SEED(_op);
    uint64_t st = splitmix64(ms ^ ((uint64_t)id * 0xD6E8FEB86659FD93ULL) ^ 0xA5A55A5AF0F00F0FULL);
    for (uint32_t i = 0; i < n; i++) {
        st = splitmix64(st + (uint64_t)i * 0x9E3779B97F4A7C15ULL);
        uint8_t k = (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);
        uint32_t rot = (uint32_t)((st >> 56) & 7u);
        uint8_t r = g_sym_blob[m.off + i] ^ (uint8_t)((i * 31u + id) & 0xFFu);
        uint8_t x = (uint8_t)(((r >> rot) | (r << (8u - rot))) & 0xFFu);
        out[i] = (char)(x ^ k);
    }
    if (n > 0u) out[n - 1u] = '\0';
    else out[0] = '\0';
    return out;
}

jstring new_wstr(JNIEnv* env, int32_t wstr_id) {
    const WStrMeta& m = g_wstr_meta[(uint32_t)wstr_id];
    if (m.len == 0) return env->NewString(nullptr, 0);
    jchar stack_buf[256];
    jchar* buf = m.len <= 256 ? stack_buf : (jchar*)heap_alloc((size_t)m.len * sizeof(jchar));
    const uint64_t _op = opaque_seed();
    uint64_t ms = HY_MBA_MASTER_SEED(_op);
    uint64_t st = splitmix64(ms ^ ((uint64_t)(uint32_t)wstr_id * 0x94D049BB133111EBULL) ^ 0x55AA33CC11EE7799ULL);
    for (uint32_t i = 0; i < m.len; i++) {
        st = splitmix64(st ^ ((uint64_t)i * 0xBF58476D1CE4E5B9ULL));
        uint16_t k = (uint16_t)(st & 0xFFFFu);
        uint32_t rot = (uint32_t)((st >> 48) & 15u);
        uint16_t r = g_wstr_blob[m.off + i] ^ (uint16_t)((i * 131u + (uint32_t)wstr_id * 17u) & 0xFFFFu);
        uint16_t x = (uint16_t)(((r >> rot) | (r << (16u - rot))) & 0xFFFFu);
        buf[i] = (jchar)(x ^ k);
    }
    jstring js = env->NewString(buf, (jsize)m.len);
    secure_wipe(buf, (size_t)m.len * sizeof(jchar));
    if (buf != stack_buf) heap_free(buf);
    return js;
}

jstring string_concat(JNIEnv* env, int32_t recipe_wid, const int32_t* const_wids, int32_t const_cnt, const ConcatArg* args, int32_t argc) {
    jobject sbo = env->NewObject(g_cls_sb, g_mid_sb_init);
    if (!sbo || env->ExceptionCheck()) return nullptr;
    const WStrMeta& rm = g_wstr_meta[(uint32_t)recipe_wid];
    jchar stack_rec[256];
    jchar* rbuf = rm.len <= 256 ? stack_rec : (jchar*)heap_alloc((size_t)rm.len * sizeof(jchar));
    const uint64_t _op = opaque_seed();
    uint64_t ms = HY_MBA_MASTER_SEED(_op);
    uint64_t st = splitmix64(ms ^ ((uint64_t)(uint32_t)recipe_wid * 0x94D049BB133111EBULL) ^ 0x55AA33CC11EE7799ULL);
    for (uint32_t i = 0; i < rm.len; i++) {
        st = splitmix64(st ^ ((uint64_t)i * 0xBF58476D1CE4E5B9ULL));
        uint16_t k = (uint16_t)(st & 0xFFFFu);
        uint32_t rot = (uint32_t)((st >> 48) & 15u);
        uint16_t r = g_wstr_blob[rm.off + i] ^ (uint16_t)((i * 131u + (uint32_t)recipe_wid * 17u) & 0xFFFFu);
        uint16_t x = (uint16_t)(((r >> rot) | (r << (16u - rot))) & 0xFFFFu);
        rbuf[i] = (jchar)(x ^ k);
    }
    uint32_t seg_start = 0;
    int32_t arg_idx = 0, const_idx = 0;
    auto flush_lit = [&](uint32_t s, uint32_t e) {
        if (e > s) {
            jstring js = env->NewString(rbuf + s, (jsize)(e - s));
            jobject tmp = env->CallObjectMethod(sbo, g_mid_sb_app_str, js);
            if (tmp) env->DeleteLocalRef(tmp);
            if (js) env->DeleteLocalRef(js);
        }
    };
    for (uint32_t i = 0; i < rm.len; i++) {
        if (rbuf[i] == 1) {
            flush_lit(seg_start, i); seg_start = i + 1;
            if (arg_idx < argc) {
                const ConcatArg& ca = args[arg_idx++];
                jobject tmp = nullptr;
                switch (ca.kind) {
                    case 1: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_z, (jboolean)(ca.i & 1 ? JNI_TRUE : JNI_FALSE)); break;
                    case 2: case 4: case 5: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_i, (jint)ca.i); break;
                    case 3: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_c, (jchar)ca.i); break;
                    case 6: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_j, (jlong)ca.j); break;
                    case 7: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_f, (jfloat)ca.f); break;
                    case 8: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_d, (jdouble)ca.d); break;
                    default: tmp = env->CallObjectMethod(sbo, g_mid_sb_app_obj, ca.obj); break;
                }
                if (tmp) env->DeleteLocalRef(tmp);
            }
        } else if (rbuf[i] == 2) {
            flush_lit(seg_start, i); seg_start = i + 1;
            if (const_idx < const_cnt && const_wids) {
                jstring cs = new_wstr(env, const_wids[const_idx++]);
                jobject tmp = env->CallObjectMethod(sbo, g_mid_sb_app_str, cs);
                if (tmp) env->DeleteLocalRef(tmp);
                if (cs) env->DeleteLocalRef(cs);
            }
        }
    }
    flush_lit(seg_start, rm.len);
    secure_wipe(rbuf, (size_t)rm.len * sizeof(jchar));
    if (rbuf != stack_rec) heap_free(rbuf);
    jstring out = (jstring)env->CallObjectMethod(sbo, g_mid_toString);
    env->DeleteLocalRef(sbo);
    return out;
}

static jobject alloc_multi_rec(JNIEnv* env, const int32_t* cids, const int32_t* dims, int32_t level, int32_t ndims, int32_t elem_kind) {
    int32_t len = dims[level];
    if (len < 0) { throw_neg_arr(env); return nullptr; }
    if (level == ndims - 1) {
        switch (elem_kind) {
            case 1: return env->NewBooleanArray(len);
            case 2: return env->NewByteArray(len);
            case 3: return env->NewCharArray(len);
            case 4: return env->NewShortArray(len);
            case 5: return env->NewIntArray(len);
            case 6: return env->NewLongArray(len);
            case 7: return env->NewFloatArray(len);
            case 8: return env->NewDoubleArray(len);
            default: {
                jclass ec = resolve_class(env, cids[level]);
                return env->NewObjectArray(len, ec, nullptr);
            }
        }
    }
    jclass sub_cls = resolve_class(env, cids[level]);
    if (!sub_cls || env->ExceptionCheck()) return nullptr;
    jobjectArray arr = env->NewObjectArray(len, sub_cls, nullptr);
    if (!arr || env->ExceptionCheck()) return nullptr;
    for (int32_t i = 0; i < len; i++) {
        jobject sub = alloc_multi_rec(env, cids, dims, level + 1, ndims, elem_kind);
        if (env->ExceptionCheck()) { if (sub) env->DeleteLocalRef(sub); env->DeleteLocalRef(arr); return nullptr; }
        env->SetObjectArrayElement(arr, i, sub);
        if (sub) env->DeleteLocalRef(sub);
    }
    return arr;
}

jobject new_multi_array(JNIEnv* env, const int32_t* cids, const int32_t* dims, int32_t ndims, int32_t elem_kind) {
    for (int32_t i = 0; i < ndims; i++) {
        if (dims[i] < 0) { throw_neg_arr(env); return nullptr; }
    }
    return alloc_multi_rec(env, cids, dims, 0, ndims, elem_kind);
}

int32_t baload_dyn(JNIEnv* env, jarray arr, int32_t idx) {
    if (env->IsInstanceOf(arr, g_cls_bool_arr)) {
        jboolean v = 0;
        env->GetBooleanArrayRegion((jbooleanArray)arr, idx, 1, &v);
        return v ? 1 : 0;
    } else {
        jbyte v = 0;
        env->GetByteArrayRegion((jbyteArray)arr, idx, 1, &v);
        return (int32_t)(int8_t)v;
    }
}

void bastore_dyn(JNIEnv* env, jarray arr, int32_t idx, int32_t val) {
    if (env->IsInstanceOf(arr, g_cls_bool_arr)) {
        jboolean v = (val & 1) ? JNI_TRUE : JNI_FALSE;
        env->SetBooleanArrayRegion((jbooleanArray)arr, idx, 1, &v);
    } else {
        jbyte v = (jbyte)val;
        env->SetByteArrayRegion((jbyteArray)arr, idx, 1, &v);
    }
}

void throw_arith(JNIEnv* env) {
    SymBuf smb;
    env->ThrowNew(g_cls_arith, decrypt_sym(HY_SYM_DIV_ZERO_MSG, smb));
}

void throw_npe(JNIEnv* env) { env->ThrowNew(g_cls_npe, ""); }
void throw_neg_arr(JNIEnv* env) { env->ThrowNew(g_cls_negarr, ""); }
void throw_cce(JNIEnv* env) { env->ThrowNew(g_cls_cce, ""); }
void throw_aioobe(JNIEnv* env) { env->ThrowNew(g_cls_aioobe, ""); }

} // namespace hy
