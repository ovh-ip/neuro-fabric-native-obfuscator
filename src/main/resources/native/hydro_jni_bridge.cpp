#include "hydro_runtime.hpp"

namespace hy {

jclass g_cls_class = nullptr;
jmethodID g_mid_forName = nullptr;
jclass g_cls_sb = nullptr;
jmethodID g_mid_sb_init = nullptr;
jmethodID g_mid_sb_app_str = nullptr;
jmethodID g_mid_sb_app_obj = nullptr;
jmethodID g_mid_sb_app_i = nullptr;
jmethodID g_mid_sb_app_j = nullptr;
jmethodID g_mid_sb_app_f = nullptr;
jmethodID g_mid_sb_app_d = nullptr;
jmethodID g_mid_sb_app_z = nullptr;
jmethodID g_mid_sb_app_c = nullptr;
jmethodID g_mid_toString = nullptr;
jclass g_cls_bool_arr = nullptr;
jclass g_cls_obj = nullptr;
jclass g_cls_npe = nullptr;
jclass g_cls_arith = nullptr;
jclass g_cls_negarr = nullptr;
jclass g_cls_cce = nullptr;
jclass g_cls_aioobe = nullptr;

static uintptr_t g_prim_cls_cache[9] = {};
static volatile int32_t g_vm_unsealed = 0;

jclass find_class_by_sym(JNIEnv* env, uint32_t sym_id) {
    SymBuf sb_name;
    char* buf = decrypt_sym(sym_id, sb_name);
    jclass c = env->FindClass(buf);
    if (c == nullptr || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (g_mod_loader && g_cls_class && g_mid_forName) {
            for (char* p = buf; *p; p++) {
                if (*p == '/') *p = '.';
            }
            jstring jn = env->NewStringUTF(buf);
            c = (jclass)env->CallStaticObjectMethod(g_cls_class, g_mid_forName, jn, JNI_TRUE, g_mod_loader);
            if (jn) env->DeleteLocalRef(jn);
        }
    }
    return c;
}

jclass resolve_class(JNIEnv* env, int32_t cls_id) {
    uintptr_t v = __atomic_load_n(&g_cls_cache[cls_id], __ATOMIC_ACQUIRE);
    if (v != 0) [[likely]] return (jclass)(v ^ g_ptr_cookie);
    jclass lc = find_class_by_sym(env, g_cls_syms[cls_id]);
    if (!lc || env->ExceptionCheck()) return nullptr;
    jclass gc = (jclass)env->NewGlobalRef(lc);
    env->DeleteLocalRef(lc);
    uintptr_t masked = ((uintptr_t)gc) ^ g_ptr_cookie;
    uintptr_t expected = 0;
    if (!__atomic_compare_exchange_n(&g_cls_cache[cls_id], &expected, masked, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        env->DeleteGlobalRef(gc);
        return (jclass)(expected ^ g_ptr_cookie);
    }
    return gc;
}

jclass resolve_prim_class(JNIEnv* env, int32_t kind) {
    int32_t idx = (kind >= 0 && kind <= 8) ? kind : 8;
    uintptr_t v = __atomic_load_n(&g_prim_cls_cache[idx], __ATOMIC_ACQUIRE);
    if (v != 0) [[likely]] return (jclass)env->NewLocalRef((jobject)(v ^ g_ptr_cookie));

    uint32_t csym = HY_SYM_DOUBLE_CLS;
    switch (idx) {
        case 0: csym = HY_SYM_VOID_CLS; break;
        case 1: csym = HY_SYM_BOOL_CLS; break;
        case 2: csym = HY_SYM_BYTE_CLS; break;
        case 3: csym = HY_SYM_CHAR_CLS; break;
        case 4: csym = HY_SYM_SHORT_CLS; break;
        case 5: csym = HY_SYM_INT_CLS; break;
        case 6: csym = HY_SYM_LONG_CLS; break;
        case 7: csym = HY_SYM_FLOAT_CLS; break;
        default: csym = HY_SYM_DOUBLE_CLS; break;
    }
    jclass wc = find_class_by_sym(env, csym);
    if (!wc) return nullptr;
    SymBuf sfn, sfd;
    jfieldID fid = env->GetStaticFieldID(wc, decrypt_sym(HY_SYM_TYPE_FIELD, sfn), decrypt_sym(HY_SYM_CLS_FIELD_DESC, sfd));
    jclass res = (jclass)env->GetStaticObjectField(wc, fid);
    env->DeleteLocalRef(wc);
    if (res && !env->ExceptionCheck()) {
        jclass gc = (jclass)env->NewGlobalRef(res);
        uintptr_t masked = ((uintptr_t)gc) ^ g_ptr_cookie;
        uintptr_t expected = 0;
        if (!__atomic_compare_exchange_n(&g_prim_cls_cache[idx], &expected, masked, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            env->DeleteGlobalRef(gc);
        }
    }
    return res;
}

static jmethodID resolve_method_impl(JNIEnv* env, int32_t mid_id, bool is_static) {
    uintptr_t v = __atomic_load_n(&g_method_cache[mid_id], __ATOMIC_ACQUIRE);
    if (v != 0) [[likely]] return (jmethodID)(v ^ g_ptr_cookie);
    const MemberMeta& mm = g_method_meta[mid_id];
    jclass cls = resolve_class(env, (int32_t)mm.cls_id);
    if (!cls || env->ExceptionCheck()) return nullptr;
    SymBuf snb, sdb;
    const char* nb = decrypt_sym(mm.name_sym, snb);
    const char* db = decrypt_sym(mm.desc_sym, sdb);
    jmethodID mid = is_static ? env->GetStaticMethodID(cls, nb, db) : env->GetMethodID(cls, nb, db);
    if (mid && !env->ExceptionCheck()) {
        uintptr_t masked = ((uintptr_t)mid) ^ g_ptr_cookie;
        __atomic_store_n(&g_method_cache[mid_id], masked, __ATOMIC_RELEASE);
    }
    return mid;
}

jmethodID resolve_imethod(JNIEnv* env, int32_t id) { return resolve_method_impl(env, id, false); }
jmethodID resolve_smethod(JNIEnv* env, int32_t id) { return resolve_method_impl(env, id, true); }

static jfieldID resolve_field_impl(JNIEnv* env, int32_t fid_id, bool is_static) {
    uintptr_t v = __atomic_load_n(&g_field_cache[fid_id], __ATOMIC_ACQUIRE);
    if (v != 0) [[likely]] return (jfieldID)(v ^ g_ptr_cookie);
    const MemberMeta& fm = g_field_meta[fid_id];
    jclass cls = resolve_class(env, (int32_t)fm.cls_id);
    if (!cls || env->ExceptionCheck()) return nullptr;
    SymBuf snb, sdb;
    const char* nb = decrypt_sym(fm.name_sym, snb);
    const char* db = decrypt_sym(fm.desc_sym, sdb);
    jfieldID fid = is_static ? env->GetStaticFieldID(cls, nb, db) : env->GetFieldID(cls, nb, db);
    if (fid && !env->ExceptionCheck()) {
        uintptr_t masked = ((uintptr_t)fid) ^ g_ptr_cookie;
        __atomic_store_n(&g_field_cache[fid_id], masked, __ATOMIC_RELEASE);
    }
    return fid;
}

jfieldID resolve_ifield(JNIEnv* env, int32_t id) { return resolve_field_impl(env, id, false); }
jfieldID resolve_sfield(JNIEnv* env, int32_t id) { return resolve_field_impl(env, id, true); }
jclass resolve_field_owner(JNIEnv* env, int32_t fid_id) { return resolve_class(env, (int32_t)g_field_meta[fid_id].cls_id); }
jclass resolve_method_owner(JNIEnv* env, int32_t mid_id) { return resolve_class(env, (int32_t)g_method_meta[mid_id].cls_id); }

jmethodID resolve_dyn_method(JNIEnv* env, jobject recv, int32_t name_sym, int32_t desc_sym) {
    jclass cls = env->GetObjectClass(recv);
    SymBuf snb, sdb;
    jmethodID mid = env->GetMethodID(cls, decrypt_sym((uint32_t)name_sym, snb), decrypt_sym((uint32_t)desc_sym, sdb));
    env->DeleteLocalRef(cls);
    return mid;
}

jfieldID resolve_dyn_field(JNIEnv* env, jobject obj, int32_t name_sym, int32_t desc_sym) {
    jclass cls = env->GetObjectClass(obj);
    SymBuf snb, sdb;
    jfieldID fid = env->GetFieldID(cls, decrypt_sym((uint32_t)name_sym, snb), decrypt_sym((uint32_t)desc_sym, sdb));
    env->DeleteLocalRef(cls);
    return fid;
}

static void JNICALL hy_register_natives(JNIEnv* env, jclass, jclass target_cls, jint class_id) {
    if (!inline_session_ok(opaque_seed()) || !g_jar_verified) [[unlikely]] { destroy_session_keys(); return; }
    if (!target_cls) return;
    for (uint32_t i = 0; i < g_reg_class_count; i++) {
        if (g_reg_classes[i].class_id == class_id) {
            const RegClassMeta& rc = g_reg_classes[i];
            if (rc.count == 0) return;
            JNINativeMethod* methods = (JNINativeMethod*)heap_alloc(rc.count * sizeof(JNINativeMethod));
            uint32_t arena_bytes = 0;
            for (uint32_t m = 0; m < rc.count; m++) {
                const RegMethodMeta& rm = g_reg_methods[rc.start + m];
                arena_bytes += g_sym_meta[rm.name_sym].len + g_sym_meta[rm.desc_sym].len + 2u;
            }
            char* str_arena = (char*)heap_alloc(arena_bytes);
            uint32_t cursor = 0;
            for (uint32_t m = 0; m < rc.count; m++) {
                const RegMethodMeta& rm = g_reg_methods[rc.start + m];
                SymBuf snb, sdb;
                const char* np = decrypt_sym(rm.name_sym, snb);
                const char* dp = decrypt_sym(rm.desc_sym, sdb);
                uint32_t nl = g_sym_meta[rm.name_sym].len;
                uint32_t dl = g_sym_meta[rm.desc_sym].len;
                char* nb = str_arena + cursor; memcpy(nb, np, nl); nb[nl] = '\0'; cursor += nl + 1u;
                char* db = str_arena + cursor; memcpy(db, dp, dl); db[dl] = '\0'; cursor += dl + 1u;
                methods[m].name = nb;
                methods[m].signature = db;
                methods[m].fnPtr = rm.fn;
            }
            env->RegisterNatives(target_cls, methods, (jint)rc.count);
            secure_wipe(str_arena, arena_bytes);
            heap_free(str_arena);
            heap_free(methods);
            return;
        }
    }
}

static void decrypt_fucked_inplace(uint8_t* buf, uint32_t len, uint64_t file_seed, uint64_t vs) {
    uint64_t st = splitmix64(file_seed ^ vs);
    for (uint32_t i = 0; i < len; i++) {
        st = splitmix64(st + (uint64_t)i * 0x9E3779B97F4A7C15ULL);
        uint8_t k = (uint8_t)((st >> ((i & 7u) * 8u)) & 0xFFu);
        uint32_t rot = (uint32_t)((st >> 56) & 7u);
        uint8_t r = buf[i] ^ (uint8_t)((i * 73u + (uint32_t)file_seed) & 0xFFu);
        uint8_t x = (uint8_t)(((r >> rot) | (r << (8u - rot))) & 0xFFu);
        buf[i] = (uint8_t)(x ^ k);
    }
}

static void JNICALL hy_verify_loader(JNIEnv* env, jclass hcls, jobject loader) {
    (void)hcls;
    if (loader && !g_mod_loader) {
        g_mod_loader = env->NewGlobalRef(loader);
    }
    const uint64_t _op = opaque_seed();
    uint64_t ts = HY_MBA_TAG_SALT(_op);
    uint64_t vs = HY_MBA_VAULT_SALT(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    uint64_t hb = HY_MBA_HASH_BASIS(_op);
    (void)vs; (void)hp; (void)hb;

#if HY_VERIFY_JAR || HY_HAS_FUCKED || HY_ENABLE_SERVER
    if (!g_mod_loader) { g_tampered = 1; poison_cookie(); return; }
    jclass cl_cls = find_class_by_sym(env, HY_SYM_CL);
    jclass is_cls = find_class_by_sym(env, HY_SYM_IS);
    jclass url_cls = find_class_by_sym(env, HY_SYM_URL_CLS);
    jclass enum_cls = find_class_by_sym(env, HY_SYM_ENUM_CLS);
    jclass str_cls = find_class_by_sym(env, HY_SYM_STR_CLS);
    SymBuf sgn, sgd, srn, srd, scn, svd;
    jmethodID mid_get = env->GetMethodID(cl_cls, decrypt_sym(HY_SYM_GETRES, sgn), decrypt_sym(HY_SYM_GETRES_DESC, sgd));
    jmethodID mid_read = env->GetMethodID(is_cls, decrypt_sym(HY_SYM_IS_READ, srn), decrypt_sym(HY_SYM_IS_READ_DESC, srd));
    jmethodID mid_close = env->GetMethodID(is_cls, decrypt_sym(HY_SYM_IS_CLOSE, scn), decrypt_sym(HY_SYM_SB_INIT_DESC, svd));
    jstring base_prefix = nullptr;
    jmethodID mid_get_enum = nullptr, mid_has_more = nullptr, mid_next_elem = nullptr;
    jmethodID mid_url_tostr = nullptr, mid_url_open = nullptr, mid_str_starts = nullptr;
    if (hcls && g_cls_class && url_cls && enum_cls && str_cls) {
        SymBuf sb0, sb1, sb2, sb3, sb4, sb5, sb6, sb7, sb8, sb9, sb10, sb11, sb12, sb13, sb14, sb15, sb16, sb17, sb18;
        jmethodID mid_cls_url = env->GetMethodID(g_cls_class, decrypt_sym(HY_SYM_GETRES_URL, sb0), decrypt_sym(HY_SYM_GETRES_URL_DESC, sb1));
        mid_get_enum = env->GetMethodID(cl_cls, decrypt_sym(HY_SYM_GETRES_ENUM, sb2), decrypt_sym(HY_SYM_GETRES_ENUM_DESC, sb3));
        mid_url_tostr = env->GetMethodID(url_cls, decrypt_sym(HY_SYM_TOSTR, sb4), decrypt_sym(HY_SYM_TOSTR_DESC, sb5));
        mid_url_open = env->GetMethodID(url_cls, decrypt_sym(HY_SYM_URL_OPEN, sb6), decrypt_sym(HY_SYM_URL_OPEN_DESC, sb7));
        mid_has_more = env->GetMethodID(enum_cls, decrypt_sym(HY_SYM_HAS_MORE, sb8), decrypt_sym(HY_SYM_HAS_MORE_DESC, sb9));
        mid_next_elem = env->GetMethodID(enum_cls, decrypt_sym(HY_SYM_NEXT_ELEM, sb10), decrypt_sym(HY_SYM_NEXT_ELEM_DESC, sb11));
        jmethodID mid_str_ends = env->GetMethodID(str_cls, decrypt_sym(HY_SYM_ENDS_WITH, sb12), decrypt_sym(HY_SYM_BOOL_STR_DESC, sb13));
        mid_str_starts = env->GetMethodID(str_cls, decrypt_sym(HY_SYM_STARTS_WITH, sb14), sb13.ptr);
        jmethodID mid_str_sub = env->GetMethodID(str_cls, decrypt_sym(HY_SYM_SUBSTR, sb15), decrypt_sym(HY_SYM_SUBSTR_DESC, sb16));
        jmethodID mid_str_len = env->GetMethodID(str_cls, decrypt_sym(HY_SYM_STR_LEN, sb17), decrypt_sym(HY_SYM_INT_VOID_DESC, sb18));
        if (env->ExceptionCheck()) { env->ExceptionClear(); }
        if (mid_cls_url && mid_get_enum && mid_url_tostr && mid_url_open && mid_has_more && mid_next_elem && mid_str_ends && mid_str_starts && mid_str_sub && mid_str_len) {
            SymBuf slr, slt;
            jstring jlr = env->NewStringUTF(decrypt_sym(HY_SYM_LOADER_RES, slr));
            jstring jlt = env->NewStringUTF(decrypt_sym(HY_SYM_LOADER_TAIL, slt));
            jobject self_url = env->CallObjectMethod(hcls, mid_cls_url, jlr);
            if (env->ExceptionCheck()) { env->ExceptionClear(); if (self_url) env->DeleteLocalRef(self_url); self_url = nullptr; }
            if (self_url) {
                jstring self_str = (jstring)env->CallObjectMethod(self_url, mid_url_tostr);
                if (env->ExceptionCheck()) { env->ExceptionClear(); if (self_str) env->DeleteLocalRef(self_str); self_str = nullptr; }
                if (self_str && env->CallBooleanMethod(self_str, mid_str_ends, jlt)) {
                    jint flen = env->CallIntMethod(self_str, mid_str_len);
                    jint tlen = env->CallIntMethod(jlt, mid_str_len);
                    if (flen > tlen) base_prefix = (jstring)env->CallObjectMethod(self_str, mid_str_sub, (jint)0, (jint)(flen - tlen));
                    if (env->ExceptionCheck()) { env->ExceptionClear(); if (base_prefix) env->DeleteLocalRef(base_prefix); base_prefix = nullptr; }
                }
                if (self_str) env->DeleteLocalRef(self_str);
                env->DeleteLocalRef(self_url);
            }
            env->DeleteLocalRef(jlr);
            env->DeleteLocalRef(jlt);
        }
    }
    auto open_own_res = [&](const char* rname) -> jobject {
        jstring js = env->NewStringUTF(rname);
        if (base_prefix && mid_get_enum) {
            jobject en = env->CallObjectMethod(g_mod_loader, mid_get_enum, js);
            if (env->ExceptionCheck()) { env->ExceptionClear(); if (en) env->DeleteLocalRef(en); en = nullptr; }
            jobject matched = nullptr;
            while (en && env->CallBooleanMethod(en, mid_has_more)) {
                if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
                jobject u = env->CallObjectMethod(en, mid_next_elem);
                if (env->ExceptionCheck() || !u) { if (env->ExceptionCheck()) env->ExceptionClear(); break; }
                jstring us = (jstring)env->CallObjectMethod(u, mid_url_tostr);
                if (env->ExceptionCheck()) { env->ExceptionClear(); if (us) env->DeleteLocalRef(us); us = nullptr; }
                jboolean ok = us ? env->CallBooleanMethod(us, mid_str_starts, base_prefix) : JNI_FALSE;
                if (env->ExceptionCheck()) { env->ExceptionClear(); ok = JNI_FALSE; }
                if (us) env->DeleteLocalRef(us);
                if (ok) {
                    matched = env->CallObjectMethod(u, mid_url_open);
                    if (env->ExceptionCheck()) { env->ExceptionClear(); if (matched) env->DeleteLocalRef(matched); matched = nullptr; }
                    env->DeleteLocalRef(u);
                    break;
                }
                env->DeleteLocalRef(u);
            }
            if (en) env->DeleteLocalRef(en);
            env->DeleteLocalRef(js);
            return matched;
        }
        jobject stm = env->CallObjectMethod(g_mod_loader, mid_get, js);
        if (env->ExceptionCheck()) { env->ExceptionClear(); if (stm) env->DeleteLocalRef(stm); stm = nullptr; }
        env->DeleteLocalRef(js);
        return stm;
    };
    jbyteArray jbuf = env->NewByteArray(4096);
    jbyte raw[4096];
    uint64_t ek = hb;
#if HY_VERIFY_JAR
    for (uint32_t idx = 0; idx < g_verify_res_count; idx++) {
        SymBuf srn_buf;
        jobject stm = open_own_res(decrypt_sym(g_verify_res_syms[idx], srn_buf));
        if (!stm) { g_tampered = 1; break; }
        for (;;) {
            jint n = env->CallIntMethod(stm, mid_read, jbuf);
            if (env->ExceptionCheck()) { env->ExceptionClear(); g_tampered = 1; break; }
            if (n <= 0) break;
            env->GetByteArrayRegion(jbuf, 0, n, raw);
            for (jint k = 0; k < n; k++) { ek ^= (uint8_t)raw[k]; ek *= hp; }
        }
        env->CallVoidMethod(stm, mid_close);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(stm);
    }
    uint64_t tag = splitmix64(ek ^ ts) ^ splitmix64(ek * hp + vs) ^ ((ek >> 17) * (ek | 1ULL));
    if (tag != HY_VERIFY_TAG) { g_tampered = 1; poison_cookie(); }
#else
    ek = HY_MBA_EFFECTIVE_KEY(_op);
#endif
    uint64_t srv_vm_share = 0;
    uint64_t srv_vault_share = 0;
    bool server_denied = false;
#if HY_ENABLE_SERVER
    if (!g_tampered) {
        if (!server_handshake(env, ek, &srv_vm_share, &srv_vault_share)) {
            server_denied = true;
            g_tampered = 1;
            poison_cookie();
        }
    }
#endif
    if (!g_tampered && !__atomic_exchange_n(&g_vm_unsealed, 1, __ATOMIC_ACQ_REL)) {
        uint64_t srv_dyn0 = HY_ENABLE_SERVER ? (g_srv_dyn_params[0] ^ (uint64_t)g_ptr_cookie) : 0ULL;
        g_vm_key_masked ^= splitmix64(ek ^ ts) ^ srv_vm_share ^ srv_dyn0;
        g_vm_key_masked ^= (uint64_t)g_ptr_cookie;
    }
    vs ^= srv_vault_share;
#if HY_HAS_FUCKED
    if (!g_tampered) {
        for (uint32_t fi = 0; fi < g_fucked_count; fi++) {
            const FuckedMeta& fm = g_fucked_entries[fi];
            uint32_t u_csym = fm.cls_sym ^ (uint32_t)splitmix64(ek ^ ((uint64_t)fi * 0xD6E8FEB86659FD93ULL));
            uint32_t u_psym = fm.path_sym ^ (uint32_t)splitmix64(ek ^ ((uint64_t)fi * 0x517CC1B727220A95ULL));
            uint32_t u_len  = fm.raw_len ^ (uint32_t)splitmix64(ek + ((uint64_t)fi * 0x9E3779B97F4A7C15ULL));
            uint64_t u_seed = fm.seed ^ splitmix64(ek + ((uint64_t)fi * 0xBF58476D1CE4E5B9ULL));
            uint64_t u_mac  = fm.mac ^ splitmix64(ek + ((uint64_t)fi * 0x94D049BB133111EBULL));
            SymBuf scname, spname;
            const char* cname = decrypt_sym(u_csym, scname);
            const char* pname = decrypt_sym(u_psym, spname);
            jobject stm = open_own_res(pname);
            if (!stm) { g_tampered = 1; poison_cookie(); break; }
            uint8_t* cbuf = (uint8_t*)heap_alloc(u_len > 0 ? u_len : 1u);
            uint32_t total = 0;
            for (;;) {
                jint n = env->CallIntMethod(stm, mid_read, jbuf);
                if (env->ExceptionCheck()) { env->ExceptionClear(); g_tampered = 1; break; }
                if (n <= 0) break;
                env->GetByteArrayRegion(jbuf, 0, n, raw);
                if (total < u_len) {
                    uint32_t take = (uint32_t)n;
                    if (total + take > u_len) take = u_len - total;
                    memcpy(cbuf + total, raw, (size_t)take);
                }
                total += (uint32_t)n;
            }
            env->CallVoidMethod(stm, mid_close);
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(stm);
            if (!g_tampered && total >= u_len) {
                decrypt_fucked_inplace(cbuf, u_len, u_seed, vs);
                uint64_t mac = hb;
                for (uint32_t k = 0; k < u_len; k++) { mac ^= cbuf[k]; mac *= hp; }
                if (mac != u_mac) {
                    g_tampered = 1; poison_cookie();
                } else {
                    jclass dc = env->DefineClass(cname, g_mod_loader, (const jbyte*)cbuf, (jsize)u_len);
                    if (!dc || env->ExceptionCheck()) { if (env->ExceptionCheck()) env->ExceptionClear(); g_tampered = 1; poison_cookie(); }
                    if (dc) env->DeleteLocalRef(dc);
                }
            } else { g_tampered = 1; poison_cookie(); }
            secure_wipe(cbuf, u_len); heap_free(cbuf);
            if (g_tampered) break;
        }
    }
#endif
    if (base_prefix) env->DeleteLocalRef(base_prefix);
    env->DeleteLocalRef(jbuf);
    if (url_cls) env->DeleteLocalRef(url_cls);
    if (enum_cls) env->DeleteLocalRef(enum_cls);
    if (str_cls) env->DeleteLocalRef(str_cls);
    env->DeleteLocalRef(cl_cls);
    env->DeleteLocalRef(is_cls);
    run_periodic_vm_guard();
    if (!g_tampered) {
        g_jar_verified = 1;
    } else if (server_denied) {
        SymBuf sex, smsg;
        jclass excCls = env->FindClass(decrypt_sym(HY_SYM_SEC_EX, sex));
        if (excCls) {
            env->ThrowNew(excCls, decrypt_sym(HY_SYM_SEC_MSG, smsg));
            env->DeleteLocalRef(excCls);
        }
    }
#else
    if (!g_tampered && !__atomic_exchange_n(&g_vm_unsealed, 1, __ATOMIC_ACQ_REL)) {
        uint64_t ek = HY_MBA_EFFECTIVE_KEY(_op);
        g_vm_key_masked ^= splitmix64(ek ^ ts);
        g_vm_key_masked ^= (uint64_t)g_ptr_cookie;
    }
    run_periodic_vm_guard();
    if (!g_tampered) g_jar_verified = 1;
#endif
}

static void init_bootstrap(JNIEnv* env) {
    auto gcls = [&](uint32_t sym) -> jclass {
        SymBuf s;
        jclass lc = env->FindClass(decrypt_sym(sym, s));
        if (!lc) return nullptr;
        jclass gc = (jclass)env->NewGlobalRef(lc);
        env->DeleteLocalRef(lc);
        return gc;
    };
    auto gmid = [&](jclass c, uint32_t ns, uint32_t ds, bool st) -> jmethodID {
        SymBuf sn, sd;
        const char* nb = decrypt_sym(ns, sn);
        const char* db = decrypt_sym(ds, sd);
        return st ? env->GetStaticMethodID(c, nb, db) : env->GetMethodID(c, nb, db);
    };
    g_cls_class = gcls(HY_SYM_CLASS);
    g_mid_forName = gmid(g_cls_class, HY_SYM_FORNAME, HY_SYM_FORNAME_DESC, true);
    g_cls_sb = gcls(HY_SYM_SB);
    g_mid_sb_init = gmid(g_cls_sb, HY_SYM_SB_INIT, HY_SYM_SB_INIT_DESC, false);
    g_mid_sb_app_str = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_STR_DESC, false);
    g_mid_sb_app_obj = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_OBJ_DESC, false);
    g_mid_sb_app_i = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_INT_DESC, false);
    g_mid_sb_app_j = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_LONG_DESC, false);
    g_mid_sb_app_f = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_FLOAT_DESC, false);
    g_mid_sb_app_d = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_DOUBLE_DESC, false);
    g_mid_sb_app_z = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_BOOL_DESC, false);
    g_mid_sb_app_c = gmid(g_cls_sb, HY_SYM_SB_APP_STR, HY_SYM_SB_APP_CHAR_DESC, false);
    g_mid_toString = gmid(g_cls_sb, HY_SYM_TOSTR, HY_SYM_TOSTR_DESC, false);
    g_cls_bool_arr = gcls(HY_SYM_BOOL_ARR);
    g_cls_obj = gcls(HY_SYM_OBJ);
    g_cls_npe = gcls(HY_SYM_NPE);
    g_cls_arith = gcls(HY_SYM_ARITH);
    g_cls_negarr = gcls(HY_SYM_NEGARR);
    g_cls_cce = gcls(HY_SYM_CCE);
    g_cls_aioobe = gcls(HY_SYM_AIOOBE);
}

} // namespace hy

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_8) != JNI_OK || !env) return JNI_ERR;
    uint64_t tsc = hy::hy_tick();
    hy::g_ptr_cookie = (uintptr_t)(hy::splitmix64(tsc ^ (uintptr_t)env ^ (uintptr_t)&vm) | 1ULL);
    hy::g_rt_entropy ^= tsc;
    hy::init_code_integrity();
    hy::run_security_checks(env);
    hy::init_bootstrap(env);
    jclass lcls = hy::find_class_by_sym(env, HY_SYM_LOADER);
    if (lcls) {
        hy::SymBuf srn, srd, svn, svd;
        JNINativeMethod reg[2] = {
            {hy::decrypt_sym(HY_SYM_REG_NAME, srn), hy::decrypt_sym(HY_SYM_REG_DESC, srd), (void*)&hy::hy_register_natives},
            {hy::decrypt_sym(HY_SYM_VER_NAME, svn), hy::decrypt_sym(HY_SYM_VER_DESC, svd), (void*)&hy::hy_verify_loader}
        };
        env->RegisterNatives(lcls, reg, 2);
        env->DeleteLocalRef(lcls);
    }
    return JNI_VERSION_1_8;
}

#if HY_ENABLE_SERVER
extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM*, void*) {
    hy::server_logout();
}
#endif
