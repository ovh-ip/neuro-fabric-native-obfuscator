#include "hydro_runtime.hpp"

namespace hy {

struct VmSlot {
    uint64_t u;
    int32_t r;
    uint8_t cat;
    uint8_t is_ref;
};

static uint64_t vm_invoke_helper(
        JNIEnv* env, const VmCallMeta& cm, VmSlot* stk, int32_t& sp,
        RefTable& refs, bool is_static, bool is_special, bool& threw) {

    threw = false;
    int32_t base = sp - cm.arg_cnt - (is_static ? 0 : 1);
    jobject recv = is_static ? nullptr : refs.raw(stk[base].r);
    if (!is_static && !recv) {
        throw_npe(env);
        threw = true;
        return 0;
    }
    jmethodID mid = is_static ? resolve_smethod(env, cm.member_id) : resolve_imethod(env, cm.member_id);
    if (env->ExceptionCheck()) { threw = true; return 0; }
    jclass cls = (is_static || is_special) ? resolve_method_owner(env, cm.member_id) : nullptr;
    if (env->ExceptionCheck()) { threw = true; return 0; }

    jvalue jargs_stk[16];
    jvalue* jargs = cm.arg_cnt <= 16 ? jargs_stk : (jvalue*)heap_alloc((size_t)cm.arg_cnt * sizeof(jvalue));
    for (uint16_t k = 0; k < cm.arg_cnt; k++) {
        int32_t s = base + (is_static ? 0 : 1) + k;
        switch (g_vm_call_ak[cm.arg_off + k]) {
            case 1: jargs[k].z = (stk[s].u & 1) ? JNI_TRUE : JNI_FALSE; break;
            case 2: jargs[k].b = (jbyte)stk[s].u; break;
            case 3: jargs[k].c = (jchar)stk[s].u; break;
            case 4: jargs[k].s = (jshort)stk[s].u; break;
            case 5: jargs[k].i = (jint)stk[s].u; break;
            case 6: jargs[k].j = (jlong)stk[s].u; break;
            case 7: jargs[k].f = bits_to_f32((uint32_t)stk[s].u); break;
            case 8: jargs[k].d = bits_to_f64(stk[s].u); break;
            default: jargs[k].l = refs.raw(stk[s].r); break;
        }
    }
    const jvalue* ap = cm.arg_cnt > 0 ? jargs : nullptr;
    uint64_t rbits = 0;
    jobject robj = nullptr;

#define HY_DO_CALL(retType, name) \
    (is_static ? env->CallStatic##name##MethodA(cls, mid, ap) \
               : (is_special ? env->CallNonvirtual##name##MethodA(recv, cls, mid, ap) \
                             : env->Call##name##MethodA(recv, mid, ap)))

    switch (cm.ret_kind) {
        case 0:
            if (is_static) env->CallStaticVoidMethodA(cls, mid, ap);
            else if (is_special) env->CallNonvirtualVoidMethodA(recv, cls, mid, ap);
            else env->CallVoidMethodA(recv, mid, ap);
            break;
        case 1: rbits = HY_DO_CALL(jboolean, Boolean) ? 1ULL : 0ULL; break;
        case 2: rbits = (uint64_t)(uint32_t)(int32_t)(int8_t)HY_DO_CALL(jbyte, Byte); break;
        case 3: rbits = (uint64_t)(uint32_t)(uint16_t)HY_DO_CALL(jchar, Char); break;
        case 4: rbits = (uint64_t)(uint32_t)(int32_t)(int16_t)HY_DO_CALL(jshort, Short); break;
        case 5: rbits = (uint64_t)(uint32_t)(int32_t)HY_DO_CALL(jint, Int); break;
        case 6: rbits = (uint64_t)(int64_t)HY_DO_CALL(jlong, Long); break;
        case 7: { float rv = HY_DO_CALL(jfloat, Float); memcpy(&rbits, &rv, 4); break; }
        case 8: { double rv = HY_DO_CALL(jdouble, Double); memcpy(&rbits, &rv, 8); break; }
        default: robj = HY_DO_CALL(jobject, Object); break;
    }
#undef HY_DO_CALL

    if (jargs != jargs_stk) heap_free(jargs);
    if (env->ExceptionCheck()) {
        if (robj) env->DeleteLocalRef(robj);
        threw = true;
        return 0;
    }
    while (sp > base) {
        int32_t idx = --sp;
        if (stk[idx].is_ref && stk[idx].r >= 0) refs.release(stk[idx].r);
        stk[idx] = {0ULL, -1, 1, 0};
    }
    if (cm.ret_kind == 9) {
        stk[sp++] = {0ULL, refs.track(robj, true), 1, 1};
    } else if (cm.ret_kind != 0) {
        stk[sp++] = {rbits, -1, (uint8_t)((cm.ret_kind == 6 || cm.ret_kind == 8) ? 2 : 1), 0};
    }
    return rbits;
}

uint64_t vm_exec_core(
        JNIEnv* env, uint32_t vm_method_id,
        const uint64_t* init_vals, const uint8_t* init_is_ref,
        int32_t init_slots, jobject* out_ref) {

    if (out_ref) *out_ref = nullptr;
    if (g_tampered || !check_session_alive()) [[unlikely]] return 0;

    const uint64_t _op = opaque_seed();
    const VmMethodMeta& mm = g_vm_methods[vm_method_id];
    RefTable refs(env);
    const uint64_t mix_const = HY_MBA_VM_MIX_CONST(_op);
    const uint64_t mix_mul = HY_MBA_VM_MIX_MUL(_op);
    const uint32_t disp_mul = (uint32_t)HY_MBA_VM_DISP_MUL(_op);
    const uint32_t disp_xor = (uint32_t)HY_MBA_VM_DISP_XOR(_op);
    (void)mix_mul;
    const uint64_t base_key = (g_vm_key_masked ^ (uint64_t)g_ptr_cookie);
    const uint64_t method_key = splitmix64(base_key ^ mm.method_salt ^ ((uint64_t)vm_method_id * mix_const));

    auto rd_u8_at = [&](uint32_t pos) -> uint8_t {
        uint64_t k = splitmix64(method_key + ((uint64_t)pos * mix_mul));
        return g_vm_code[mm.code_off + pos] ^ (uint8_t)((k >> ((pos & 7u) * 8u)) & 0xFFu);
    };
    auto rd_i32_at = [&](uint32_t pos) -> int32_t {
        uint32_t v = (uint32_t)rd_u8_at(pos)
                   | ((uint32_t)rd_u8_at(pos + 1u) << 8)
                   | ((uint32_t)rd_u8_at(pos + 2u) << 16)
                   | ((uint32_t)rd_u8_at(pos + 3u) << 24);
        return (int32_t)v;
    };

    VmSlot stack_mem[64];
    VmSlot local_mem[64];
    VmSlot* stk = mm.max_stack <= 64 ? stack_mem : (VmSlot*)heap_alloc(mm.max_stack * sizeof(VmSlot));
    VmSlot* loc = mm.max_locals <= 64 ? local_mem : (VmSlot*)heap_alloc(mm.max_locals * sizeof(VmSlot));
    for (int32_t i = 0; i < mm.max_stack; i++) stk[i] = {0ULL, -1, 1, 0};
    for (int32_t i = 0; i < mm.max_locals; i++) loc[i] = {0ULL, -1, 1, 0};
    for (int32_t i = 0; i < init_slots; i++) {
        if (init_is_ref[i]) {
            loc[i].is_ref = 1;
            loc[i].r = refs.track((jobject)(uintptr_t)init_vals[i], false);
        } else {
            loc[i].u = init_vals[i];
        }
    }

    int32_t sp = 0;
    uint32_t pc = 0;
    uint32_t cur_insn_pc = 0;
    uint32_t step_cnt = 0;

    auto cleanup = [&]() {
        if (stk != stack_mem) heap_free(stk);
        if (loc != local_mem) heap_free(loc);
    };

    auto rd_u8 = [&]() -> uint8_t { return rd_u8_at(pc++); };
    auto rd_u16 = [&]() -> uint16_t {
        uint16_t a = rd_u8_at(pc);
        uint16_t b = rd_u8_at(pc + 1u);
        pc += 2u;
        return (uint16_t)(a | (b << 8));
    };
    auto rd_i32 = [&]() -> int32_t {
        int32_t v = rd_i32_at(pc);
        pc += 4u;
        return v;
    };
    auto rd_i64 = [&]() -> int64_t {
        uint64_t v = 0;
        for (uint32_t b = 0; b < 8u; b++) v |= ((uint64_t)rd_u8_at(pc + b) << (b * 8u));
        pc += 8u;
        return (int64_t)v;
    };

    auto clear_stk_slot = [&](int32_t idx) {
        if (stk[idx].is_ref && stk[idx].r >= 0) refs.release(stk[idx].r);
        stk[idx] = {0ULL, -1, 1, 0};
    };

    auto push_i32 = [&](int32_t v) { stk[sp++] = {(uint64_t)(uint32_t)v, -1, 1, 0}; };
    auto push_i64 = [&](int64_t v) { stk[sp++] = {(uint64_t)v, -1, 2, 0}; };
    auto push_f32 = [&](float v) { uint32_t b = 0; memcpy(&b, &v, 4); stk[sp++] = {(uint64_t)b, -1, 1, 0}; };
    auto push_f64 = [&](double v) { uint64_t b = 0; memcpy(&b, &v, 8); stk[sp++] = {b, -1, 2, 0}; };
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

#ifdef HY_OP_NOP
    while (pc < mm.code_len) {
        if ((++step_cnt & 63u) == 1u) [[unlikely]] { if (g_tampered || !check_session_alive()) { cleanup(); return 0; } }
        if ((step_cnt & 1023u) == 511u) [[unlikely]] { run_periodic_vm_guard(); }
        cur_insn_pc = pc;
        uint8_t op = (uint8_t)(rd_u8() ^ mm.op_mask ^ (uint8_t)((cur_insn_pc * mm.pc_mul) & 0xFFu));
        uint32_t h_op = ((uint32_t)op * disp_mul) ^ disp_xor;
        switch (h_op) {
            case HY_OP_NOP: break;
            case HY_OP_CONST_I32: push_i32(rd_i32()); break;
            case HY_OP_CONST_I64: push_i64(rd_i64()); break;
            case HY_OP_CONST_F32: stk[sp++] = {(uint64_t)(uint32_t)rd_i32(), -1, 1, 0}; break;
            case HY_OP_CONST_F64: stk[sp++] = {(uint64_t)rd_i64(), -1, 2, 0}; break;
            case HY_OP_CONST_NULL: stk[sp++] = {0ULL, -1, 1, 1}; break;
            case HY_OP_CONST_STR: {
                int32_t wid = rd_i32();
                jstring js = new_wstr(env, wid);
                if (env->ExceptionCheck()) { if (js) env->DeleteLocalRef(js); if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(js, true);
                break;
            }
            case HY_OP_CONST_CLS: {
                int32_t cid = rd_i32();
                jclass c = resolve_class(env, cid);
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(c, false);
                break;
            }
            case HY_OP_CONST_PRIM_CLS: {
                int32_t k = rd_i32();
                jclass c = resolve_prim_class(env, k);
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(c, true);
                break;
            }
            case HY_OP_LOAD_P: {
                uint16_t slot = rd_u16();
                uint8_t cat = rd_u8();
                stk[sp++] = {loc[slot].u, -1, cat, 0};
                break;
            }
            case HY_OP_STORE_P: {
                uint16_t slot = rd_u16();
                uint8_t cat = rd_u8();
                if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
                loc[slot] = {stk[--sp].u, -1, cat, 0};
                stk[sp] = {0ULL, -1, 1, 0};
                break;
            }
            case HY_OP_LOAD_R: {
                uint16_t slot = rd_u16();
                stk[sp++] = {0ULL, refs.retain(loc[slot].r), 1, 1};
                break;
            }
            case HY_OP_STORE_R: {
                uint16_t slot = rd_u16();
                int32_t nr = stk[--sp].r;
                if (!loc[slot].is_ref || loc[slot].r != nr) {
                    if (loc[slot].is_ref && loc[slot].r >= 0) refs.release(loc[slot].r);
                    loc[slot] = {0ULL, nr, 1, 1};
                } else {
                    refs.release(nr);
                }
                stk[sp] = {0ULL, -1, 1, 0};
                break;
            }
            case HY_OP_IINC: {
                uint16_t slot = rd_u16();
                int32_t d = rd_i32();
                uint32_t x = (uint32_t)loc[slot].u, y = (uint32_t)d;
                loc[slot].u = (uint64_t)((x ^ y) + ((x & y) << 1));
                break;
            }
            case HY_OP_POP1: clear_stk_slot(--sp); break;
            case HY_OP_POP2:
                if (stk[sp - 1].cat == 2) { clear_stk_slot(--sp); }
                else { clear_stk_slot(--sp); clear_stk_slot(--sp); }
                break;
            case HY_OP_DUP1: {
                VmSlot v = stk[sp - 1];
                if (v.is_ref) v.r = refs.retain(v.r);
                stk[sp++] = v;
                break;
            }
            case HY_OP_DUP_X1: {
                VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v1c = v1;
                if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
                stk[sp] = v1; stk[sp - 1] = v2; stk[sp - 2] = v1c;
                sp++;
                break;
            }
            case HY_OP_DUP_X2: {
                VmSlot v1 = stk[sp - 1], v1c = v1;
                if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
                if (stk[sp - 2].cat == 2) {
                    stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = v1c;
                } else {
                    stk[sp] = v1; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = v1c;
                }
                sp++;
                break;
            }
            case HY_OP_DUP2: {
                if (stk[sp - 1].cat == 2) {
                    stk[sp] = stk[sp - 1]; sp++;
                } else {
                    VmSlot a = stk[sp - 2], b = stk[sp - 1];
                    if (a.is_ref) a.r = refs.retain(a.r);
                    if (b.is_ref) b.r = refs.retain(b.r);
                    stk[sp] = a; stk[sp + 1] = b; sp += 2;
                }
                break;
            }
            case HY_OP_DUP2_X1: {
                if (stk[sp - 1].cat == 2) {
                    stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
                } else {
                    VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                    VmSlot v1c = v1, v2c = v2;
                    if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
                    if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                    stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c;
                    sp += 2;
                }
                break;
            }
            case HY_OP_DUP2_X2: {
                if (stk[sp - 1].cat == 2 && stk[sp - 2].cat == 2) {
                    stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp]; sp++;
                } else if (stk[sp - 1].cat == 2) {
                    stk[sp] = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = stk[sp - 3]; stk[sp - 3] = stk[sp]; sp++;
                } else if (stk[sp - 3].cat == 2) {
                    VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3];
                    VmSlot v1c = v1, v2c = v2;
                    if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
                    if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                    stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v1c; stk[sp - 3] = v2c; sp += 2;
                } else {
                    VmSlot v1 = stk[sp - 1], v2 = stk[sp - 2], v3 = stk[sp - 3], v4 = stk[sp - 4];
                    VmSlot v1c = v1, v2c = v2;
                    if (v1c.is_ref) v1c.r = refs.retain(v1c.r);
                    if (v2c.is_ref) v2c.r = refs.retain(v2c.r);
                    stk[sp + 1] = v1; stk[sp] = v2; stk[sp - 1] = v3; stk[sp - 2] = v4; stk[sp - 3] = v1c; stk[sp - 4] = v2c; sp += 2;
                }
                break;
            }
            case HY_OP_SWAP: { VmSlot t = stk[sp - 1]; stk[sp - 1] = stk[sp - 2]; stk[sp - 2] = t; break; }

            case HY_OP_IADD: { uint32_t b = (uint32_t)as_i32(--sp), a = (uint32_t)as_i32(--sp); push_i32((int32_t)((a ^ b) + ((a & b) << 1))); break; }
            case HY_OP_ISUB: { uint32_t b = (uint32_t)as_i32(--sp), a = (uint32_t)as_i32(--sp), nb = ~b; push_i32((int32_t)(((a ^ nb) + ((a & nb) << 1)) + 1u)); break; }
            case HY_OP_IMUL: { int32_t b = as_i32(--sp), a = as_i32(--sp); push_i32((int32_t)((uint32_t)a * (uint32_t)b)); break; }
            case HY_OP_IDIV: { int32_t b = as_i32(--sp), a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_idiv(a, b)); break; }
            case HY_OP_IREM: { int32_t b = as_i32(--sp), a = as_i32(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i32(j_irem(a, b)); break; }
            case HY_OP_INEG: { uint32_t a = (uint32_t)as_i32(--sp); push_i32((int32_t)((~a) + 1u)); break; }
            case HY_OP_ISHL: { int32_t b = as_i32(--sp), a = as_i32(--sp); push_i32((int32_t)((uint32_t)a << (b & 31))); break; }
            case HY_OP_ISHR: { int32_t b = as_i32(--sp), a = as_i32(--sp); push_i32(a >> (b & 31)); break; }
            case HY_OP_IUSHR: { int32_t b = as_i32(--sp), a = as_i32(--sp); push_i32((int32_t)((uint32_t)a >> (b & 31))); break; }
            case HY_OP_IAND: { uint32_t b = (uint32_t)as_i32(--sp), a = (uint32_t)as_i32(--sp); push_i32((int32_t)((a + b) - (a | b))); break; }
            case HY_OP_IOR:  { uint32_t b = (uint32_t)as_i32(--sp), a = (uint32_t)as_i32(--sp); push_i32((int32_t)((a + b) - (a & b))); break; }
            case HY_OP_IXOR: { uint32_t b = (uint32_t)as_i32(--sp), a = (uint32_t)as_i32(--sp); push_i32((int32_t)((a | b) - (a & b))); break; }

            case HY_OP_LADD: { uint64_t b = (uint64_t)as_i64(--sp), a = (uint64_t)as_i64(--sp); push_i64((int64_t)((a ^ b) + ((a & b) << 1))); break; }
            case HY_OP_LSUB: { uint64_t b = (uint64_t)as_i64(--sp), a = (uint64_t)as_i64(--sp), nb = ~b; push_i64((int64_t)(((a ^ nb) + ((a & nb) << 1)) + 1ULL)); break; }
            case HY_OP_LMUL: { int64_t b = as_i64(--sp), a = as_i64(--sp); push_i64((int64_t)((uint64_t)a * (uint64_t)b)); break; }
            case HY_OP_LDIV: { int64_t b = as_i64(--sp), a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_ldiv(a, b)); break; }
            case HY_OP_LREM: { int64_t b = as_i64(--sp), a = as_i64(--sp); if (b == 0) { throw_arith(env); if (!handle_exception()) { cleanup(); return 0; } break; } push_i64(j_lrem(a, b)); break; }
            case HY_OP_LNEG: { int64_t a = as_i64(--sp); push_i64((int64_t)(0ULL - (uint64_t)a)); break; }
            case HY_OP_LSHL: { int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a << (b & 63))); break; }
            case HY_OP_LSHR: { int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64(a >> (b & 63)); break; }
            case HY_OP_LUSHR: { int32_t b = as_i32(--sp); int64_t a = as_i64(--sp); push_i64((int64_t)((uint64_t)a >> (b & 63))); break; }
            case HY_OP_LAND: { int64_t b = as_i64(--sp), a = as_i64(--sp); push_i64(a & b); break; }
            case HY_OP_LOR:  { int64_t b = as_i64(--sp), a = as_i64(--sp); push_i64(a | b); break; }
            case HY_OP_LXOR: { uint64_t b = (uint64_t)as_i64(--sp), a = (uint64_t)as_i64(--sp); push_i64((int64_t)((a | b) - (a & b))); break; }

            case HY_OP_FADD: { float b = as_f32(--sp), a = as_f32(--sp); push_f32(a + b); break; }
            case HY_OP_FSUB: { float b = as_f32(--sp), a = as_f32(--sp); push_f32(a - b); break; }
            case HY_OP_FMUL: { float b = as_f32(--sp), a = as_f32(--sp); push_f32(a * b); break; }
            case HY_OP_FDIV: { float b = as_f32(--sp), a = as_f32(--sp); push_f32(a / b); break; }
            case HY_OP_FREM: { float b = as_f32(--sp), a = as_f32(--sp); push_f32(j_frem(a, b)); break; }
            case HY_OP_FNEG: { float a = as_f32(--sp); push_f32(-a); break; }

            case HY_OP_DADD: { double b = as_f64(--sp), a = as_f64(--sp); push_f64(a + b); break; }
            case HY_OP_DSUB: { double b = as_f64(--sp), a = as_f64(--sp); push_f64(a - b); break; }
            case HY_OP_DMUL: { double b = as_f64(--sp), a = as_f64(--sp); push_f64(a * b); break; }
            case HY_OP_DDIV: { double b = as_f64(--sp), a = as_f64(--sp); push_f64(a / b); break; }
            case HY_OP_DREM: { double b = as_f64(--sp), a = as_f64(--sp); push_f64(j_drem(a, b)); break; }
            case HY_OP_DNEG: { double a = as_f64(--sp); push_f64(-a); break; }

            case HY_OP_I2L: { push_i64((int64_t)as_i32(--sp)); break; }
            case HY_OP_I2F: { push_f32((float)as_i32(--sp)); break; }
            case HY_OP_I2D: { push_f64((double)as_i32(--sp)); break; }
            case HY_OP_L2I: { push_i32((int32_t)as_i64(--sp)); break; }
            case HY_OP_L2F: { push_f32((float)as_i64(--sp)); break; }
            case HY_OP_L2D: { push_f64((double)as_i64(--sp)); break; }
            case HY_OP_F2I: { push_i32(j_f2i(as_f32(--sp))); break; }
            case HY_OP_F2L: { push_i64(j_f2l(as_f32(--sp))); break; }
            case HY_OP_F2D: { push_f64((double)as_f32(--sp)); break; }
            case HY_OP_D2I: { push_i32(j_d2i(as_f64(--sp))); break; }
            case HY_OP_D2L: { push_i64(j_d2l(as_f64(--sp))); break; }
            case HY_OP_D2F: { push_f32((float)as_f64(--sp)); break; }
            case HY_OP_I2B: { push_i32((int32_t)(int8_t)as_i32(--sp)); break; }
            case HY_OP_I2C: { push_i32((int32_t)(uint16_t)as_i32(--sp)); break; }
            case HY_OP_I2S: { push_i32((int32_t)(int16_t)as_i32(--sp)); break; }

            case HY_OP_LCMP:  { int64_t b = as_i64(--sp), a = as_i64(--sp); push_i32(a > b ? 1 : (a < b ? -1 : 0)); break; }
            case HY_OP_FCMPL: { float b = as_f32(--sp), a = as_f32(--sp); push_i32(j_fcmpl(a, b)); break; }
            case HY_OP_FCMPG: { float b = as_f32(--sp), a = as_f32(--sp); push_i32(j_fcmpg(a, b)); break; }
            case HY_OP_DCMPL: { double b = as_f64(--sp), a = as_f64(--sp); push_i32(j_dcmpl(a, b)); break; }
            case HY_OP_DCMPG: { double b = as_f64(--sp), a = as_f64(--sp); push_i32(j_dcmpg(a, b)); break; }

            case HY_OP_JMP: pc = (uint32_t)rd_i32(); break;
            case HY_OP_IF_ZERO: { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) == 0) pc = t; break; }
            case HY_OP_IF_NEZ:  { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) != 0) pc = t; break; }
            case HY_OP_IF_LTZ:  { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) < 0) pc = t; break; }
            case HY_OP_IF_GEZ:  { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) >= 0) pc = t; break; }
            case HY_OP_IF_GTZ:  { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) > 0) pc = t; break; }
            case HY_OP_IF_LEZ:  { uint32_t t = (uint32_t)rd_i32(); if (as_i32(--sp) <= 0) pc = t; break; }

            case HY_OP_IF_ICMPEQ: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a == b) pc = t; break; }
            case HY_OP_IF_ICMPNE: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a != b) pc = t; break; }
            case HY_OP_IF_ICMPLT: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a < b) pc = t; break; }
            case HY_OP_IF_ICMPGE: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a >= b) pc = t; break; }
            case HY_OP_IF_ICMPGT: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a > b) pc = t; break; }
            case HY_OP_IF_ICMPLE: { uint32_t t = (uint32_t)rd_i32(); int32_t b = as_i32(--sp), a = as_i32(--sp); if (a <= b) pc = t; break; }

            case HY_OP_IF_ACMPEQ: { uint32_t t = (uint32_t)rd_i32(); bool eq = env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (eq) pc = t; break; }
            case HY_OP_IF_ACMPNE: { uint32_t t = (uint32_t)rd_i32(); bool ne = !env->IsSameObject(refs.raw(stk[sp-2].r), refs.raw(stk[sp-1].r)); clear_stk_slot(--sp); clear_stk_slot(--sp); if (ne) pc = t; break; }
            case HY_OP_IF_NULL:   { uint32_t t = (uint32_t)rd_i32(); bool z = (refs.raw(stk[sp-1].r) == nullptr); clear_stk_slot(--sp); if (z) pc = t; break; }
            case HY_OP_IF_NONNULL:{ uint32_t t = (uint32_t)rd_i32(); bool nz = (refs.raw(stk[sp-1].r) != nullptr); clear_stk_slot(--sp); if (nz) pc = t; break; }

            case HY_OP_SWITCH_TABLE: {
                int32_t key = as_i32(--sp), mn = rd_i32(), mx = rd_i32();
                uint32_t dflt = (uint32_t)rd_i32();
                if (key >= mn && key <= mx) {
                    uint32_t toff = pc + (uint32_t)(key - mn) * 4u;
                    pc = (uint32_t)rd_i32_at(toff);
                } else {
                    pc = dflt;
                }
                break;
            }
            case HY_OP_SWITCH_LOOKUP: {
                int32_t key = as_i32(--sp), cnt = rd_i32();
                uint32_t dflt = (uint32_t)rd_i32(), target = dflt;
                for (int32_t i = 0; i < cnt; i++) {
                    int32_t k = rd_i32();
                    uint32_t dst = (uint32_t)rd_i32();
                    if (k == key && target == dflt) target = dst;
                }
                pc = target;
                break;
            }

            case HY_OP_GETSTATIC: {
                const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32()];
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
                break;
            }
            case HY_OP_PUTSTATIC: {
                const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32()];
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
                break;
            }
            case HY_OP_GETFIELD: {
                const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32()];
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
                    case 7: { float rv = env->GetFloatField(obj, fid); memcpy(&fval, &rv, 4); break; }
                    case 8: { double rv = env->GetDoubleField(obj, fid); memcpy(&fval, &rv, 8); fcat = 2; break; }
                    default: fobj = env->GetObjectField(obj, fid); is_o = true; break;
                }
                clear_stk_slot(--sp);
                if (is_o) push_ref(fobj, true);
                else stk[sp++] = {fval, -1, fcat, 0};
                break;
            }
            case HY_OP_PUTFIELD: {
                const VmFieldMeta& fm = g_vm_fields[mm.field_off + (uint32_t)rd_i32()];
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
                clear_stk_slot(os);
                break;
            }

            case HY_OP_INVOKE_STATIC: {
                bool threw = false;
                const VmCallMeta& cm = g_vm_calls[mm.call_off + (uint32_t)rd_i32()];
                vm_invoke_helper(env, cm, stk, sp, refs, true, false, threw);
                if (threw && !handle_exception()) { cleanup(); return 0; }
                break;
            }
            case HY_OP_INVOKE_VIRTUAL:
            case HY_OP_INVOKE_INTERFACE: {
                bool threw = false;
                const VmCallMeta& cm = g_vm_calls[mm.call_off + (uint32_t)rd_i32()];
                vm_invoke_helper(env, cm, stk, sp, refs, false, false, threw);
                if (threw && !handle_exception()) { cleanup(); return 0; }
                break;
            }
            case HY_OP_INVOKE_SPECIAL: {
                bool threw = false;
                const VmCallMeta& cm = g_vm_calls[mm.call_off + (uint32_t)rd_i32()];
                vm_invoke_helper(env, cm, stk, sp, refs, false, true, threw);
                if (threw && !handle_exception()) { cleanup(); return 0; }
                break;
            }

            case HY_OP_STRING_CONCAT: {
                const VmConcatMeta& cc = g_vm_concats[mm.concat_off + (uint32_t)rd_i32()];
                int32_t base = sp - cc.arg_cnt;
                ConcatArg cargs_stk[16];
                ConcatArg* cargs = cc.arg_cnt <= 16 ? cargs_stk : (ConcatArg*)heap_alloc((size_t)cc.arg_cnt * sizeof(ConcatArg));
                for (uint16_t k = 0; k < cc.arg_cnt; k++) {
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
                if (cargs != cargs_stk) heap_free(cargs);
                if (env->ExceptionCheck()) { if (js) env->DeleteLocalRef(js); if (!handle_exception()) { cleanup(); return 0; } break; }
                while (sp > base) clear_stk_slot(--sp);
                push_ref(js, true);
                break;
            }

            case HY_OP_NEW_ALLOC: {
                jclass c = resolve_class(env, rd_i32());
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                jobject o = env->AllocObject(c);
                if (env->ExceptionCheck()) { if (o) env->DeleteLocalRef(o); if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(o, true);
                break;
            }
            case HY_OP_NEWARRAY: {
                uint8_t at = rd_u8();
                int32_t len = as_i32(--sp);
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
                push_ref(a, true);
                break;
            }
            case HY_OP_ANEWARRAY: {
                int32_t cid = rd_i32();
                int32_t len = as_i32(--sp);
                if (len < 0) { throw_neg_arr(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                jclass ec = resolve_class(env, cid);
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                jobjectArray a = env->NewObjectArray(len, ec, nullptr);
                if (env->ExceptionCheck()) { if (a) env->DeleteLocalRef(a); if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(a, true);
                break;
            }
            case HY_OP_MULTIANEWARRAY: {
                uint8_t dims = rd_u8();
                int32_t dvals_stk[16], cids_stk[16];
                int32_t* dvals = dims <= 16 ? dvals_stk : (int32_t*)heap_alloc((size_t)dims * sizeof(int32_t));
                int32_t* cids = dims <= 16 ? cids_stk : (int32_t*)heap_alloc((size_t)dims * sizeof(int32_t));
                for (int32_t d = 0; d < dims; d++) cids[d] = rd_i32();
                uint8_t elem_kind = rd_u8();
                for (int32_t d = dims - 1; d >= 0; d--) dvals[d] = as_i32(--sp);
                jobject marr = new_multi_array(env, cids, dvals, (int32_t)dims, (int32_t)elem_kind);
                if (dvals != dvals_stk) heap_free(dvals);
                if (cids != cids_stk) heap_free(cids);
                if (env->ExceptionCheck()) { if (marr) env->DeleteLocalRef(marr); if (!handle_exception()) { cleanup(); return 0; } break; }
                push_ref(marr, true);
                break;
            }
            case HY_OP_ARRAYLENGTH: {
                jarray a = (jarray)refs.raw(stk[sp - 1].r);
                if (!a) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                int32_t len = (int32_t)env->GetArrayLength(a);
                clear_stk_slot(--sp);
                push_i32(len);
                break;
            }
            case HY_OP_ARR_LOAD: {
                uint8_t k = rd_u8();
                int32_t idx = as_i32(--sp);
                jarray a = (jarray)refs.raw(stk[sp - 1].r);
                if (!a) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                if (k == 9) {
                    jobject el = env->GetObjectArrayElement((jobjectArray)a, idx);
                    if (env->ExceptionCheck()) { if (el) env->DeleteLocalRef(el); if (!handle_exception()) { cleanup(); return 0; } break; }
                    clear_stk_slot(--sp);
                    push_ref(el, true);
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
                        case 7: { jfloat v = 0; env->GetFloatArrayRegion((jfloatArray)a, idx, 1, &v); uint32_t b = 0; memcpy(&b, &v, 4); val = b; break; }
                        default: { jdouble v = 0; env->GetDoubleArrayRegion((jdoubleArray)a, idx, 1, &v); memcpy(&val, &v, 8); cat = 2; break; }
                    }
                    if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                    clear_stk_slot(--sp);
                    stk[sp++] = {val, -1, cat, 0};
                }
                break;
            }
            case HY_OP_ARR_STORE: {
                uint8_t k = rd_u8();
                int32_t vs = --sp;
                int32_t idx = as_i32(--sp);
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
                clear_stk_slot(--sp);
                break;
            }
            case HY_OP_CHECKCAST: {
                int32_t cid = rd_i32();
                jobject o = refs.raw(stk[sp - 1].r);
                if (o != nullptr) {
                    jclass c = resolve_class(env, cid);
                    if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                    if (!env->IsInstanceOf(o, c)) { throw_cce(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                }
                break;
            }
            case HY_OP_INSTANCEOF: {
                int32_t cid = rd_i32();
                jobject o = refs.raw(stk[sp - 1].r);
                int32_t res = 0;
                if (o != nullptr) {
                    jclass c = resolve_class(env, cid);
                    if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } break; }
                    res = env->IsInstanceOf(o, c) ? 1 : 0;
                }
                clear_stk_slot(--sp);
                push_i32(res);
                break;
            }
            case HY_OP_MONITORENTER: {
                jobject o = refs.raw(stk[sp - 1].r);
                if (!o) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                env->MonitorEnter(o);
                clear_stk_slot(--sp);
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } }
                break;
            }
            case HY_OP_MONITOREXIT: {
                jobject o = refs.raw(stk[sp - 1].r);
                if (!o) { throw_npe(env); if (!handle_exception()) { cleanup(); return 0; } break; }
                env->MonitorExit(o);
                clear_stk_slot(--sp);
                if (env->ExceptionCheck()) { if (!handle_exception()) { cleanup(); return 0; } }
                break;
            }
            case HY_OP_ATHROW: {
                jthrowable ex = (jthrowable)refs.raw(stk[sp - 1].r);
                if (!ex) throw_npe(env);
                else env->Throw(ex);
                clear_stk_slot(--sp);
                if (!handle_exception()) { cleanup(); return 0; }
                break;
            }
            case HY_OP_RET_VOID: cleanup(); return 0;
            case HY_OP_RET_I32: { uint64_t r = (uint64_t)(uint32_t)as_i32(sp - 1); cleanup(); return r; }
            case HY_OP_RET_I64: { uint64_t r = stk[sp - 1].u; cleanup(); return r; }
            case HY_OP_RET_F32: { uint64_t r = (uint64_t)(uint32_t)stk[sp - 1].u; cleanup(); return r; }
            case HY_OP_RET_F64: { uint64_t r = stk[sp - 1].u; cleanup(); return r; }
            case HY_OP_RET_REF: { if (out_ref) *out_ref = refs.detach_return(stk[sp - 1].r); cleanup(); return 0; }
            HY_VM_TRAP_CASES
            default: g_tampered = 1; cleanup(); return 0;
        }
    }
#endif
    cleanup();
    return 0;
}

} // namespace hy
