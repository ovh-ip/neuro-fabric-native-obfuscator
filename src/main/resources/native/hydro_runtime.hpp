#pragma once

#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include <string.h>

#if defined(__has_include)
#if __has_include("hydro_build_cfg.hpp")
#include "hydro_build_cfg.hpp"
#endif
#else
#include "hydro_build_cfg.hpp"
#endif

// Fallback definitions for standalone IDE linting when hydro_build_cfg.hpp has not been generated yet
#ifndef HY_ENABLE_ANTI_DEBUG
#define HY_ENABLE_ANTI_DEBUG 0
#define HY_ENABLE_ANTI_DUMP 0
#define HY_ENABLE_ANTI_TAMPER 0
#define HY_VERIFY_JAR 0
#define HY_HAS_FUCKED 0
#define HY_INITIAL_JAR_VERIFIED 1
#define HY_ENABLE_SERVER 0
#define HY_HAS_BAKED_LIC 0
#define HY_SRV_HB_SEC 15
#define HY_VERIFY_TAG 0ULL
#define HY_MBA_MASTER_SEED(op) ((uint64_t)(op ^ op))
#define HY_MBA_HASH_BASIS(op) 0xCBF29CE484222325ULL
#define HY_MBA_HASH_PRIME(op) 0x100000001B3ULL
#define HY_MBA_TAG_SALT(op) 0ULL
#define HY_MBA_VAULT_SALT(op) 0ULL
#define HY_MBA_PUBKEY_MASK(op) 0ULL
#define HY_MBA_EFFECTIVE_KEY(op) ((uint64_t)((op) ^ (op)))
#define HY_MBA_VM_MIX_CONST(op) 0ULL
#define HY_MBA_VM_MIX_MUL(op) 1ULL
#define HY_MBA_VM_DISP_MUL(op) 1u
#define HY_MBA_VM_DISP_XOR(op) 0u
#define HY_MBA_SESS_ALIVE_MAGIC(op) 0x6A09E667F3BCC909ULL

#define HY_HASH_KERNEL32 0u
#define HY_HASH_NTDLL 0u
#define HY_HASH_JVM 0u
#define HY_HASH_ISDBG 0u
#define HY_HASH_NTQIP 0u
#define HY_HASH_GETCTX 0u
#define HY_HASH_CURTHR 0u
#define HY_HASH_CURPROC 0u
#define HY_HASH_TERMPROC 0u
#define HY_HASH_LOADLIB 0u
#define HY_HASH_VIRTUALQUERY 0u
#define HY_HASH_NTSETINFOTHREAD 0u
#define HY_HASH_BCRYPT 0u
#define HY_HASH_ADVAPI32 0u
#define HY_HASH_WINHTTP 0u
#define HY_HASH_BCRYPT_GEN 0u
#define HY_HASH_REG_OPEN 0u
#define HY_HASH_REG_QUERY 0u
#define HY_HASH_REG_CLOSE 0u
#define HY_HASH_WH_OPEN 0u
#define HY_HASH_WH_CONN 0u
#define HY_HASH_WH_REQ 0u
#define HY_HASH_WH_TIME 0u
#define HY_HASH_WH_SEND 0u
#define HY_HASH_WH_RECV 0u
#define HY_HASH_WH_HDR 0u
#define HY_HASH_WH_AVAIL 0u
#define HY_HASH_WH_READ 0u
#define HY_HASH_WH_CLOSE 0u
#define HY_HASH_FRIDA_AGENT 0u
#define HY_HASH_FRIDA_GADGET 0u
#define HY_HASH_X64DBG 0u
#define HY_HASH_SCYLLA 0u
#define HY_HASH_VEHDBG 0u
#define HY_HASH_FRIDA_CORE 0u
#define HY_HASH_VEHDBG32 0u
#define HY_HASH_CE64 0u
#define HY_HASH_TITAN 0u
#define HY_HASH_SHARPOD 0u
#define HY_HASH_MINHOOK64 0u
#define HY_HASH_CREATEFILEA 0u
#define HY_HASH_READFILE 0u
#define HY_HASH_CLOSEHANDLE 0u

#define HY_SYM_CLASS 0u
#define HY_SYM_FORNAME 0u
#define HY_SYM_FORNAME_DESC 0u
#define HY_SYM_NPE 0u
#define HY_SYM_ARITH 0u
#define HY_SYM_NEGARR 0u
#define HY_SYM_CCE 0u
#define HY_SYM_AIOOBE 0u
#define HY_SYM_SB 0u
#define HY_SYM_SB_INIT 0u
#define HY_SYM_SB_INIT_DESC 0u
#define HY_SYM_SB_APP_STR 0u
#define HY_SYM_SB_APP_STR_DESC 0u
#define HY_SYM_SB_APP_OBJ_DESC 0u
#define HY_SYM_SB_APP_INT_DESC 0u
#define HY_SYM_SB_APP_LONG_DESC 0u
#define HY_SYM_SB_APP_FLOAT_DESC 0u
#define HY_SYM_SB_APP_DOUBLE_DESC 0u
#define HY_SYM_SB_APP_BOOL_DESC 0u
#define HY_SYM_SB_APP_CHAR_DESC 0u
#define HY_SYM_TOSTR 0u
#define HY_SYM_TOSTR_DESC 0u
#define HY_SYM_BOOL_ARR 0u
#define HY_SYM_OBJ 0u
#define HY_SYM_LOADER 0u
#define HY_SYM_REG_NAME 0u
#define HY_SYM_REG_DESC 0u
#define HY_SYM_VER_NAME 0u
#define HY_SYM_VER_DESC 0u
#define HY_SYM_INT_CLS 0u
#define HY_SYM_LONG_CLS 0u
#define HY_SYM_FLOAT_CLS 0u
#define HY_SYM_DOUBLE_CLS 0u
#define HY_SYM_BOOL_CLS 0u
#define HY_SYM_BYTE_CLS 0u
#define HY_SYM_CHAR_CLS 0u
#define HY_SYM_SHORT_CLS 0u
#define HY_SYM_VOID_CLS 0u
#define HY_SYM_TYPE_FIELD 0u
#define HY_SYM_CLS_FIELD_DESC 0u
#define HY_SYM_DIV_ZERO_MSG 0u
#define HY_SYM_CL 0u
#define HY_SYM_GETRES 0u
#define HY_SYM_GETRES_DESC 0u
#define HY_SYM_GETRES_URL 0u
#define HY_SYM_GETRES_URL_DESC 0u
#define HY_SYM_GETRES_ENUM 0u
#define HY_SYM_GETRES_ENUM_DESC 0u
#define HY_SYM_URL_CLS 0u
#define HY_SYM_URL_OPEN 0u
#define HY_SYM_URL_OPEN_DESC 0u
#define HY_SYM_ENUM_CLS 0u
#define HY_SYM_HAS_MORE 0u
#define HY_SYM_HAS_MORE_DESC 0u
#define HY_SYM_NEXT_ELEM 0u
#define HY_SYM_NEXT_ELEM_DESC 0u
#define HY_SYM_STR_CLS 0u
#define HY_SYM_ENDS_WITH 0u
#define HY_SYM_STARTS_WITH 0u
#define HY_SYM_BOOL_STR_DESC 0u
#define HY_SYM_SUBSTR 0u
#define HY_SYM_SUBSTR_DESC 0u
#define HY_SYM_STR_LEN 0u
#define HY_SYM_INT_VOID_DESC 0u
#define HY_SYM_LOADER_RES 0u
#define HY_SYM_LOADER_TAIL 0u
#define HY_SYM_IS 0u
#define HY_SYM_IS_READ 0u
#define HY_SYM_IS_READ_DESC 0u
#define HY_SYM_IS_CLOSE 0u
#define HY_SYM_JDWP 0u
#define HY_SYM_XRUNJDWP 0u
#define HY_SYM_PROC_STATUS 0u
#define HY_SYM_TRACER_PID 0u
#define HY_SYM_PROC_CMD 0u
#define HY_SYM_LIBJVM 0u
#define HY_SYM_REG_CRYPTO 0u
#define HY_SYM_MACHINE_GUID 0u
#define HY_SYM_SYS_CLS 0u
#define HY_SYM_GET_PROP 0u
#define HY_SYM_GET_PROP_DESC 0u
#define HY_SYM_PROP_KEY 0u
#define HY_SYM_ENV_KEY 0u
#define HY_SYM_LIC_FILE 0u
#define HY_SYM_BAKED_LIC 0u
#define HY_SYM_PRODUCT_ID 0u
#define HY_SYM_BUILD_ID 0u
#define HY_SYM_SRV_URL 0u
#define HY_SYM_SEC_EX 0u
#define HY_SYM_SEC_MSG 0u
#define HY_SYM_BCRYPT_DLL 0u
#define HY_SYM_ADVAPI32_DLL 0u
#define HY_SYM_WINHTTP_DLL 0u
#define HY_SYM_DRIVE_C 0u
#define HY_SYM_UA 0u
#define HY_SYM_CTYPE 0u
#define HY_SYM_EP_HS 0u
#define HY_SYM_EP_HB 0u
#define HY_SYM_HWID_TAG 0u
#define HY_SYM_HS_PFX 0u
#define HY_SYM_SESS_PFX 0u
#define HY_SYM_J_SESS 0u
#define HY_SYM_J_SEPH 0u
#define HY_SYM_J_SNONCE 0u
#define HY_SYM_J_NONCE 0u
#define HY_SYM_J_CT 0u
#define HY_SYM_J_MAC 0u
#define HY_SYM_EP_LO 0u
#define HY_SYM_REQ_E2 0u
#define HY_SYM_REQ_M2 0u
#define HY_SYM_HBQ_PFX 0u
#define HY_SYM_HB_PFX 0u
#define HY_SYM_LOQ_PFX 0u
#define HY_SYM_LO_PFX 0u

#define HY_OP_NOP 0
#define HY_OP_CONST_I32 1
#define HY_OP_CONST_I64 2
#define HY_OP_CONST_F32 3
#define HY_OP_CONST_F64 4
#define HY_OP_CONST_NULL 5
#define HY_OP_CONST_STR 6
#define HY_OP_CONST_CLS 7
#define HY_OP_CONST_PRIM_CLS 8
#define HY_OP_LOAD_P 9
#define HY_OP_STORE_P 10
#define HY_OP_LOAD_R 11
#define HY_OP_STORE_R 12
#define HY_OP_IINC 13
#define HY_OP_POP1 14
#define HY_OP_POP2 15
#define HY_OP_DUP1 16
#define HY_OP_DUP_X1 17
#define HY_OP_DUP_X2 18
#define HY_OP_DUP2 19
#define HY_OP_DUP2_X1 20
#define HY_OP_DUP2_X2 21
#define HY_OP_SWAP 22
#define HY_OP_IADD 23
#define HY_OP_ISUB 24
#define HY_OP_IMUL 25
#define HY_OP_IDIV 26
#define HY_OP_IREM 27
#define HY_OP_INEG 28
#define HY_OP_ISHL 29
#define HY_OP_ISHR 30
#define HY_OP_IUSHR 31
#define HY_OP_IAND 32
#define HY_OP_IOR 33
#define HY_OP_IXOR 34
#define HY_OP_LADD 35
#define HY_OP_LSUB 36
#define HY_OP_LMUL 37
#define HY_OP_LDIV 38
#define HY_OP_LREM 39
#define HY_OP_LNEG 40
#define HY_OP_LSHL 41
#define HY_OP_LSHR 42
#define HY_OP_LUSHR 43
#define HY_OP_LAND 44
#define HY_OP_LOR 45
#define HY_OP_LXOR 46
#define HY_OP_FADD 47
#define HY_OP_FSUB 48
#define HY_OP_FMUL 49
#define HY_OP_FDIV 50
#define HY_OP_FREM 51
#define HY_OP_FNEG 52
#define HY_OP_DADD 53
#define HY_OP_DSUB 54
#define HY_OP_DMUL 55
#define HY_OP_DDIV 56
#define HY_OP_DREM 57
#define HY_OP_DNEG 58
#define HY_OP_I2L 59
#define HY_OP_I2F 60
#define HY_OP_I2D 61
#define HY_OP_L2I 62
#define HY_OP_L2F 63
#define HY_OP_L2D 64
#define HY_OP_F2I 65
#define HY_OP_F2L 66
#define HY_OP_F2D 67
#define HY_OP_D2I 68
#define HY_OP_D2L 69
#define HY_OP_D2F 70
#define HY_OP_I2B 71
#define HY_OP_I2C 72
#define HY_OP_I2S 73
#define HY_OP_LCMP 74
#define HY_OP_FCMPL 75
#define HY_OP_FCMPG 76
#define HY_OP_DCMPL 77
#define HY_OP_DCMPG 78
#define HY_OP_JMP 79
#define HY_OP_IF_ZERO 80
#define HY_OP_IF_NEZ 81
#define HY_OP_IF_LTZ 82
#define HY_OP_IF_GEZ 83
#define HY_OP_IF_GTZ 84
#define HY_OP_IF_LEZ 85
#define HY_OP_IF_ICMPEQ 86
#define HY_OP_IF_ICMPNE 87
#define HY_OP_IF_ICMPLT 88
#define HY_OP_IF_ICMPGE 89
#define HY_OP_IF_ICMPGT 90
#define HY_OP_IF_ICMPLE 91
#define HY_OP_IF_ACMPEQ 92
#define HY_OP_IF_ACMPNE 93
#define HY_OP_IF_NULL 94
#define HY_OP_IF_NONNULL 95
#define HY_OP_SWITCH_TABLE 96
#define HY_OP_SWITCH_LOOKUP 97
#define HY_OP_GETSTATIC 98
#define HY_OP_PUTSTATIC 99
#define HY_OP_GETFIELD 100
#define HY_OP_PUTFIELD 101
#define HY_OP_INVOKE_STATIC 102
#define HY_OP_INVOKE_VIRTUAL 103
#define HY_OP_INVOKE_SPECIAL 104
#define HY_OP_INVOKE_INTERFACE 105
#define HY_OP_STRING_CONCAT 106
#define HY_OP_NEW_ALLOC 107
#define HY_OP_NEWARRAY 108
#define HY_OP_ANEWARRAY 109
#define HY_OP_MULTIANEWARRAY 110
#define HY_OP_ARRAYLENGTH 111
#define HY_OP_ARR_LOAD 112
#define HY_OP_ARR_STORE 113
#define HY_OP_CHECKCAST 114
#define HY_OP_INSTANCEOF 115
#define HY_OP_MONITORENTER 116
#define HY_OP_MONITOREXIT 117
#define HY_OP_ATHROW 118
#define HY_OP_RET_VOID 119
#define HY_OP_RET_I32 120
#define HY_OP_RET_I64 121
#define HY_OP_RET_F32 122
#define HY_OP_RET_F64 123
#define HY_OP_RET_REF 124
#define HY_VM_TRAP_CASES
#endif

#if defined(_MSC_VER)
#define HY_USED
#define HY_FORCEINLINE __forceinline
#else
#define HY_USED __attribute__((used))
#define HY_FORCEINLINE inline __attribute__((always_inline))
#endif

extern "C" {
struct HySealBox {
    volatile uint64_t magic;
    volatile uint64_t hash;
};
extern volatile HySealBox g_hydro_seal_box;
}

namespace hy {

struct SymMeta { uint32_t off; uint32_t len; };
struct WStrMeta { uint32_t off; uint32_t len; };
struct MemberMeta { uint32_t cls_id; uint32_t name_sym; uint32_t desc_sym; };
struct RegMethodMeta { uint32_t name_sym; uint32_t desc_sym; void* fn; };
struct RegClassMeta { int32_t class_id; uint32_t cls_sym; uint32_t start; uint32_t count; };
struct FuckedMeta { uint32_t cls_sym; uint32_t path_sym; uint32_t raw_len; uint64_t seed; uint64_t mac; };

struct VmTryEntry { uint32_t start_pc; uint32_t end_pc; uint32_t handler_pc; int32_t catch_cls; };
struct VmCallMeta { int32_t member_id; uint8_t ret_kind; uint16_t arg_off; uint16_t arg_cnt; };
struct VmFieldMeta { int32_t member_id; uint8_t field_kind; };
struct VmConcatMeta { int32_t recipe_wid; uint16_t const_off; uint16_t const_cnt; uint16_t arg_off; uint16_t arg_cnt; };
struct VmMethodMeta {
    uint32_t code_off;
    uint32_t code_len;
    uint64_t method_salt;
    uint8_t op_mask;
    uint8_t pc_mul;
    uint16_t max_stack;
    uint16_t max_locals;
    uint32_t try_off;
    uint32_t try_cnt;
    uint32_t call_off;
    uint32_t field_off;
    uint32_t concat_off;
};

// Runtime global state (defined across hydro_tables.cpp / hydro_memory.cpp / hydro_jni_bridge.cpp)
extern volatile uint64_t g_rt_entropy;
extern uintptr_t g_ptr_cookie;
extern volatile uint64_t g_vm_key_masked;
extern volatile int32_t g_tampered;
extern volatile int32_t g_jar_verified;
extern jobject g_mod_loader;

extern const uint8_t g_sym_blob[];
extern const uint32_t g_sym_blob_size;
extern const SymMeta g_sym_meta[];
extern const uint16_t g_wstr_blob[];
extern const WStrMeta g_wstr_meta[];

extern const uint32_t g_cls_syms[];
extern uintptr_t g_cls_cache[];
extern const MemberMeta g_method_meta[];
extern uintptr_t g_method_cache[];
extern const MemberMeta g_field_meta[];
extern uintptr_t g_field_cache[];

extern const RegMethodMeta g_reg_methods[];
extern const RegClassMeta g_reg_classes[];
extern const uint32_t g_reg_class_count;

extern const FuckedMeta g_fucked_entries[];
extern const uint32_t g_fucked_count;
extern const uint32_t g_verify_res_syms[];
extern const uint32_t g_verify_res_count;
extern const uint8_t g_srv_pubkey_masked[32];
extern volatile uint64_t g_srv_dyn_params[8];
extern volatile uint64_t g_sess_state_masked;
extern volatile uint64_t g_sess_deadline_masked;
extern volatile uint64_t g_hb_pulse_masked;
extern volatile uint64_t g_hb_silence_limit_ms;

extern const uint8_t g_vm_code[];
extern const int32_t g_vm_call_ak[];
extern const int32_t g_vm_cnc_consts[];
extern const int32_t g_vm_cnc_ak[];
extern const VmTryEntry g_vm_tries[];
extern const VmCallMeta g_vm_calls[];
extern const VmFieldMeta g_vm_fields[];
extern const VmConcatMeta g_vm_concats[];
extern const VmMethodMeta g_vm_methods[];

// Cached JVM bootstrap classes & methods
extern jclass g_cls_class;
extern jmethodID g_mid_forName;
extern jclass g_cls_sb;
extern jmethodID g_mid_sb_init;
extern jmethodID g_mid_sb_app_str;
extern jmethodID g_mid_sb_app_obj;
extern jmethodID g_mid_sb_app_i;
extern jmethodID g_mid_sb_app_j;
extern jmethodID g_mid_sb_app_f;
extern jmethodID g_mid_sb_app_d;
extern jmethodID g_mid_sb_app_z;
extern jmethodID g_mid_sb_app_c;
extern jmethodID g_mid_toString;
extern jclass g_cls_bool_arr;
extern jclass g_cls_obj;
extern jclass g_cls_npe;
extern jclass g_cls_arith;
extern jclass g_cls_negarr;
extern jclass g_cls_cce;
extern jclass g_cls_aioobe;

HY_FORCEINLINE uint64_t opaque_seed() {
    uint64_t v = g_rt_entropy;
    v ^= (v << 13);
    v ^= (v >> 7);
    return v | 1ULL;
}

HY_FORCEINLINE uint64_t splitmix64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

inline uint64_t hy_tick() {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return __rdtsc();
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v = 0;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return ((uint64_t)(uintptr_t)&g_rt_entropy) ^ 0x9E3779B97F4A7C15ULL;
#endif
}

HY_FORCEINLINE float bits_to_f32(uint32_t u) {
    float f = 0.0f;
    memcpy(&f, &u, sizeof(f));
    return f;
}

HY_FORCEINLINE double bits_to_f64(uint64_t u) {
    double d = 0.0;
    memcpy(&d, &u, sizeof(d));
    return d;
}

inline int32_t j_popcnt32(uint32_t x) {
    x = x - ((x >> 1) & 0x55555555u);
    x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
    return (int32_t)((((x + (x >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24);
}

inline int32_t j_popcnt64(uint64_t x) {
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (int32_t)((x * 0x0101010101010101ULL) >> 56);
}

inline int32_t j_clz32(uint32_t x) {
    if (x == 0u) return 32;
    int32_t n = 0;
    if ((x & 0xFFFF0000u) == 0u) { n += 16; x <<= 16; }
    if ((x & 0xFF000000u) == 0u) { n += 8; x <<= 8; }
    if ((x & 0xF0000000u) == 0u) { n += 4; x <<= 4; }
    if ((x & 0xC0000000u) == 0u) { n += 2; x <<= 2; }
    if ((x & 0x80000000u) == 0u) { n += 1; }
    return n;
}

inline int32_t j_ctz32(uint32_t x) {
    if (x == 0u) return 32;
    int32_t n = 0;
    if ((x & 0x0000FFFFu) == 0u) { n += 16; x >>= 16; }
    if ((x & 0x000000FFu) == 0u) { n += 8; x >>= 8; }
    if ((x & 0x0000000Fu) == 0u) { n += 4; x >>= 4; }
    if ((x & 0x00000003u) == 0u) { n += 2; x >>= 2; }
    if ((x & 0x00000001u) == 0u) { n += 1; }
    return n;
}

inline uint32_t j_bswap32(uint32_t x) {
    return ((x & 0x000000FFu) << 24)
         | ((x & 0x0000FF00u) << 8)
         | ((x & 0x00FF0000u) >> 8)
         | ((x & 0xFF000000u) >> 24);
}

inline uint64_t j_bswap64(uint64_t x) {
    return ((uint64_t)j_bswap32((uint32_t)(x & 0xFFFFFFFFULL)) << 32)
         | (uint64_t)j_bswap32((uint32_t)(x >> 32));
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

inline float j_frem(float a, float b) { return fmodf(a, b); }
inline double j_drem(double a, double b) { return fmod(a, b); }

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

HY_FORCEINLINE void secure_wipe(void* p, size_t n) {
    volatile uint8_t* vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
}

struct SymBuf {
    char stk[512];
    char* ptr;
    uint32_t cap;

    SymBuf() : ptr(stk), cap(512) { stk[0] = '\0'; }

    ~SymBuf() {
        secure_wipe(ptr, cap);
        if (ptr != stk) heap_free(ptr);
    }

    SymBuf(const SymBuf&) = delete;
    SymBuf& operator=(const SymBuf&) = delete;

    char* ensure(uint32_t need) {
        uint32_t n = need < 2u ? 2u : need;
        if (n <= cap) [[likely]] return ptr;
        char* mem = (char*)heap_alloc((size_t)n);
        if (ptr != stk) {
            secure_wipe(ptr, cap);
            heap_free(ptr);
        }
        ptr = mem;
        cap = n;
        return ptr;
    }
};

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

    HY_FORCEINLINE RefSlot& at(int32_t idx) {
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

    HY_FORCEINLINE int32_t retain(int32_t idx) {
        if (idx >= 0) at(idx).rc++;
        return idx;
    }

    HY_FORCEINLINE void release(int32_t idx) {
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

    HY_FORCEINLINE jobject raw(int32_t idx) {
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
            memcpy(mem, overflow, (size_t)overflow_cap * sizeof(RefSlot));
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

char* decrypt_sym(uint32_t id, SymBuf& sb);
jclass find_class_by_sym(JNIEnv* env, uint32_t sym_id);
jclass resolve_class(JNIEnv* env, int32_t cls_id);
jclass resolve_prim_class(JNIEnv* env, int32_t kind);
jmethodID resolve_imethod(JNIEnv* env, int32_t mid_id);
jmethodID resolve_smethod(JNIEnv* env, int32_t mid_id);
jfieldID resolve_ifield(JNIEnv* env, int32_t fid_id);
jfieldID resolve_sfield(JNIEnv* env, int32_t fid_id);
jclass resolve_field_owner(JNIEnv* env, int32_t fid_id);
jclass resolve_method_owner(JNIEnv* env, int32_t mid_id);
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

void poison_cookie();
void init_code_integrity();
void hide_current_thread();
uintptr_t find_module_base(uint32_t mod_hash, uint32_t* out_img_size = nullptr);
void* resolve_export(uintptr_t mod_base, uint32_t fn_hash);
uintptr_t load_sys_module(uint32_t mod_hash, uint32_t mod_sym);
bool has_inline_hook(const void* fn);
void run_security_checks(JNIEnv* env);
void run_periodic_vm_guard();
void destroy_session_keys();
bool verify_session_window();
bool check_session_alive();
void server_logout();
bool server_handshake(JNIEnv* env, uint64_t jar_digest, uint64_t* out_vm_share, uint64_t* out_vault_share);
uint64_t vm_exec_core(JNIEnv* env, uint32_t vm_method_id, const uint64_t* init_vals, const uint8_t* init_is_ref, int32_t init_slots, jobject* out_ref);

HY_FORCEINLINE bool inline_session_ok(uint64_t op_seed) {
    if (g_tampered) [[unlikely]] { destroy_session_keys(); return false; }
#if !HY_ENABLE_SERVER
    (void)op_seed;
    return true;
#else
    uint64_t st = __atomic_load_n(&g_sess_state_masked, __ATOMIC_ACQUIRE);
    uint64_t expected = HY_MBA_SESS_ALIVE_MAGIC(op_seed) ^ (uint64_t)g_ptr_cookie;
    if (st != expected) [[unlikely]] {
        destroy_session_keys();
        return false;
    }
    if (!verify_session_window()) [[unlikely]] {
        destroy_session_keys();
        return false;
    }
    return true;
#endif
}

} // namespace hy
