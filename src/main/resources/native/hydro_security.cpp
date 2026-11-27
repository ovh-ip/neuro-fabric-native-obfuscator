#include "hydro_runtime.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#if defined(__APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#endif

namespace hy {

struct CodeSecRange { uintptr_t base; uint32_t size; uint64_t hash_masked; };
static CodeSecRange g_code_secs[4] = {};
static uint32_t g_code_sec_cnt = 0;
static volatile uint32_t g_guard_ticks = 0;
static volatile int32_t g_text_ready = 0;

void poison_cookie() {
    g_tampered = 1;
    g_ptr_cookie ^= 0xDEAD0000BEEF1337ULL;
    g_vm_key_masked ^= 0xBADC0FFEECAFEBABULL;
}

static bool str_icontains(const char* hay, size_t hay_len, const char* pat) {
    if (!hay || !pat || !*pat) return false;
    size_t pn = 0;
    while (pat[pn]) pn++;
    if (hay_len < pn) return false;
    for (size_t i = 0; i <= hay_len - pn; i++) {
        bool ok = true;
        for (size_t j = 0; j < pn; j++) {
            char hc = hay[i + j];
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            char pc = pat[j];
            if (pc >= 'A' && pc <= 'Z') pc += 32;
            if (hc != pc) { ok = false; break; }
        }
        if (ok) return true;
    }
    return false;
}

bool has_inline_hook(const void* fn) {
    if (!fn) return false;
    const uint8_t* b = (const uint8_t*)fn;
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    if (b[0] == 0xCCu || b[0] == 0xE9u || b[0] == 0xEBu || b[0] == 0xF1u) return true;
    if (b[0] == 0xFFu && b[1] == 0x25u) return true; // jmp qword ptr [rip+disp]
    if (b[0] == 0x48u && b[1] == 0xB8u && b[10] == 0xFFu && b[11] == 0xE0u) return true; // movabs rax; jmp rax
#elif defined(__aarch64__) || defined(_M_ARM64)
    uint32_t insn = *(const uint32_t*)b;
    if ((insn & 0xFFE0001Fu) == 0xD4200000u) return true; // BRK #imm
#endif
    return false;
}

#ifdef _WIN32
struct HyUnicodeStr {
    uint16_t Length;
    uint16_t MaxLength;
    uint32_t Pad;
    wchar_t* Buffer;
};

struct HyListEntry {
    HyListEntry* Flink;
    HyListEntry* Blink;
};

static inline uint32_t fnv1a_ascii(const char* s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) { h ^= (uint8_t)(*s++); h *= 0x01000193u; }
    return h;
}

static inline uint32_t fnv1a_ascii_lower(const char* s) {
    uint32_t h = 0x811c9dc5u;
    while (*s) {
        char c = *s++;
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= (uint8_t)c;
        h *= 0x01000193u;
    }
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
#if defined(__x86_64__) || defined(_M_X64)
    uint64_t p = 0;
#if defined(_MSC_VER)
    p = __readgsqword(0x60);
#else
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
#endif
    return (uint8_t*)(uintptr_t)p;
#elif defined(__i386__) || defined(_M_IX86)
    uint32_t p = 0;
#if defined(_MSC_VER)
    p = __readfsdword(0x30);
#else
    __asm__ volatile("movl %%fs:0x30, %0" : "=r"(p));
#endif
    return (uint8_t*)(uintptr_t)p;
#else
    return nullptr;
#endif
}

uintptr_t find_module_base(uint32_t mod_hash, uint32_t* out_img_size) {
    uint8_t* peb = get_peb();
    if (!peb) return 0;
#if defined(__x86_64__) || defined(_M_X64)
    uint8_t* ldr = *(uint8_t**)(peb + 0x18);
    if (!ldr) return 0;
    HyListEntry* head = (HyListEntry*)(ldr + 0x20);
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
#endif
    return 0;
}

static void* resolve_export_impl(uintptr_t mod_base, uint32_t fn_hash, int depth) {
    if (!mod_base || depth > 4) return nullptr;
    auto* dos = (const IMAGE_DOS_HEADER*)mod_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = (const IMAGE_NT_HEADERS*)(mod_base + dos->e_lfanew);
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
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
                const char* fwd = (const char*)(mod_base + rva);
                int dot = -1;
                for (int k = 0; fwd[k] && k < 120; k++) {
                    if (fwd[k] == '.') { dot = k; break; }
                }
                if (dot <= 0) return nullptr;
                char dll[128];
                for (int k = 0; k < dot; k++) dll[k] = fwd[k];
                dll[dot] = '\0';
                bool has_dll = dot >= 4
                    && (dll[dot - 4] == '.')
                    && (dll[dot - 3] == 'd' || dll[dot - 3] == 'D')
                    && (dll[dot - 2] == 'l' || dll[dot - 2] == 'L')
                    && (dll[dot - 1] == 'l' || dll[dot - 1] == 'L');
                if (!has_dll && dot + 4 < 127) {
                    dll[dot] = '.'; dll[dot + 1] = 'd'; dll[dot + 2] = 'l'; dll[dot + 3] = 'l'; dll[dot + 4] = '\0';
                }
                uintptr_t target = find_module_base(fnv1a_ascii_lower(dll), nullptr);
                if (!target) {
                    uintptr_t k32 = find_module_base(HY_HASH_KERNEL32, nullptr);
                    using FnLoadLibA = HMODULE(WINAPI*)(const char*);
                    auto pLL = (FnLoadLibA)resolve_export_impl(k32, HY_HASH_LOADLIB, depth + 1);
                    if (pLL) target = (uintptr_t)pLL(dll);
                }
                if (!target) return nullptr;
                const char* fn = fwd + dot + 1;
                if (fn[0] == '#') {
                    uint32_t ord_num = 0;
                    for (const char* q = fn + 1; *q >= '0' && *q <= '9'; q++) {
                        ord_num = ord_num * 10u + (uint32_t)(*q - '0');
                    }
                    auto* td = (const IMAGE_DOS_HEADER*)target;
                    auto* tnt = (const IMAGE_NT_HEADERS*)(target + td->e_lfanew);
                    const auto& tdir = tnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    if (!tdir.VirtualAddress) return nullptr;
                    auto* texp = (const IMAGE_EXPORT_DIRECTORY*)(target + tdir.VirtualAddress);
                    if (ord_num < texp->Base) return nullptr;
                    uint32_t idx = ord_num - texp->Base;
                    if (idx >= texp->NumberOfFunctions) return nullptr;
                    auto* tfuncs = (const uint32_t*)(target + texp->AddressOfFunctions);
                    uint32_t trva = tfuncs[idx];
                    if (trva >= tdir.VirtualAddress && trva < tdir.VirtualAddress + tdir.Size) return nullptr;
                    return (void*)(target + trva);
                }
                return resolve_export_impl(target, fnv1a_ascii(fn), depth + 1);
            }
            return (void*)(mod_base + rva);
        }
    }
    return nullptr;
}

void* resolve_export(uintptr_t mod_base, uint32_t fn_hash) {
    return resolve_export_impl(mod_base, fn_hash, 0);
}

uintptr_t load_sys_module(uint32_t mod_hash, uint32_t mod_sym) {
    uintptr_t existing = find_module_base(mod_hash, nullptr);
    if (existing) return existing;
    uintptr_t k32 = find_module_base(HY_HASH_KERNEL32, nullptr);
    using FnLoadLibA = HMODULE(WINAPI*)(const char*);
    auto pLL = (FnLoadLibA)resolve_export(k32, HY_HASH_LOADLIB);
    if (!pLL) return 0;
    SymBuf sb;
    return (uintptr_t)pLL(decrypt_sym(mod_sym, sb));
}

static bool wstr_icontains_ascii(const wchar_t* ws, uint16_t byteLen, const char* pat) {
    if (!ws || !byteLen || !pat || !*pat) return false;
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

static uint64_t hash_range(uintptr_t addr, uint32_t sz, uint64_t hb, uint64_t hp) {
    const uint8_t* p = (const uint8_t*)addr;
    uint64_t h = hb;
    for (uint32_t i = 0; i < sz; i++) {
        h ^= p[i];
        h *= hp;
    }
    return h;
}
#else
uintptr_t find_module_base(uint32_t, uint32_t*) { return 0; }
void* resolve_export(uintptr_t, uint32_t) { return nullptr; }
uintptr_t load_sys_module(uint32_t, uint32_t) { return 0; }
#endif

void hide_current_thread() {
#if HY_ENABLE_ANTI_DEBUG && defined(_WIN32)
    uintptr_t k32 = find_module_base(HY_HASH_KERNEL32);
    uintptr_t ntd = find_module_base(HY_HASH_NTDLL);
    using FnCurThr = HANDLE(WINAPI*)();
    using FnNtSetThr = LONG(NTAPI*)(HANDLE, uint32_t, void*, uint32_t);
    auto pCT = (FnCurThr)resolve_export(k32, HY_HASH_CURTHR);
    auto pSet = (FnNtSetThr)resolve_export(ntd, HY_HASH_NTSETINFOTHREAD);
    if (pCT && pSet) pSet(pCT(), 0x11u /* ThreadHideFromDebugger */, nullptr, 0u);
#endif
}

void init_code_integrity() {
#if HY_ENABLE_ANTI_TAMPER && defined(_WIN32)
    uintptr_t k32 = find_module_base(HY_HASH_KERNEL32);
    using FnVQ = SIZE_T(WINAPI*)(const void*, MEMORY_BASIC_INFORMATION*, SIZE_T);
    auto pVQ = (FnVQ)resolve_export(k32, HY_HASH_VIRTUALQUERY);
    if (!pVQ) return;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (pVQ((const void*)&init_code_integrity, &mbi, sizeof(mbi)) == 0 || !mbi.AllocationBase) return;
    uintptr_t self_base = (uintptr_t)mbi.AllocationBase;
    auto* dos = (const IMAGE_DOS_HEADER*)self_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = (const IMAGE_NT_HEADERS*)(self_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    const uint64_t _op = opaque_seed();
    uint64_t hb = HY_MBA_HASH_BASIS(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    g_code_sec_cnt = 0;
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections && g_code_sec_cnt < 4u; i++) {
        if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) && sec[i].Misc.VirtualSize > 0) {
            uintptr_t sbase = self_base + sec[i].VirtualAddress;
            uint32_t ssz = sec[i].Misc.VirtualSize;
            uint64_t th = hash_range(sbase, ssz, hb, hp);
            g_code_secs[g_code_sec_cnt++] = { sbase, ssz, th ^ (uint64_t)g_ptr_cookie };
        }
    }
    if (g_code_sec_cnt > 0u) g_text_ready = 1;
#endif
}

static bool has_analysis_module() {
#ifdef _WIN32
    return find_module_base(HY_HASH_FRIDA_AGENT)
        || find_module_base(HY_HASH_FRIDA_GADGET)
        || find_module_base(HY_HASH_FRIDA_CORE)
        || find_module_base(HY_HASH_X64DBG)
        || find_module_base(HY_HASH_SCYLLA)
        || find_module_base(HY_HASH_VEHDBG)
        || find_module_base(HY_HASH_VEHDBG32)
        || find_module_base(HY_HASH_CE64)
        || find_module_base(HY_HASH_TITAN)
        || find_module_base(HY_HASH_SHARPOD)
        || find_module_base(HY_HASH_MINHOOK64);
#else
    return false;
#endif
}

void run_periodic_vm_guard() {
    if (has_inline_hook((const void*)&vm_exec_core)
            || has_inline_hook((const void*)&run_security_checks)
            || has_inline_hook((const void*)&run_periodic_vm_guard)) {
        destroy_session_keys();
        return;
    }
    uint32_t tick = __atomic_fetch_add(&g_guard_ticks, 1u, __ATOMIC_RELAXED);
#if HY_ENABLE_ANTI_DEBUG && defined(_WIN32)
    if ((tick & 3u) == 0u) {
        uint8_t* peb = get_peb();
        if (peb) {
#if defined(__x86_64__) || defined(_M_X64)
            if (peb[2] != 0 || (*(uint32_t*)(peb + 0xBC) & 0x70u)) { destroy_session_keys(); return; }
#endif
        }
        if (has_analysis_module()) { destroy_session_keys(); return; }
    }
#else
    (void)tick;
#endif
#if HY_ENABLE_ANTI_TAMPER
    const uint64_t _op = opaque_seed();
    uint64_t hb = HY_MBA_HASH_BASIS(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    if (g_hydro_seal_box.hash != 0ULL) {
        uint64_t h = hb;
        for (uint32_t i = 0; i < g_sym_blob_size; i++) {
            h ^= g_sym_blob[i];
            h *= hp;
        }
        if (h != g_hydro_seal_box.hash) {
            destroy_session_keys();
            return;
        }
    }
#ifdef _WIN32
    if (g_text_ready && g_code_sec_cnt > 0u) {
        for (uint32_t s = 0; s < g_code_sec_cnt; s++) {
            uint64_t th = hash_range(g_code_secs[s].base, g_code_secs[s].size, hb, hp);
            if ((th ^ (uint64_t)g_ptr_cookie) != g_code_secs[s].hash_masked) {
                destroy_session_keys();
                return;
            }
        }
    }
#endif
#endif
}

void run_security_checks(JNIEnv* env) {
    (void)env;
#if HY_ENABLE_ANTI_DEBUG
    SymBuf sjdwp, sxjdwp;
    const char* p_jdwp = decrypt_sym(HY_SYM_JDWP, sjdwp);
    const char* p_xjdwp = decrypt_sym(HY_SYM_XRUNJDWP, sxjdwp);
#ifdef _WIN32
    uint8_t* peb = get_peb();
    if (peb) {
#if defined(__x86_64__) || defined(_M_X64)
        if (peb[2] != 0) poison_cookie();
        uint32_t ntGlobalFlag = *(uint32_t*)(peb + 0xBC);
        if (ntGlobalFlag & 0x70u) poison_cookie();
        uint8_t* procParams = *(uint8_t**)(peb + 0x20);
        if (procParams) {
            HyUnicodeStr* cmd = (HyUnicodeStr*)(procParams + 0x70);
            if (wstr_icontains_ascii(cmd->Buffer, cmd->Length, p_jdwp)
                    || wstr_icontains_ascii(cmd->Buffer, cmd->Length, p_xjdwp)) {
                poison_cookie();
            }
        }
#endif
    }
    // Check known hook/analysis/debugger modules in PEB (Frida / x64dbg / ScyllaHide / CheatEngine)
    if (has_analysis_module()) {
        poison_cookie();
    }
    uintptr_t k32 = find_module_base(HY_HASH_KERNEL32);
    uintptr_t ntd = find_module_base(HY_HASH_NTDLL);
    using FnIsDbg = BOOL(WINAPI*)();
    using FnNtQip = LONG(NTAPI*)(HANDLE, uint32_t, void*, uint32_t, uint32_t*);
    using FnCurThr = HANDLE(WINAPI*)();
    using FnGetCtx = BOOL(WINAPI*)(HANDLE, CONTEXT*);
    auto pIsDbg = (FnIsDbg)resolve_export(k32, HY_HASH_ISDBG);
    if (pIsDbg && pIsDbg()) poison_cookie();
    auto pNtQip = (FnNtQip)resolve_export(ntd, HY_HASH_NTQIP);
    if (pNtQip) {
        uintptr_t dbgPort = 0;
        if (pNtQip((HANDLE)-1, 7u, &dbgPort, sizeof(dbgPort), nullptr) == 0 && dbgPort != 0) poison_cookie();
        uint32_t dbgFlags = 1;
        if (pNtQip((HANDLE)-1, 0x1Fu, &dbgFlags, sizeof(dbgFlags), nullptr) == 0 && dbgFlags == 0) poison_cookie();
        uintptr_t dbgObj = 0;
        if (pNtQip((HANDLE)-1, 0x1Eu, &dbgObj, sizeof(dbgObj), nullptr) == 0 && dbgObj != 0) poison_cookie();
    }
    auto pCurThr = (FnCurThr)resolve_export(k32, HY_HASH_CURTHR);
    auto pGetCtx = (FnGetCtx)resolve_export(k32, HY_HASH_GETCTX);
    if (pCurThr && pGetCtx) {
#ifdef CONTEXT_DEBUG_REGISTERS
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (pGetCtx(pCurThr(), &ctx) && (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)) poison_cookie();
#endif
    }
#elif defined(__linux__)
    SymBuf sstat, strc, scmd;
    int fd = open(decrypt_sym(HY_SYM_PROC_STATUS, sstat), O_RDONLY);
    if (fd >= 0) {
        char pbuf[2048];
        ssize_t rd = read(fd, pbuf, sizeof(pbuf) - 1);
        close(fd);
        if (rd > 0) {
            pbuf[rd] = '\0';
            const char* tp = decrypt_sym(HY_SYM_TRACER_PID, strc);
            const char* hit = strstr(pbuf, tp);
            if (hit) {
                hit += strlen(tp);
                while (*hit == ' ' || *hit == '\t') hit++;
                if (*hit >= '1' && *hit <= '9') poison_cookie();
            }
        }
    }
    int cfd = open(decrypt_sym(HY_SYM_PROC_CMD, scmd), O_RDONLY);
    if (cfd >= 0) {
        char cbuf[4096];
        ssize_t rd = read(cfd, cbuf, sizeof(cbuf));
        close(cfd);
        if (rd > 0) {
            for (ssize_t i = 0; i < rd; i++) if (cbuf[i] == '\0') cbuf[i] = ' ';
            if (str_icontains(cbuf, (size_t)rd, p_jdwp) || str_icontains(cbuf, (size_t)rd, p_xjdwp)) {
                poison_cookie();
            }
        }
    }
#elif defined(__APPLE__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc kp = {};
    size_t ksz = sizeof(kp);
    if (sysctl(mib, 4, &kp, &ksz, nullptr, 0) == 0) {
        if ((kp.kp_proc.p_flag & 0x00000800) != 0) poison_cookie();
    }
#endif
#endif

#if HY_ENABLE_ANTI_DUMP
#ifdef _WIN32
    uint32_t jvm_sz = 0;
    uintptr_t jvm_base = find_module_base(HY_HASH_JVM, &jvm_sz);
    if (jvm_base && jvm_sz && env && env->functions) {
        uintptr_t pReg = (uintptr_t)env->functions->RegisterNatives;
        uintptr_t pFind = (uintptr_t)env->functions->FindClass;
        if (pReg < jvm_base || pReg >= jvm_base + jvm_sz || pFind < jvm_base || pFind >= jvm_base + jvm_sz) {
            poison_cookie();
        } else if (has_inline_hook((const void*)pReg) || has_inline_hook((const void*)pFind)) {
            poison_cookie();
        }
    }
#else
    if (env && env->functions) {
        Dl_info info = {};
        SymBuf slibjvm;
        const char* lj = decrypt_sym(HY_SYM_LIBJVM, slibjvm);
        if (dladdr((void*)env->functions->RegisterNatives, &info) && info.dli_fname) {
            if (!str_icontains(info.dli_fname, strlen(info.dli_fname), lj)) poison_cookie();
        }
        if (has_inline_hook((const void*)env->functions->RegisterNatives)) poison_cookie();
    }
#endif
#endif

    run_periodic_vm_guard();

    if (g_tampered) {
#ifdef _WIN32
        uintptr_t k32 = find_module_base(HY_HASH_KERNEL32);
        using FnCurProc = HANDLE(WINAPI*)();
        using FnTerm = BOOL(WINAPI*)(HANDLE, UINT);
        auto pCP = (FnCurProc)resolve_export(k32, HY_HASH_CURPROC);
        auto pTP = (FnTerm)resolve_export(k32, HY_HASH_TERMPROC);
        if (pCP && pTP) pTP(pCP(), 0xC0000005u);
        __builtin_trap();
#else
        _exit(139);
#endif
    }
}

} // namespace hy
