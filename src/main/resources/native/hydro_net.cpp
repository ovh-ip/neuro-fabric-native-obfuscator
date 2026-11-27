#include "hydro_runtime.hpp"
#include "hydro_crypto.hpp"

#if !HY_ENABLE_SERVER

namespace hy {

volatile uint64_t g_srv_dyn_params[8] = {};
volatile uint64_t g_sess_state_masked = 0;
volatile uint64_t g_sess_deadline_masked = 0;
volatile uint64_t g_hb_pulse_masked = 0;
volatile uint64_t g_hb_silence_limit_ms = 0;

void destroy_session_keys() {
    poison_cookie();
}

bool verify_session_window() {
    return g_tampered == 0;
}

bool check_session_alive() {
    return g_tampered == 0;
}

void server_logout() {}

} // namespace hy

#else

#ifdef _WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/utsname.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#endif

namespace hy {

volatile uint64_t g_srv_dyn_params[8] = {};
volatile uint64_t g_sess_state_masked = 0;
volatile uint64_t g_sess_deadline_masked = 0;
volatile uint64_t g_hb_pulse_masked = 0;
volatile uint64_t g_hb_silence_limit_ms = 0;

static volatile uint32_t g_hb_interval_sec = 15;
static volatile uint32_t g_lease_sec = 45;
static volatile int32_t g_hb_stop = 0;
static volatile int32_t g_net_lock = 0;
static volatile uint64_t g_mem_epoch_salt = 0x517CC1B727220A95ULL;
static volatile uint64_t g_sess_wall_anchor_s = 0;
static volatile uint64_t g_sess_mono_anchor_ms = 0;

static uint8_t g_enc_key_masked[32] = {};
static uint8_t g_mac_key_masked[32] = {};
static uint8_t g_rolling_key_masked[32] = {};
static uint8_t g_guard_masked[8] = {};
static char g_session_id[72] = {};
static char g_cached_hwid[65] = {};
static char g_cached_jar_hex[17] = {};
static uint64_t g_session_seq = 0;

static inline void net_lock_acquire() {
    while (__atomic_exchange_n(&g_net_lock, 1, __ATOMIC_ACQUIRE) != 0) {}
}

static inline void net_lock_release() {
    __atomic_store_n(&g_net_lock, 0, __ATOMIC_RELEASE);
}

static uint64_t monotonic_ms() {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts = {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
#endif
}

static uint64_t epoch_sec() {
#ifdef _WIN32
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
    return (t - 116444736000000000ULL) / 10000000ULL;
#else
    return (uint64_t)time(nullptr);
#endif
}

static void xor_mask_buf(uint8_t* dst, const uint8_t* src, size_t n, uint64_t epoch_salt) {
    uint64_t c = (uint64_t)g_ptr_cookie ^ g_rt_entropy ^ epoch_salt;
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i] ^ (uint8_t)((splitmix64(c + (uint64_t)i * 0x9E3779B97F4A7C15ULL) >> ((i & 7u) * 8u)) & 0xFFu);
    }
}

void destroy_session_keys() {
    __atomic_store_n(&g_sess_state_masked, 0ULL, __ATOMIC_RELEASE);
    __atomic_store_n(&g_sess_deadline_masked, 0ULL, __ATOMIC_RELEASE);
    __atomic_store_n(&g_hb_pulse_masked, 0ULL, __ATOMIC_RELEASE);
    __atomic_store_n(&g_hb_stop, 1, __ATOMIC_RELEASE);
    poison_cookie();
    for (int i = 0; i < 8; i++) {
        g_srv_dyn_params[i] ^= splitmix64((uint64_t)g_ptr_cookie + (uint64_t)i * 0xD6E8FEB86659FD93ULL);
    }
    secure_wipe(g_enc_key_masked, sizeof(g_enc_key_masked));
    secure_wipe(g_mac_key_masked, sizeof(g_mac_key_masked));
    secure_wipe(g_rolling_key_masked, sizeof(g_rolling_key_masked));
    secure_wipe(g_guard_masked, sizeof(g_guard_masked));
    secure_wipe(g_session_id, sizeof(g_session_id));
}

bool verify_session_window() {
    uint64_t now_m = monotonic_ms();
    uint64_t c = (uint64_t)g_ptr_cookie;
    uint64_t dl = __atomic_load_n(&g_sess_deadline_masked, __ATOMIC_ACQUIRE) ^ c;
    uint64_t last_pulse = __atomic_load_n(&g_hb_pulse_masked, __ATOMIC_ACQUIRE) ^ c;
    uint64_t silence_lim = __atomic_load_n(&g_hb_silence_limit_ms, __ATOMIC_ACQUIRE);
    if (now_m > dl) return false;
    if (now_m > last_pulse && (now_m - last_pulse) > silence_lim) return false;
    return true;
}

bool check_session_alive() {
    return inline_session_ok(opaque_seed());
}

// Compact libc/stdio-free format helpers so binary imports stay free of vfprintf/stdio
static inline void append_char(char* dst, size_t cap, size_t& pos, char ch) {
    if (pos + 1u < cap) dst[pos++] = ch;
    if (cap > 0u) dst[pos] = '\0';
}

static inline void append_cstr(char* dst, size_t cap, size_t& pos, const char* s) {
    if (!s) return;
    while (*s && pos + 1u < cap) dst[pos++] = *s++;
    if (cap > 0u) dst[pos] = '\0';
}

static void append_u64(char* dst, size_t cap, size_t& pos, uint64_t v) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10ULL));
        v /= 10ULL;
    } while (v > 0ULL && n < 24);
    for (int i = n - 1; i >= 0; i--) append_char(dst, cap, pos, tmp[i]);
}

static void u64_to_hex16(uint64_t v, char out[17]) {
    volatile uint8_t hx_off = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t nib = (uint8_t)(v & 0xFu);
        out[i] = (char)(nib < 10u ? ('0' + nib + hx_off) : ('a' + (nib - 10u) + hx_off));
        v >>= 4;
    }
    out[16] = '\0';
}

static void append_json_str(char* dst, size_t cap, size_t& pos, char key, const char* val, bool comma) {
    append_char(dst, cap, pos, '\"');
    append_char(dst, cap, pos, key);
    append_char(dst, cap, pos, '\"');
    append_char(dst, cap, pos, ':');
    append_char(dst, cap, pos, '\"');
    append_cstr(dst, cap, pos, val);
    append_char(dst, cap, pos, '\"');
    if (comma) append_char(dst, cap, pos, ',');
}

static void append_json_u64(char* dst, size_t cap, size_t& pos, char key, uint64_t val, bool comma) {
    append_char(dst, cap, pos, '\"');
    append_char(dst, cap, pos, key);
    append_char(dst, cap, pos, '\"');
    append_char(dst, cap, pos, ':');
    append_u64(dst, cap, pos, val);
    if (comma) append_char(dst, cap, pos, ',');
}

static uint64_t parse_u64_prefix(const char* s) {
    if (!s) return 0;
    uint64_t v = 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10ULL + (uint64_t)(*s - '0');
        s++;
    }
    return v;
}

static bool split_pipes(char* s, char** out, int expected) {
    int cnt = 0;
    out[cnt++] = s;
    for (char* p = s; *p; p++) {
        if (*p == '|') {
            *p = '\0';
            if (cnt >= expected) return false;
            out[cnt++] = p + 1;
        }
    }
    return cnt == expected;
}

static bool json_get_key_str(const char* json, char key, char* out, size_t cap) {
    if (!json || cap == 0u) return false;
    for (const char* p = json; *p; p++) {
        if (p[0] == '\"' && p[1] == key && p[2] == '\"') {
            const char* q = p + 3;
            while (*q == ' ' || *q == '\t' || *q == ':') q++;
            if (*q != '\"') continue;
            q++;
            size_t n = 0;
            while (*q && *q != '\"' && n + 1u < cap) {
                if (*q == '\\' && q[1]) q++;
                out[n++] = *q++;
            }
            out[n] = '\0';
            return *q == '\"';
        }
    }
    return false;
}

static uint64_t live_sym_digest() {
    const uint64_t _op = opaque_seed();
    uint64_t sh = HY_MBA_HASH_BASIS(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    for (uint32_t i = 0; i < g_sym_blob_size; i++) {
        sh ^= g_sym_blob[i];
        sh *= hp;
    }
    return sh;
}

static void compute_hwid(char out_hex[65]) {
    uint8_t acc[512];
    size_t pos = 0;
    auto push_bytes = [&](const void* p, size_t n) {
        if (!p || n == 0u) return;
        size_t take = (pos + n <= sizeof(acc)) ? n : (sizeof(acc) - pos);
        if (take > 0u) { memcpy(acc + pos, p, take); pos += take; }
    };
#ifdef _WIN32
    uintptr_t hAdv = load_sys_module(HY_HASH_ADVAPI32, HY_SYM_ADVAPI32_DLL);
    if (hAdv) {
        SymBuf skey, sval;
        const char* regPath = decrypt_sym(HY_SYM_REG_CRYPTO, skey);
        const char* valName = decrypt_sym(HY_SYM_MACHINE_GUID, sval);
        using FnOpen = LONG(WINAPI*)(HKEY, const char*, DWORD, REGSAM, PHKEY);
        using FnQuery = LONG(WINAPI*)(HKEY, const char*, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
        using FnClose = LONG(WINAPI*)(HKEY);
        auto pOpen = (FnOpen)resolve_export(hAdv, HY_HASH_REG_OPEN);
        auto pQuery = (FnQuery)resolve_export(hAdv, HY_HASH_REG_QUERY);
        auto pClose = (FnClose)resolve_export(hAdv, HY_HASH_REG_CLOSE);
        HKEY hk = nullptr;
        if (pOpen && pQuery && pClose && pOpen(HKEY_LOCAL_MACHINE, regPath, 0, 0x20019, &hk) == 0) {
            uint8_t rbuf[128] = {};
            DWORD rsz = sizeof(rbuf);
            if (pQuery(hk, valName, nullptr, nullptr, rbuf, &rsz) == 0 && rsz > 0) push_bytes(rbuf, rsz);
            pClose(hk);
        }
    }
    SymBuf sdrv;
    DWORD serial = 0;
    if (GetVolumeInformationA(decrypt_sym(HY_SYM_DRIVE_C, sdrv), nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        push_bytes(&serial, sizeof(serial));
    }
    char cname[128] = {};
    DWORD csz = sizeof(cname);
    if (GetComputerNameA(cname, &csz)) push_bytes(cname, csz);
#else
    int fd = open("/etc/machine-id", O_RDONLY);
    if (fd >= 0) {
        char mb[128]; ssize_t rd = read(fd, mb, sizeof(mb)); close(fd);
        if (rd > 0) push_bytes(mb, (size_t)rd);
    }
    struct utsname uts = {};
    if (uname(&uts) == 0) {
        push_bytes(uts.sysname, strlen(uts.sysname));
        push_bytes(uts.nodename, strlen(uts.nodename));
        push_bytes(uts.machine, strlen(uts.machine));
    }
#endif
    SymBuf stag;
    const char* tag = decrypt_sym(HY_SYM_HWID_TAG, stag);
    push_bytes(tag, strlen(tag));
    uint8_t digest[32];
    sha256(acc, pos, digest);
    hex_encode(digest, 32, out_hex);
    secure_wipe(acc, sizeof(acc));
    secure_wipe(digest, sizeof(digest));
}

static bool parse_url(const char* url, bool& is_https, char* host, size_t hcap, uint16_t& port, char* base_path, size_t pcap) {
    if (!url) return false;
    const char* p = url;
    is_https = false;
    if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p') {
        if (p[4] == ':' && p[5] == '/' && p[6] == '/') {
            p += 7;
        } else if (p[4] == 's' && p[5] == ':' && p[6] == '/' && p[7] == '/') {
            is_https = true;
            p += 8;
        } else {
            return false;
        }
    } else {
        return false;
    }

    const char* slash = strchr(p, '/');
    const char* host_end = slash ? slash : (p + strlen(p));
    const char* colon = nullptr;
    for (const char* q = p; q < host_end; q++) {
        if (*q == ':') colon = q;
    }
    size_t hlen = colon ? (size_t)(colon - p) : (size_t)(host_end - p);
    if (hlen == 0 || hlen >= hcap) return false;
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    if (colon) {
        uint64_t pv = parse_u64_prefix(colon + 1);
        port = (uint16_t)(pv > 0 && pv <= 65535 ? pv : (is_https ? 443 : 80));
    } else {
        port = is_https ? 443 : 80;
    }
    if (slash) {
        size_t plen = strlen(slash);
        while (plen > 0 && slash[plen - 1] == '/') plen--;
        if (plen >= pcap) plen = pcap - 1;
        memcpy(base_path, slash, plen);
        base_path[plen] = '\0';
    } else {
        base_path[0] = '\0';
    }
    return true;
}

static bool http_post_json(const char* base_url, const char* route, const char* json_body, char* out_resp, size_t resp_cap, int& out_status) {
    out_status = 0;
    if (resp_cap > 0) out_resp[0] = '\0';
    bool is_https = false;
    char host[256] = {}, bpath[256] = {}, full_path[512] = {};
    uint16_t port = 80;
    if (!parse_url(base_url, is_https, host, sizeof(host), port, bpath, sizeof(bpath))) return false;
    size_t fpos = 0;
    append_cstr(full_path, sizeof(full_path), fpos, bpath);
    append_cstr(full_path, sizeof(full_path), fpos, route);
    size_t body_len = strlen(json_body);

#ifdef _WIN32
    uintptr_t hWh = load_sys_module(HY_HASH_WINHTTP, HY_SYM_WINHTTP_DLL);
    if (!hWh) return false;
    using HINTERNET = void*;
    using FnOpen = HINTERNET(WINAPI*)(const wchar_t*, DWORD, const wchar_t*, const wchar_t*, DWORD);
    using FnConnect = HINTERNET(WINAPI*)(HINTERNET, const wchar_t*, WORD, DWORD);
    using FnOpenReq = HINTERNET(WINAPI*)(HINTERNET, const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t*, const wchar_t**, DWORD);
    using FnSetTimeouts = BOOL(WINAPI*)(HINTERNET, int, int, int, int);
    using FnSendReq = BOOL(WINAPI*)(HINTERNET, const wchar_t*, DWORD, void*, DWORD, DWORD, DWORD_PTR);
    using FnRecvResp = BOOL(WINAPI*)(HINTERNET, void*);
    using FnQueryHeaders = BOOL(WINAPI*)(HINTERNET, DWORD, const wchar_t*, void*, LPDWORD, LPDWORD);
    using FnQueryAvail = BOOL(WINAPI*)(HINTERNET, LPDWORD);
    using FnRead = BOOL(WINAPI*)(HINTERNET, void*, DWORD, LPDWORD);
    using FnClose = BOOL(WINAPI*)(HINTERNET);

    auto pOpen = (FnOpen)resolve_export(hWh, HY_HASH_WH_OPEN);
    auto pConn = (FnConnect)resolve_export(hWh, HY_HASH_WH_CONN);
    auto pReq = (FnOpenReq)resolve_export(hWh, HY_HASH_WH_REQ);
    auto pTimeouts = (FnSetTimeouts)resolve_export(hWh, HY_HASH_WH_TIME);
    auto pSend = (FnSendReq)resolve_export(hWh, HY_HASH_WH_SEND);
    auto pRecv = (FnRecvResp)resolve_export(hWh, HY_HASH_WH_RECV);
    auto pHdr = (FnQueryHeaders)resolve_export(hWh, HY_HASH_WH_HDR);
    auto pAvail = (FnQueryAvail)resolve_export(hWh, HY_HASH_WH_AVAIL);
    auto pRead = (FnRead)resolve_export(hWh, HY_HASH_WH_READ);
    auto pClose = (FnClose)resolve_export(hWh, HY_HASH_WH_CLOSE);
    if (!pOpen || !pConn || !pReq || !pSend || !pRecv || !pHdr || !pAvail || !pRead || !pClose) return false;

    SymBuf sua, sct;
    wchar_t whost[256] = {}, wpath[512] = {}, wua[64] = {}, wctype[128] = {};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 255);
    MultiByteToWideChar(CP_UTF8, 0, full_path, -1, wpath, 511);
    MultiByteToWideChar(CP_UTF8, 0, decrypt_sym(HY_SYM_UA, sua), -1, wua, 63);
    MultiByteToWideChar(CP_UTF8, 0, decrypt_sym(HY_SYM_CTYPE, sct), -1, wctype, 127);

    volatile uint16_t vk = 0x5Au;
    const uint16_t wm[4] = { (uint16_t)('P' ^ 0x5Au), (uint16_t)('O' ^ 0x5Au), (uint16_t)('S' ^ 0x5Au), (uint16_t)('T' ^ 0x5Au) };
    wchar_t wmethod[5] = {};
    for (int i = 0; i < 4; i++) wmethod[i] = (wchar_t)(wm[i] ^ vk);

    HINTERNET hSess = pOpen(wua, 0, nullptr, nullptr, 0);
    if (!hSess) return false;
    if (pTimeouts) pTimeouts(hSess, 4000, 4000, 5000, 5000);
    HINTERNET hConn = pConn(hSess, whost, port, 0);
    if (!hConn) { pClose(hSess); return false; }

    DWORD flags = is_https ? 0x00800000u : 0u;
    HINTERNET hReq = pReq(hConn, wmethod, wpath, nullptr, nullptr, nullptr, flags);
    if (!hReq) { pClose(hConn); pClose(hSess); return false; }

    BOOL ok = pSend(hReq, wctype, (DWORD)-1L, (void*)json_body, (DWORD)body_len, (DWORD)body_len, 0);
    if (ok) ok = pRecv(hReq, nullptr);
    if (ok) {
        DWORD status = 0, ssz = sizeof(status);
        pHdr(hReq, 19u | 0x20000000u, nullptr, &status, &ssz, nullptr);
        out_status = (int)status;
        size_t total = 0;
        for (;;) {
            DWORD avail = 0;
            if (!pAvail(hReq, &avail) || avail == 0) break;
            DWORD to_read = avail;
            if (total + to_read >= resp_cap) to_read = (DWORD)(resp_cap - 1u - total);
            if (to_read == 0) break;
            DWORD got = 0;
            if (!pRead(hReq, out_resp + total, to_read, &got) || got == 0) break;
            total += got;
        }
        out_resp[total] = '\0';
    }
    pClose(hReq); pClose(hConn); pClose(hSess);
    return ok && out_status >= 200 && out_status < 300;
#else
    if (is_https) return false;
    char port_str[16];
    size_t pp = 0;
    append_u64(port_str, sizeof(port_str), pp, port);
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return false;
    int fd = -1;
    for (struct addrinfo* rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return false;

    size_t req_cap = body_len + 1024u;
    char* req_buf = (char*)heap_alloc(req_cap);
    size_t hp = 0;
    append_cstr(req_buf, req_cap, hp, "POST ");
    append_cstr(req_buf, req_cap, hp, full_path);
    append_cstr(req_buf, req_cap, hp, " HTTP/1.1\r\nHost: ");
    append_cstr(req_buf, req_cap, hp, host);
    append_char(req_buf, req_cap, hp, ':');
    append_u64(req_buf, req_cap, hp, port);
    append_cstr(req_buf, req_cap, hp, "\r\nContent-Type: application/json\r\nContent-Length: ");
    append_u64(req_buf, req_cap, hp, body_len);
    append_cstr(req_buf, req_cap, hp, "\r\nConnection: close\r\n\r\n");
    if (hp + body_len <= req_cap) memcpy(req_buf + hp, json_body, body_len);
    size_t total_send = hp + body_len;
    size_t sent = 0;
    while (sent < total_send) {
        ssize_t n = send(fd, req_buf + sent, total_send - sent, 0);
        if (n <= 0) { heap_free(req_buf); close(fd); return false; }
        sent += (size_t)n;
    }
    heap_free(req_buf);

    size_t raw_cap = resp_cap + 2048u;
    char* raw = (char*)heap_alloc(raw_cap);
    size_t rtot = 0;
    while (rtot + 1 < raw_cap) {
        ssize_t n = recv(fd, raw + rtot, raw_cap - 1 - rtot, 0);
        if (n <= 0) break;
        rtot += (size_t)n;
    }
    raw[rtot] = '\0';
    close(fd);

    const char* sp = strchr(raw, ' ');
    if (sp) out_status = (int)parse_u64_prefix(sp + 1);
    const char* sep = strstr(raw, "\r\n\r\n");
    if (sep) {
        const char* body = sep + 4;
        size_t bl = strlen(body);
        if (bl >= resp_cap) bl = resp_cap - 1;
        memcpy(out_resp, body, bl);
        out_resp[bl] = '\0';
    }
    heap_free(raw);
    return out_status >= 200 && out_status < 300;
#endif
}

static void resolve_license_key(JNIEnv* env, char* out, size_t cap) {
    out[0] = '\0';
    if (HY_HAS_BAKED_LIC) {
        SymBuf sb;
        const char* bk = decrypt_sym(HY_SYM_BAKED_LIC, sb);
        if (bk && *bk) {
            size_t p = 0;
            append_cstr(out, cap, p, bk);
            return;
        }
    }
    if (env) {
        SymBuf sc, sm, sd, sp;
        jclass sysCls = find_class_by_sym(env, HY_SYM_SYS_CLS);
        if (sysCls && !env->ExceptionCheck()) {
            jmethodID mid = env->GetStaticMethodID(sysCls, decrypt_sym(HY_SYM_GET_PROP, sm), decrypt_sym(HY_SYM_GET_PROP_DESC, sd));
            if (mid && !env->ExceptionCheck()) {
                jstring jkey = env->NewStringUTF(decrypt_sym(HY_SYM_PROP_KEY, sp));
                jstring jval = (jstring)env->CallStaticObjectMethod(sysCls, mid, jkey);
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (jval) {
                    const char* utf = env->GetStringUTFChars(jval, nullptr);
                    if (utf && *utf) {
                        size_t p = 0;
                        append_cstr(out, cap, p, utf);
                    }
                    if (utf) env->ReleaseStringUTFChars(jval, utf);
                    env->DeleteLocalRef(jval);
                }
                if (jkey) env->DeleteLocalRef(jkey);
            }
            env->DeleteLocalRef(sysCls);
        }
        if (out[0] != '\0') return;
    }
    {
        SymBuf se;
        const char* evName = decrypt_sym(HY_SYM_ENV_KEY, se);
#ifdef _WIN32
        char ebuf[256] = {};
        if (GetEnvironmentVariableA(evName, ebuf, sizeof(ebuf)) > 0) {
            size_t p = 0;
            append_cstr(out, cap, p, ebuf);
            secure_wipe(ebuf, sizeof(ebuf));
            return;
        }
#else
        const char* ev = getenv(evName);
        if (ev && *ev) { size_t p = 0; append_cstr(out, cap, p, ev); return; }
#endif
    }
    {
        SymBuf sf;
        const char* path = decrypt_sym(HY_SYM_LIC_FILE, sf);
#ifdef _WIN32
        uintptr_t k32 = find_module_base(HY_HASH_KERNEL32);
        using FnCreateFileA = HANDLE(WINAPI*)(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
        using FnReadFile = BOOL(WINAPI*)(HANDLE, void*, DWORD, LPDWORD, void*);
        using FnCloseHandle = BOOL(WINAPI*)(HANDLE);
        auto pCF = (FnCreateFileA)resolve_export(k32, HY_HASH_CREATEFILEA);
        auto pRF = (FnReadFile)resolve_export(k32, HY_HASH_READFILE);
        auto pCH = (FnCloseHandle)resolve_export(k32, HY_HASH_CLOSEHANDLE);
        if (pCF && pRF && pCH) {
            HANDLE hf = pCF(path, 0x80000000u /* GENERIC_READ */, 1u /* FILE_SHARE_READ */, nullptr, 3u /* OPEN_EXISTING */, 0x80u, nullptr);
            if (hf && hf != (HANDLE)(uintptr_t)-1) {
                DWORD got = 0;
                if (pRF(hf, out, (DWORD)(cap - 1u), &got, nullptr) && got > 0) {
                    size_t n = (size_t)got;
                    out[n] = '\0';
                    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ' || out[n - 1] == '\t')) out[--n] = '\0';
                }
                pCH(hf);
            }
        }
#else
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t rd = read(fd, out, cap - 1u);
            close(fd);
            if (rd > 0) {
                size_t n = (size_t)rd;
                out[n] = '\0';
                while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ' || out[n - 1] == '\t')) out[--n] = '\0';
            }
        }
#endif
    }
}

static void derive_ratchet_keys(const uint8_t secret32[32], uint8_t ek[32], uint8_t mk[32], uint8_t rk[32], uint8_t gd[8]) {
    uint8_t le = 'E', lm = 'M', lr = 'R', lg = 'G';
    hkdf_expand(secret32, &le, 1, ek, 32);
    hkdf_expand(secret32, &lm, 1, mk, 32);
    hkdf_expand(secret32, &lr, 1, rk, 32);
    hkdf_expand(secret32, &lg, 1, gd, 8);
}

static bool send_heartbeat_once() {
    net_lock_acquire();
    if (g_tampered || __atomic_load_n(&g_hb_stop, __ATOMIC_ACQUIRE) || __atomic_load_n(&g_sess_state_masked, __ATOMIC_ACQUIRE) == 0ULL) {
        net_lock_release();
        return false;
    }

    uint64_t esalt = __atomic_load_n(&g_mem_epoch_salt, __ATOMIC_ACQUIRE);
    uint64_t next_seq = g_session_seq + 1ULL;
    uint64_t ts = epoch_sec();
    char live_sym[17];
    u64_to_hex16(live_sym_digest(), live_sym);

    uint8_t rk[32], ek[32], mk[32], gd[8];
    xor_mask_buf(rk, g_rolling_key_masked, 32, esalt);
    xor_mask_buf(ek, g_enc_key_masked, 32, esalt);
    xor_mask_buf(mk, g_mac_key_masked, 32, esalt);
    xor_mask_buf(gd, g_guard_masked, 8, esalt);
    char guard_hex[17];
    hex_encode(gd, 8, guard_hex);

    // proof = HMAC(rk, sessionId|nextSeq|ts|hwid|jarHex|symHex|guardHex)
    char auth_msg[512];
    size_t ap = 0;
    append_cstr(auth_msg, sizeof(auth_msg), ap, g_session_id); append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_u64(auth_msg, sizeof(auth_msg), ap, next_seq);      append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_u64(auth_msg, sizeof(auth_msg), ap, ts);            append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_cstr(auth_msg, sizeof(auth_msg), ap, g_cached_hwid); append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_cstr(auth_msg, sizeof(auth_msg), ap, g_cached_jar_hex); append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_cstr(auth_msg, sizeof(auth_msg), ap, live_sym);     append_char(auth_msg, sizeof(auth_msg), ap, '|');
    append_cstr(auth_msg, sizeof(auth_msg), ap, guard_hex);
    uint8_t proof[32];
    hmac_sha256(rk, 32, (const uint8_t*)auth_msg, ap, proof);
    char proof_hex[65];
    hex_encode(proof, 32, proof_hex);
    secure_wipe(rk, sizeof(rk));
    secure_wipe(proof, sizeof(proof));

    // Inner encrypted heartbeat payload: ts|hwid|jarHex|symHex|guardHex|proofHex
    char inner_pt[512];
    size_t ip = 0;
    append_u64(inner_pt, sizeof(inner_pt), ip, ts);               append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, g_cached_hwid);   append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, g_cached_jar_hex); append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, live_sym);        append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, guard_hex);       append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, proof_hex);

    uint8_t req_n12[12];
    csprng(req_n12, 12);
    uint8_t* req_ct = (uint8_t*)heap_alloc(ip);
    chacha20_xor(ek, req_n12, 1u, (const uint8_t*)inner_pt, ip, req_ct);
    secure_wipe(inner_pt, sizeof(inner_pt));

    SymBuf shbq;
    char req_aad[160];
    size_t ra = 0;
    append_cstr(req_aad, sizeof(req_aad), ra, decrypt_sym(HY_SYM_HBQ_PFX, shbq));
    append_cstr(req_aad, sizeof(req_aad), ra, g_session_id);
    append_char(req_aad, sizeof(req_aad), ra, '|');
    append_u64(req_aad, sizeof(req_aad), ra, next_seq);

    size_t rmac_in_len = ra + 12u + ip;
    uint8_t* rmac_in = (uint8_t*)heap_alloc(rmac_in_len);
    memcpy(rmac_in, req_aad, ra);
    memcpy(rmac_in + ra, req_n12, 12);
    memcpy(rmac_in + ra + 12u, req_ct, ip);
    uint8_t req_mac[32];
    hmac_sha256(mk, 32, rmac_in, rmac_in_len, req_mac);
    heap_free(rmac_in);

    char rn12_hex[25], rmac_hex[65];
    char* rct_hex = (char*)heap_alloc(ip * 2u + 1u);
    hex_encode(req_n12, 12, rn12_hex);
    hex_encode(req_mac, 32, rmac_hex);
    hex_encode(req_ct, ip, rct_hex);
    heap_free(req_ct);

    char req_json[2048];
    size_t jp = 0;
    append_char(req_json, sizeof(req_json), jp, '{');
    append_json_str(req_json, sizeof(req_json), jp, 's', g_session_id, true);
    append_json_u64(req_json, sizeof(req_json), jp, 'q', next_seq, true);
    append_json_str(req_json, sizeof(req_json), jp, 'v', rn12_hex, true);
    append_json_str(req_json, sizeof(req_json), jp, 'p', rct_hex, true);
    append_json_str(req_json, sizeof(req_json), jp, 'm', rmac_hex, false);
    append_char(req_json, sizeof(req_json), jp, '}');
    heap_free(rct_hex);

    SymBuf surl, sep;
    const char* url = decrypt_sym(HY_SYM_SRV_URL, surl);
    const char* ep = decrypt_sym(HY_SYM_EP_HB, sep);
    char resp[4096];
    int status = 0;
    bool http_ok = http_post_json(url, ep, req_json, resp, sizeof(resp), status);

    if (!http_ok) {
        secure_wipe(ek, sizeof(ek));
        secure_wipe(mk, sizeof(mk));
        secure_wipe(gd, sizeof(gd));
        if (status >= 400 && status < 500) destroy_session_keys();
        net_lock_release();
        return false;
    }

    char nonce_hex[32] = {}, ct_hex[2048] = {}, mac_hex[80] = {};
    if (!json_get_key_str(resp, 'v', nonce_hex, sizeof(nonce_hex))
            || !json_get_key_str(resp, 'p', ct_hex, sizeof(ct_hex))
            || !json_get_key_str(resp, 'm', mac_hex, sizeof(mac_hex))) {
        secure_wipe(ek, sizeof(ek)); secure_wipe(mk, sizeof(mk)); secure_wipe(gd, sizeof(gd));
        destroy_session_keys();
        net_lock_release();
        return false;
    }

    uint8_t nonce12[12], mac[32];
    size_t ct_len = strlen(ct_hex) / 2u;
    if (ct_len == 0u || ct_len > 1024u) {
        secure_wipe(ek, sizeof(ek)); secure_wipe(mk, sizeof(mk)); secure_wipe(gd, sizeof(gd));
        destroy_session_keys();
        net_lock_release();
        return false;
    }
    uint8_t* ct = (uint8_t*)heap_alloc(ct_len);
    uint8_t* pt = (uint8_t*)heap_alloc(ct_len + 1u);
    if (!hex_decode(nonce_hex, strlen(nonce_hex), nonce12, 12)
            || !hex_decode(mac_hex, strlen(mac_hex), mac, 32)
            || !hex_decode(ct_hex, strlen(ct_hex), ct, ct_len)) {
        heap_free(ct); heap_free(pt);
        secure_wipe(ek, sizeof(ek)); secure_wipe(mk, sizeof(mk)); secure_wipe(gd, sizeof(gd));
        destroy_session_keys();
        net_lock_release();
        return false;
    }

    SymBuf shb;
    char aad[160];
    size_t al = 0;
    append_cstr(aad, sizeof(aad), al, decrypt_sym(HY_SYM_HB_PFX, shb));
    append_cstr(aad, sizeof(aad), al, g_session_id);
    append_char(aad, sizeof(aad), al, '|');
    append_u64(aad, sizeof(aad), al, next_seq);

    size_t mac_in_len = al + 12u + ct_len;
    uint8_t* mac_in = (uint8_t*)heap_alloc(mac_in_len);
    memcpy(mac_in, aad, al);
    memcpy(mac_in + al, nonce12, 12);
    memcpy(mac_in + al + 12u, ct, ct_len);
    uint8_t exp_mac[32];
    hmac_sha256(mk, 32, mac_in, mac_in_len, exp_mac);
    heap_free(mac_in);

    bool ok = ct_equal(exp_mac, mac, 32);
    if (ok) {
        chacha20_xor(ek, nonce12, 1u, ct, ct_len, pt);
        pt[ct_len] = '\0';
        // Format: seq|epochHex64|hbSec|leaseSec|srvTimeSec|1
        char* flds[6];
        uint8_t epoch[32];
        if (split_pipes((char*)pt, flds, 6)
                && parse_u64_prefix(flds[0]) == next_seq
                && flds[5][0] == '1'
                && hex_decode(flds[1], strlen(flds[1]), epoch, 32)) {
            uint64_t hb = parse_u64_prefix(flds[2]);
            uint64_t lease = parse_u64_prefix(flds[3]);
            uint64_t now_m = monotonic_ms();
            uint64_t now_w = epoch_sec();
            uint64_t wall_d = (now_w > g_sess_wall_anchor_s) ? (now_w - g_sess_wall_anchor_s) : 0ULL;
            uint64_t mono_d = (now_m > g_sess_mono_anchor_ms) ? (now_m - g_sess_mono_anchor_ms) : 0ULL;
            if (wall_d > (lease * 3ULL + 30ULL) && mono_d < (lease * 250ULL)) {
                ok = false; // Clock freeze tamper detected
            } else {
                uint8_t nek[32], nmk[32], nrk[32], ngd[8];
                derive_ratchet_keys(epoch, nek, nmk, nrk, ngd);
                uint64_t new_esalt = splitmix64(esalt ^ hy_tick() ^ next_seq);
                __atomic_store_n(&g_mem_epoch_salt, new_esalt, __ATOMIC_RELEASE);
                xor_mask_buf(g_enc_key_masked, nek, 32, new_esalt);
                xor_mask_buf(g_mac_key_masked, nmk, 32, new_esalt);
                xor_mask_buf(g_rolling_key_masked, nrk, 32, new_esalt);
                xor_mask_buf(g_guard_masked, ngd, 8, new_esalt);
                secure_wipe(nek, sizeof(nek));
                secure_wipe(nmk, sizeof(nmk));
                secure_wipe(nrk, sizeof(nrk));
                secure_wipe(ngd, sizeof(ngd));

                uint32_t eff_hb = (uint32_t)(hb > 0 ? hb : 15ULL);
                uint32_t eff_lease = (uint32_t)(lease > 0 ? lease : 45ULL);
                g_hb_interval_sec = eff_hb;
                g_lease_sec = eff_lease;
                uint64_t c = (uint64_t)g_ptr_cookie;
                __atomic_store_n(&g_hb_silence_limit_ms, ((uint64_t)eff_lease + (uint64_t)eff_hb + 3ULL) * 1000ULL, __ATOMIC_RELEASE);
                __atomic_store_n(&g_hb_pulse_masked, now_m ^ c, __ATOMIC_RELEASE);
                __atomic_store_n(&g_sess_deadline_masked, (now_m + (uint64_t)eff_lease * 1000ULL) ^ c, __ATOMIC_RELEASE);
                g_sess_wall_anchor_s = now_w;
                g_sess_mono_anchor_ms = now_m;
                g_session_seq = next_seq;
            }
            secure_wipe(epoch, sizeof(epoch));
        } else {
            ok = false;
        }
    }

    secure_wipe(ek, sizeof(ek));
    secure_wipe(mk, sizeof(mk));
    secure_wipe(gd, sizeof(gd));
    secure_wipe(pt, ct_len);
    heap_free(ct);
    heap_free(pt);
    if (!ok) destroy_session_keys();
    net_lock_release();
    return ok;
}

#ifdef _WIN32
static DWORD WINAPI hb_thread_proc(void*) {
    hide_current_thread();
    while (!g_tampered && !__atomic_load_n(&g_hb_stop, __ATOMIC_ACQUIRE) && __atomic_load_n(&g_sess_state_masked, __ATOMIC_ACQUIRE) != 0ULL) {
        uint32_t iv = g_hb_interval_sec;
        if (iv < 1u) iv = 1u;
        Sleep(iv * 1000u);
        if (g_tampered || __atomic_load_n(&g_hb_stop, __ATOMIC_ACQUIRE)) break;
        run_periodic_vm_guard();
        if (g_tampered) { destroy_session_keys(); break; }
        if (!send_heartbeat_once() && !verify_session_window()) {
            destroy_session_keys();
            break;
        }
    }
    return 0;
}
#else
static void* hb_thread_proc(void*) {
    hide_current_thread();
    while (!g_tampered && !__atomic_load_n(&g_hb_stop, __ATOMIC_ACQUIRE) && __atomic_load_n(&g_sess_state_masked, __ATOMIC_ACQUIRE) != 0ULL) {
        uint32_t iv = g_hb_interval_sec;
        if (iv < 1u) iv = 1u;
        sleep(iv);
        if (g_tampered || __atomic_load_n(&g_hb_stop, __ATOMIC_ACQUIRE)) break;
        run_periodic_vm_guard();
        if (g_tampered) { destroy_session_keys(); break; }
        if (!send_heartbeat_once() && !verify_session_window()) {
            destroy_session_keys();
            break;
        }
    }
    return nullptr;
}
#endif

void server_logout() {
    net_lock_acquire();
    __atomic_store_n(&g_hb_stop, 1, __ATOMIC_RELEASE);
    if (g_session_id[0] != '\0' && __atomic_load_n(&g_sess_state_masked, __ATOMIC_ACQUIRE) != 0ULL) {
        uint64_t esalt = __atomic_load_n(&g_mem_epoch_salt, __ATOMIC_ACQUIRE);
        uint64_t ts = epoch_sec();
        uint8_t rk[32], ek[32], mk[32], gd[8];
        xor_mask_buf(rk, g_rolling_key_masked, 32, esalt);
        xor_mask_buf(ek, g_enc_key_masked, 32, esalt);
        xor_mask_buf(mk, g_mac_key_masked, 32, esalt);
        xor_mask_buf(gd, g_guard_masked, 8, esalt);
        char guard_hex[17];
        hex_encode(gd, 8, guard_hex);

        SymBuf slo, sloq, surl, sep;
        char msg[192];
        size_t mp = 0;
        append_cstr(msg, sizeof(msg), mp, decrypt_sym(HY_SYM_LO_PFX, slo));
        append_cstr(msg, sizeof(msg), mp, g_session_id);
        append_char(msg, sizeof(msg), mp, '|');
        append_u64(msg, sizeof(msg), mp, ts);
        uint8_t proof[32];
        hmac_sha256(rk, 32, (const uint8_t*)msg, mp, proof);
        char proof_hex[65];
        hex_encode(proof, 32, proof_hex);

        char pt[256];
        size_t pp = 0;
        append_u64(pt, sizeof(pt), pp, ts); append_char(pt, sizeof(pt), pp, '|');
        append_cstr(pt, sizeof(pt), pp, guard_hex); append_char(pt, sizeof(pt), pp, '|');
        append_cstr(pt, sizeof(pt), pp, proof_hex);

        uint8_t n12[12];
        csprng(n12, 12);
        uint8_t* ct = (uint8_t*)heap_alloc(pp);
        chacha20_xor(ek, n12, 1u, (const uint8_t*)pt, pp, ct);

        char aad[160];
        size_t ap = 0;
        append_cstr(aad, sizeof(aad), ap, decrypt_sym(HY_SYM_LOQ_PFX, sloq));
        append_cstr(aad, sizeof(aad), ap, g_session_id);

        size_t min_len = ap + 12u + pp;
        uint8_t* mac_in = (uint8_t*)heap_alloc(min_len);
        memcpy(mac_in, aad, ap);
        memcpy(mac_in + ap, n12, 12);
        memcpy(mac_in + ap + 12u, ct, pp);
        uint8_t mac[32];
        hmac_sha256(mk, 32, mac_in, min_len, mac);
        heap_free(mac_in);

        char n12_hex[25], mac_hex[65];
        char* ct_hex = (char*)heap_alloc(pp * 2u + 1u);
        hex_encode(n12, 12, n12_hex);
        hex_encode(mac, 32, mac_hex);
        hex_encode(ct, pp, ct_hex);
        heap_free(ct);

        char req_json[1024];
        size_t jp = 0;
        append_char(req_json, sizeof(req_json), jp, '{');
        append_json_str(req_json, sizeof(req_json), jp, 's', g_session_id, true);
        append_json_str(req_json, sizeof(req_json), jp, 'v', n12_hex, true);
        append_json_str(req_json, sizeof(req_json), jp, 'p', ct_hex, true);
        append_json_str(req_json, sizeof(req_json), jp, 'm', mac_hex, false);
        append_char(req_json, sizeof(req_json), jp, '}');
        heap_free(ct_hex);

        char resp[512];
        int st = 0;
        http_post_json(decrypt_sym(HY_SYM_SRV_URL, surl), decrypt_sym(HY_SYM_EP_LO, sep), req_json, resp, sizeof(resp), st);

        secure_wipe(rk, sizeof(rk));
        secure_wipe(ek, sizeof(ek));
        secure_wipe(mk, sizeof(mk));
        secure_wipe(gd, sizeof(gd));
    }
    destroy_session_keys();
    net_lock_release();
}

bool server_handshake(JNIEnv* env, uint64_t jar_digest, uint64_t* out_vm_share, uint64_t* out_vault_share) {
    *out_vm_share = 0;
    *out_vault_share = 0;

    compute_hwid(g_cached_hwid);
    u64_to_hex16(jar_digest, g_cached_jar_hex);
    char sym_hex[17];
    u64_to_hex16(live_sym_digest(), sym_hex);

    char lic_key[256] = {};
    resolve_license_key(env, lic_key, sizeof(lic_key));
    if (lic_key[0] == '\0') return false;

    uint8_t c_priv[32], c_pub[32], c_nonce[16];
    csprng(c_priv, 32);
    c_priv[0] &= 248u;
    c_priv[31] = (uint8_t)((c_priv[31] & 127u) | 64u);
    x25519_public(c_pub, c_priv);
    csprng(c_nonce, 16);

    const uint64_t _op = opaque_seed();
    uint8_t srv_static_pub[32];
    for (int i = 0; i < 32; i++) {
        srv_static_pub[i] = g_srv_pubkey_masked[i] ^ (uint8_t)((splitmix64(HY_MBA_PUBKEY_MASK(_op) + (uint64_t)i * 0x9E3779B97F4A7C15ULL) >> ((i & 7) * 8)) & 0xFFu);
    }
    uint8_t dh_static[32];
    x25519(dh_static, c_priv, srv_static_pub);
    secure_wipe(srv_static_pub, sizeof(srv_static_pub));

    SymBuf spro, sbld, surl, sre2, srm2, sep;
    const char* product_id = decrypt_sym(HY_SYM_PRODUCT_ID, spro);
    const char* build_id = decrypt_sym(HY_SYM_BUILD_ID, sbld);
    const char* url = decrypt_sym(HY_SYM_SRV_URL, surl);
    const char* req_e2 = decrypt_sym(HY_SYM_REQ_E2, sre2);
    const char* req_m2 = decrypt_sym(HY_SYM_REQ_M2, srm2);

    uint8_t req_enc_k[32], req_mac_k[32];
    hkdf_sha256(c_nonce, 16, dh_static, 32, (const uint8_t*)req_e2, strlen(req_e2), req_enc_k, 32);
    hkdf_sha256(c_nonce, 16, dh_static, 32, (const uint8_t*)req_m2, strlen(req_m2), req_mac_k, 32);

    char cpub_hex[65], cnonce_hex[33];
    hex_encode(c_pub, 32, cpub_hex);
    hex_encode(c_nonce, 16, cnonce_hex);
    uint64_t ts = epoch_sec();

    // Encrypted inner handshake payload: productId|buildId|licKey|hwid|jarHex|symHex|ts|cpubHex
    char inner_pt[1024];
    size_t ip = 0;
    append_cstr(inner_pt, sizeof(inner_pt), ip, product_id);       append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, build_id);         append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, lic_key);          append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, g_cached_hwid);    append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, g_cached_jar_hex); append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, sym_hex);          append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_u64(inner_pt, sizeof(inner_pt), ip, ts);                append_char(inner_pt, sizeof(inner_pt), ip, '|');
    append_cstr(inner_pt, sizeof(inner_pt), ip, cpub_hex);
    secure_wipe(lic_key, sizeof(lic_key));

    uint8_t req_n12[12];
    csprng(req_n12, 12);
    uint8_t* req_ct = (uint8_t*)heap_alloc(ip);
    chacha20_xor(req_enc_k, req_n12, 1u, (const uint8_t*)inner_pt, ip, req_ct);
    secure_wipe(inner_pt, sizeof(inner_pt));
    secure_wipe(req_enc_k, sizeof(req_enc_k));

    char req_aad[128];
    size_t rap = 0;
    append_cstr(req_aad, sizeof(req_aad), rap, cpub_hex);
    append_char(req_aad, sizeof(req_aad), rap, '|');
    append_cstr(req_aad, sizeof(req_aad), rap, cnonce_hex);
    size_t rmac_len = rap + 12u + ip;
    uint8_t* rmac_in = (uint8_t*)heap_alloc(rmac_len);
    memcpy(rmac_in, req_aad, rap);
    memcpy(rmac_in + rap, req_n12, 12);
    memcpy(rmac_in + rap + 12u, req_ct, ip);
    uint8_t req_mac[32];
    hmac_sha256(req_mac_k, 32, rmac_in, rmac_len, req_mac);
    heap_free(rmac_in);
    secure_wipe(req_mac_k, sizeof(req_mac_k));

    char rn12_hex[25], rmac_hex[65];
    char* rct_hex = (char*)heap_alloc(ip * 2u + 1u);
    hex_encode(req_n12, 12, rn12_hex);
    hex_encode(req_mac, 32, rmac_hex);
    hex_encode(req_ct, ip, rct_hex);
    heap_free(req_ct);

    char* req_json = (char*)heap_alloc(ip * 2u + 512u);
    size_t jp = 0;
    append_char(req_json, ip * 2u + 512u, jp, '{');
    append_json_str(req_json, ip * 2u + 512u, jp, 'k', cpub_hex, true);
    append_json_str(req_json, ip * 2u + 512u, jp, 'n', cnonce_hex, true);
    append_json_str(req_json, ip * 2u + 512u, jp, 'v', rn12_hex, true);
    append_json_str(req_json, ip * 2u + 512u, jp, 'p', rct_hex, true);
    append_json_str(req_json, ip * 2u + 512u, jp, 'm', rmac_hex, false);
    append_char(req_json, ip * 2u + 512u, jp, '}');
    heap_free(rct_hex);

    char resp[8192];
    int status = 0;
    bool http_ok = http_post_json(url, decrypt_sym(HY_SYM_EP_HS, sep), req_json, resp, sizeof(resp), status);
    heap_free(req_json);
    if (!http_ok) {
        secure_wipe(c_priv, sizeof(c_priv));
        secure_wipe(dh_static, sizeof(dh_static));
        return false;
    }

    char sess_id[72] = {}, seph_hex[80] = {}, snonce_hex[40] = {}, nonce_hex[32] = {}, ct_hex[4096] = {}, mac_hex[80] = {};
    if (!json_get_key_str(resp, 's', sess_id, sizeof(sess_id))
            || !json_get_key_str(resp, 'k', seph_hex, sizeof(seph_hex))
            || !json_get_key_str(resp, 'n', snonce_hex, sizeof(snonce_hex))
            || !json_get_key_str(resp, 'v', nonce_hex, sizeof(nonce_hex))
            || !json_get_key_str(resp, 'p', ct_hex, sizeof(ct_hex))
            || !json_get_key_str(resp, 'm', mac_hex, sizeof(mac_hex))) {
        secure_wipe(c_priv, sizeof(c_priv));
        secure_wipe(dh_static, sizeof(dh_static));
        return false;
    }

    uint8_t srv_eph_pub[32], s_nonce[16], nonce12[12], mac[32];
    size_t ct_len = strlen(ct_hex) / 2u;
    if (ct_len == 0 || ct_len > 2048u
            || !hex_decode(seph_hex, strlen(seph_hex), srv_eph_pub, 32)
            || !hex_decode(snonce_hex, strlen(snonce_hex), s_nonce, 16)
            || !hex_decode(nonce_hex, strlen(nonce_hex), nonce12, 12)
            || !hex_decode(mac_hex, strlen(mac_hex), mac, 32)) {
        secure_wipe(c_priv, sizeof(c_priv));
        secure_wipe(dh_static, sizeof(dh_static));
        return false;
    }

    uint8_t* ct = (uint8_t*)heap_alloc(ct_len);
    uint8_t* pt = (uint8_t*)heap_alloc(ct_len + 1u);
    if (!hex_decode(ct_hex, strlen(ct_hex), ct, ct_len)) {
        heap_free(ct); heap_free(pt);
        secure_wipe(c_priv, sizeof(c_priv));
        secure_wipe(dh_static, sizeof(dh_static));
        return false;
    }

    uint8_t dh_eph[32];
    x25519(dh_eph, c_priv, srv_eph_pub);
    secure_wipe(c_priv, sizeof(c_priv));

    uint8_t ikm[64], salt[32];
    memcpy(ikm, dh_static, 32);
    memcpy(ikm + 32, dh_eph, 32);
    memcpy(salt, c_nonce, 16);
    memcpy(salt + 16, s_nonce, 16);
    secure_wipe(dh_static, sizeof(dh_static));
    secure_wipe(dh_eph, sizeof(dh_eph));

    SymBuf ssp;
    char sess_info[256];
    size_t sip = 0;
    append_cstr(sess_info, sizeof(sess_info), sip, decrypt_sym(HY_SYM_SESS_PFX, ssp));
    append_cstr(sess_info, sizeof(sess_info), sip, build_id);
    append_char(sess_info, sizeof(sess_info), sip, '|');
    append_cstr(sess_info, sizeof(sess_info), sip, g_cached_hwid);

    uint8_t master_key[32], enc_key[32], mac_key[32];
    hkdf_sha256(salt, 32, ikm, 64, (const uint8_t*)sess_info, sip, master_key, 32);
    uint8_t le = 'E', lm = 'M';
    hkdf_expand(master_key, &le, 1, enc_key, 32);
    hkdf_expand(master_key, &lm, 1, mac_key, 32);
    secure_wipe(ikm, sizeof(ikm));
    secure_wipe(master_key, sizeof(master_key));

    char aad[512];
    size_t aap = 0;
    append_cstr(aad, sizeof(aad), aap, sess_id);        append_char(aad, sizeof(aad), aap, '|');
    append_cstr(aad, sizeof(aad), aap, build_id);       append_char(aad, sizeof(aad), aap, '|');
    append_cstr(aad, sizeof(aad), aap, g_cached_hwid);  append_char(aad, sizeof(aad), aap, '|');
    append_cstr(aad, sizeof(aad), aap, cpub_hex);       append_char(aad, sizeof(aad), aap, '|');
    append_cstr(aad, sizeof(aad), aap, seph_hex);

    size_t mac_in_len = aap + 12u + ct_len;
    uint8_t* mac_in = (uint8_t*)heap_alloc(mac_in_len);
    memcpy(mac_in, aad, aap);
    memcpy(mac_in + aap, nonce12, 12);
    memcpy(mac_in + aap + 12u, ct, ct_len);
    uint8_t exp_mac[32];
    hmac_sha256(mac_key, 32, mac_in, mac_in_len, exp_mac);
    heap_free(mac_in);

    bool ok = ct_equal(exp_mac, mac, 32);
    if (ok) {
        chacha20_xor(enc_key, nonce12, 1u, ct, ct_len, pt);
        pt[ct_len] = '\0';
        // Format: vmShareHex|vaultShareHex|rollingHex64|hbSec|leaseSec|srvTimeSec|guardHex16|dynParamsHex
        char* flds[8];
        if (split_pipes((char*)pt, flds, 8)) {
            uint8_t vm_b[8], vs_b[8], rk[32], gd[8];
            if (hex_decode(flds[0], strlen(flds[0]), vm_b, 8)
                    && hex_decode(flds[1], strlen(flds[1]), vs_b, 8)
                    && hex_decode(flds[2], strlen(flds[2]), rk, 32)
                    && hex_decode(flds[6], strlen(flds[6]), gd, 8)) {
                uint64_t vm_u = 0, vs_u = 0;
                for (int b = 0; b < 8; b++) {
                    vm_u = (vm_u << 8) | vm_b[b];
                    vs_u = (vs_u << 8) | vs_b[b];
                }
                *out_vm_share = vm_u;
                *out_vault_share = vs_u;

                const char* dp = flds[7];
                size_t dplen = strlen(dp);
                for (int d = 0; d < 8 && (size_t)(d * 16 + 16) <= dplen; d++) {
                    uint8_t db[8];
                    if (hex_decode(dp + d * 16, 16, db, 8)) {
                        uint64_t v = 0;
                        for (int b = 0; b < 8; b++) v = (v << 8) | db[b];
                        g_srv_dyn_params[d] = v ^ (uint64_t)g_ptr_cookie;
                    }
                }

                size_t sidp = 0;
                append_cstr(g_session_id, sizeof(g_session_id), sidp, sess_id);
                uint64_t init_esalt = splitmix64(hy_tick() ^ _op ^ vm_u);
                __atomic_store_n(&g_mem_epoch_salt, init_esalt, __ATOMIC_RELEASE);
                xor_mask_buf(g_enc_key_masked, enc_key, 32, init_esalt);
                xor_mask_buf(g_mac_key_masked, mac_key, 32, init_esalt);
                xor_mask_buf(g_rolling_key_masked, rk, 32, init_esalt);
                xor_mask_buf(g_guard_masked, gd, 8, init_esalt);
                secure_wipe(rk, sizeof(rk));
                secure_wipe(gd, sizeof(gd));

                uint32_t hb = (uint32_t)parse_u64_prefix(flds[3]);
                uint32_t lease = (uint32_t)parse_u64_prefix(flds[4]);
                g_hb_interval_sec = hb > 0u ? hb : 15u;
                g_lease_sec = lease > 0u ? lease : 45u;

                uint64_t now_m = monotonic_ms();
                uint64_t now_w = epoch_sec();
                uint64_t c = (uint64_t)g_ptr_cookie;
                g_sess_wall_anchor_s = now_w;
                g_sess_mono_anchor_ms = now_m;
                __atomic_store_n(&g_hb_silence_limit_ms, ((uint64_t)g_lease_sec + (uint64_t)g_hb_interval_sec + 3ULL) * 1000ULL, __ATOMIC_RELEASE);
                __atomic_store_n(&g_hb_pulse_masked, now_m ^ c, __ATOMIC_RELEASE);
                __atomic_store_n(&g_sess_deadline_masked, (now_m + (uint64_t)g_lease_sec * 1000ULL) ^ c, __ATOMIC_RELEASE);
                __atomic_store_n(&g_sess_state_masked, HY_MBA_SESS_ALIVE_MAGIC(_op) ^ c, __ATOMIC_RELEASE);
                __atomic_store_n(&g_hb_stop, 0, __ATOMIC_RELEASE);
                g_session_seq = 0;

#ifdef _WIN32
                HANDLE hThr = CreateThread(nullptr, 0, hb_thread_proc, nullptr, 0, nullptr);
                if (hThr) CloseHandle(hThr);
#else
                pthread_t tid;
                if (pthread_create(&tid, nullptr, hb_thread_proc, nullptr) == 0) pthread_detach(tid);
#endif
            } else {
                ok = false;
            }
        } else {
            ok = false;
        }
    }

    secure_wipe(enc_key, sizeof(enc_key));
    secure_wipe(mac_key, sizeof(mac_key));
    secure_wipe(pt, ct_len);
    heap_free(ct);
    heap_free(pt);
    return ok;
}

} // namespace hy

#endif // HY_ENABLE_SERVER
