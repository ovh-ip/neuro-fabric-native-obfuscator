#include "hydro_runtime.hpp"
#include "hydro_crypto.hpp"

#if !HY_ENABLE_SERVER

namespace hy {

volatile uint64_t g_srv_dyn_params[8] = {};

bool check_session_alive() {
    return g_tampered == 0;
}

} // namespace hy

#else

#ifdef _WIN32
#include <windows.h>
#include <stdio.h>
#else
#include <stdlib.h>
#include <stdio.h>
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

// Active rolling session state (protected/masked in memory)
static volatile uint64_t g_session_deadline_ms = 0;
static volatile int32_t g_session_established = 0;
static volatile int32_t g_session_revoked = 0;
static volatile uint32_t g_hb_interval_sec = 15;
static uint8_t g_enc_key_masked[32] = {};
static uint8_t g_mac_key_masked[32] = {};
static uint8_t g_rolling_key_masked[32] = {};
static char g_session_id[72] = {};
static char g_cached_hwid[65] = {};
static char g_cached_jar_hex[17] = {};
static char g_cached_sym_hex[17] = {};
static uint64_t g_session_seq = 0;

volatile uint64_t g_srv_dyn_params[8] = {};

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

static void xor_mask_32(uint8_t dst[32], const uint8_t src[32]) {
    uint64_t c = (uint64_t)g_ptr_cookie ^ g_rt_entropy;
    for (int i = 0; i < 32; i++) {
        dst[i] = src[i] ^ (uint8_t)((splitmix64(c + (uint64_t)i * 0x9E3779B97F4A7C15ULL) >> ((i & 7) * 8)) & 0xFFu);
    }
}

bool check_session_alive() {
    if (g_tampered || g_session_revoked || !g_session_established) return false;
    uint64_t now = monotonic_ms();
    uint64_t dl = __atomic_load_n(&g_session_deadline_ms, __ATOMIC_ACQUIRE);
    if (now > dl) {
        g_session_revoked = 1;
        poison_cookie();
        return false;
    }
    return true;
}

static void compute_hwid(char out_hex[65]) {
    uint8_t acc[512];
    size_t pos = 0;
    auto push_bytes = [&](const void* p, size_t n) {
        if (!p || n == 0) return;
        size_t take = (pos + n <= sizeof(acc)) ? n : (sizeof(acc) - pos);
        if (take > 0) { memcpy(acc + pos, p, take); pos += take; }
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
        if (pOpen && pQuery && pClose && pOpen(HKEY_LOCAL_MACHINE, regPath, 0, 0x20019 /* KEY_READ */, &hk) == 0) {
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
        int pv = atoi(colon + 1);
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
    snprintf(full_path, sizeof(full_path), "%s%s", bpath, route);
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

    HINTERNET hSess = pOpen(wua, 0 /* WINHTTP_ACCESS_TYPE_DEFAULT_PROXY */, nullptr, nullptr, 0);
    if (!hSess) return false;
    if (pTimeouts) pTimeouts(hSess, 4000, 4000, 5000, 5000);
    HINTERNET hConn = pConn(hSess, whost, port, 0);
    if (!hConn) { pClose(hSess); return false; }

    DWORD flags = is_https ? 0x00800000u /* WINHTTP_FLAG_SECURE */ : 0u;
    HINTERNET hReq = pReq(hConn, wmethod, wpath, nullptr, nullptr, nullptr, flags);
    if (!hReq) { pClose(hConn); pClose(hSess); return false; }

    BOOL ok = pSend(hReq, wctype, (DWORD)-1L, (void*)json_body, (DWORD)body_len, (DWORD)body_len, 0);
    if (ok) ok = pRecv(hReq, nullptr);
    if (ok) {
        DWORD status = 0, ssz = sizeof(status);
        pHdr(hReq, 19u | 0x20000000u /* WINHTTP_QUERY_STATUS_CODE | FLAG_NUMBER */, nullptr, &status, &ssz, nullptr);
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
    if (is_https) return false; // POSIX builds use TLS-terminating proxy or plain HTTP over encrypted E2EE payload
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
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

    char* req_buf = (char*)heap_alloc(body_len + 1024);
    int hdr_len = snprintf(req_buf, body_len + 1024,
            "POST %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
            full_path, host, (unsigned)port, body_len);
    memcpy(req_buf + hdr_len, json_body, body_len);
    size_t total_send = (size_t)hdr_len + body_len;
    size_t sent = 0;
    while (sent < total_send) {
        ssize_t n = send(fd, req_buf + sent, total_send - sent, 0);
        if (n <= 0) { heap_free(req_buf); close(fd); return false; }
        sent += (size_t)n;
    }
    heap_free(req_buf);

    size_t raw_cap = resp_cap + 2048;
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
    if (sp) out_status = atoi(sp + 1);
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

static bool json_get_str(const char* json, const char* key, char* out, size_t cap) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return false;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return false;
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) p++;
        out[n++] = *p++;
    }
    out[n] = '\0';
    return *p == '"';
}

static void resolve_license_key(JNIEnv* env, char* out, size_t cap) {
    out[0] = '\0';
    // 1. Optional baked key in symbol table
    if (HY_HAS_BAKED_LIC) {
        SymBuf sb;
        const char* bk = decrypt_sym(HY_SYM_BAKED_LIC, sb);
        if (bk && *bk) {
            snprintf(out, cap, "%s", bk);
            return;
        }
    }
    // 2. JVM property: -Dhydro.key=...
    if (env) {
        SymBuf sc, sm, sd, sp;
        jclass sysCls = find_class_by_sym(env, HY_SYM_SYS_CLS);
        if (sysCls && !env->ExceptionCheck()) {
            jmethodID mid = env->GetStaticMethodID(sysCls, decrypt_sym(HY_SYM_GET_PROP, sm), decrypt_sym(HY_SYM_GET_PROP_DESC, sd));
            if (mid && !env->ExceptionCheck()) {
                jstring jkey = env->NewStringUTF(decrypt_sym(HY_SYM_PROP_KEY, sp));
                jstring jval = (jstring)env->CallStaticObjectMethod(sysCls, mid, jkey);
                if (env->ExceptionCheck()) { env->ExceptionClear(); }
                if (jval) {
                    const char* utf = env->GetStringUTFChars(jval, nullptr);
                    if (utf && *utf) snprintf(out, cap, "%s", utf);
                    if (utf) env->ReleaseStringUTFChars(jval, utf);
                    env->DeleteLocalRef(jval);
                }
                if (jkey) env->DeleteLocalRef(jkey);
            }
            env->DeleteLocalRef(sysCls);
        }
        if (out[0] != '\0') return;
    }
    // 3. Environment variable HYDRO_LICENSE_KEY
    {
        SymBuf se;
        const char* evName = decrypt_sym(HY_SYM_ENV_KEY, se);
#ifdef _WIN32
        char ebuf[256] = {};
        if (GetEnvironmentVariableA(evName, ebuf, sizeof(ebuf)) > 0) {
            snprintf(out, cap, "%s", ebuf);
            secure_wipe(ebuf, sizeof(ebuf));
            return;
        }
#else
        const char* ev = getenv(evName);
        if (ev && *ev) { snprintf(out, cap, "%s", ev); return; }
#endif
    }
    // 4. Local key file (e.g. hydro.key)
    {
        SymBuf sf;
        FILE* f = fopen(decrypt_sym(HY_SYM_LIC_FILE, sf), "rb");
        if (f) {
            size_t n = fread(out, 1, cap - 1, f);
            fclose(f);
            out[n] = '\0';
            while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' || out[n - 1] == ' ' || out[n - 1] == '\t')) {
                out[--n] = '\0';
            }
        }
    }
}

static bool send_heartbeat_once() {
    if (!g_session_established || g_session_revoked || g_tampered) return false;
    uint64_t next_seq = g_session_seq + 1ULL;
    uint64_t ts = epoch_sec();

    // Compute live symDigest dynamically
    const uint64_t _op = opaque_seed();
    uint64_t sh = HY_MBA_HASH_BASIS(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    for (uint32_t i = 0; i < g_sym_blob_size; i++) { sh ^= g_sym_blob[i]; sh *= hp; }
    char live_sym[17];
    snprintf(live_sym, sizeof(live_sym), "%016llx", (unsigned long long)sh);

    uint8_t rk[32], ek[32], mk[32];
    xor_mask_32(rk, g_rolling_key_masked);
    xor_mask_32(ek, g_enc_key_masked);
    xor_mask_32(mk, g_mac_key_masked);

    char auth_msg[512];
    int alen = snprintf(auth_msg, sizeof(auth_msg), "%s|%llu|%llu|%s|%s|%s",
            g_session_id, (unsigned long long)next_seq, (unsigned long long)ts,
            g_cached_hwid, g_cached_jar_hex, live_sym);
    uint8_t proof[32];
    hmac_sha256(rk, 32, (const uint8_t*)auth_msg, (size_t)alen, proof);
    char proof_hex[65];
    hex_encode(proof, 32, proof_hex);

    SymBuf sjs, surl, sep;
    char req_json[1024];
    snprintf(req_json, sizeof(req_json),
            "{\"%s\":\"%s\",\"seq\":%llu,\"ts\":%llu,\"hwid\":\"%s\",\"jarDigest\":\"%s\",\"symDigest\":\"%s\",\"proof\":\"%s\"}",
            decrypt_sym(HY_SYM_J_SESS, sjs), g_session_id, (unsigned long long)next_seq, (unsigned long long)ts,
            g_cached_hwid, g_cached_jar_hex, live_sym, proof_hex);

    const char* url = decrypt_sym(HY_SYM_SRV_URL, surl);
    const char* ep = decrypt_sym(HY_SYM_EP_HB, sep);
    char resp[4096];
    int status = 0;
    bool http_ok = http_post_json(url, ep, req_json, resp, sizeof(resp), status);
    secure_wipe(rk, sizeof(rk));
    secure_wipe(proof, sizeof(proof));

    if (!http_ok) {
        if (status == 401 || status == 403) {
            g_session_revoked = 1;
            poison_cookie();
        }
        return false;
    }

    SymBuf sjn, sjc, sjm;
    char nonce_hex[32] = {}, ct_hex[2048] = {}, mac_hex[80] = {};
    if (!json_get_str(resp, decrypt_sym(HY_SYM_J_NONCE, sjn), nonce_hex, sizeof(nonce_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_CT, sjc), ct_hex, sizeof(ct_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_MAC, sjm), mac_hex, sizeof(mac_hex))) {
        g_session_revoked = 1; poison_cookie(); return false;
    }
    uint8_t nonce12[12], mac[32];
    size_t ct_len = strlen(ct_hex) / 2u;
    if (ct_len == 0 || ct_len > 1024u) { g_session_revoked = 1; poison_cookie(); return false; }
    uint8_t* ct = (uint8_t*)heap_alloc(ct_len);
    uint8_t* pt = (uint8_t*)heap_alloc(ct_len + 1);
    if (!hex_decode(nonce_hex, strlen(nonce_hex), nonce12, 12)
            || !hex_decode(mac_hex, strlen(mac_hex), mac, 32)
            || !hex_decode(ct_hex, strlen(ct_hex), ct, ct_len)) {
        heap_free(ct); heap_free(pt); g_session_revoked = 1; poison_cookie(); return false;
    }

    char aad[160];
    int aad_len = snprintf(aad, sizeof(aad), "HB|%s|%llu", g_session_id, (unsigned long long)next_seq);
    size_t mac_in_len = (size_t)aad_len + 12u + ct_len;
    uint8_t* mac_in = (uint8_t*)heap_alloc(mac_in_len);
    memcpy(mac_in, aad, (size_t)aad_len);
    memcpy(mac_in + aad_len, nonce12, 12);
    memcpy(mac_in + aad_len + 12u, ct, ct_len);
    uint8_t expected_mac[32];
    hmac_sha256(mk, 32, mac_in, mac_in_len, expected_mac);
    heap_free(mac_in);

    bool mac_ok = ct_equal(expected_mac, mac, 32);
    if (mac_ok) {
        chacha20_xor(ek, nonce12, 1u, ct, ct_len, pt);
        pt[ct_len] = '\0';
        // Format: seq|nextRollingHex64|hbSec|leaseSec|1
        char* p1 = strchr((char*)pt, '|');
        char* p2 = p1 ? strchr(p1 + 1, '|') : nullptr;
        char* p3 = p2 ? strchr(p2 + 1, '|') : nullptr;
        char* p4 = p3 ? strchr(p3 + 1, '|') : nullptr;
        if (p1 && p2 && p3 && p4 && p4[1] == '1') {
            uint8_t next_rk[32];
            if (hex_decode(p1 + 1, (size_t)(p2 - (p1 + 1)), next_rk, 32)) {
                xor_mask_32(g_rolling_key_masked, next_rk);
                secure_wipe(next_rk, sizeof(next_rk));
                uint32_t hb = (uint32_t)atoi(p2 + 1);
                uint32_t lease = (uint32_t)atoi(p3 + 1);
                if (hb > 0) g_hb_interval_sec = hb;
                if (lease > 0) __atomic_store_n(&g_session_deadline_ms, monotonic_ms() + (uint64_t)lease * 1000ULL, __ATOMIC_RELEASE);
                g_session_seq = next_seq;
                secure_wipe(ek, sizeof(ek)); secure_wipe(mk, sizeof(mk));
                secure_wipe(pt, ct_len); heap_free(ct); heap_free(pt);
                return true;
            }
        }
    }
    secure_wipe(ek, sizeof(ek)); secure_wipe(mk, sizeof(mk));
    secure_wipe(pt, ct_len); heap_free(ct); heap_free(pt);
    g_session_revoked = 1;
    poison_cookie();
    return false;
}

#ifdef _WIN32
static DWORD WINAPI hb_thread_proc(void*) {
    hide_current_thread();
    while (!g_tampered && !g_session_revoked) {
        uint32_t iv = g_hb_interval_sec;
        if (iv < 1u) iv = 1u;
        Sleep(iv * 1000u);
        if (g_tampered || g_session_revoked) break;
        if (!send_heartbeat_once() && monotonic_ms() > __atomic_load_n(&g_session_deadline_ms, __ATOMIC_ACQUIRE)) {
            g_session_revoked = 1;
            poison_cookie();
            break;
        }
    }
    return 0;
}
#else
static void* hb_thread_proc(void*) {
    hide_current_thread();
    while (!g_tampered && !g_session_revoked) {
        uint32_t iv = g_hb_interval_sec;
        if (iv < 1u) iv = 1u;
        sleep(iv);
        if (g_tampered || g_session_revoked) break;
        if (!send_heartbeat_once() && monotonic_ms() > __atomic_load_n(&g_session_deadline_ms, __ATOMIC_ACQUIRE)) {
            g_session_revoked = 1;
            poison_cookie();
            break;
        }
    }
    return nullptr;
}
#endif

bool server_handshake(JNIEnv* env, uint64_t jar_digest, uint64_t* out_vm_share, uint64_t* out_vault_share) {
    *out_vm_share = 0;
    *out_vault_share = 0;

    compute_hwid(g_cached_hwid);
    snprintf(g_cached_jar_hex, sizeof(g_cached_jar_hex), "%016llx", (unsigned long long)jar_digest);

    const uint64_t _op = opaque_seed();
    uint64_t sh = HY_MBA_HASH_BASIS(_op);
    uint64_t hp = HY_MBA_HASH_PRIME(_op);
    for (uint32_t i = 0; i < g_sym_blob_size; i++) { sh ^= g_sym_blob[i]; sh *= hp; }
    snprintf(g_cached_sym_hex, sizeof(g_cached_sym_hex), "%016llx", (unsigned long long)sh);

    char lic_key[256] = {};
    resolve_license_key(env, lic_key, sizeof(lic_key));
    if (lic_key[0] == '\0') return false;

    uint8_t c_priv[32], c_pub[32], c_nonce[16];
    csprng(c_priv, 32);
    c_priv[0] &= 248u;
    c_priv[31] = (uint8_t)((c_priv[31] & 127u) | 64u);
    x25519_public(c_pub, c_priv);
    csprng(c_nonce, 16);

    uint8_t srv_static_pub[32];
    for (int i = 0; i < 32; i++) {
        srv_static_pub[i] = g_srv_pubkey_masked[i] ^ (uint8_t)((splitmix64(HY_MBA_PUBKEY_MASK(_op) + (uint64_t)i * 0x9E3779B97F4A7C15ULL) >> ((i & 7) * 8)) & 0xFFu);
    }

    uint8_t dh_static[32];
    x25519(dh_static, c_priv, srv_static_pub);
    secure_wipe(srv_static_pub, sizeof(srv_static_pub));

    SymBuf spro, sbld, surl, shsp, sep;
    const char* product_id = decrypt_sym(HY_SYM_PRODUCT_ID, spro);
    const char* build_id = decrypt_sym(HY_SYM_BUILD_ID, sbld);
    const char* url = decrypt_sym(HY_SYM_SRV_URL, surl);

    char hs_info[128];
    int hilen = snprintf(hs_info, sizeof(hs_info), "%s%s", decrypt_sym(HY_SYM_HS_PFX, shsp), build_id);
    uint8_t hs_auth_key[32];
    hkdf_sha256(c_nonce, 16, dh_static, 32, (const uint8_t*)hs_info, (size_t)hilen, hs_auth_key, 32);

    char cpub_hex[65], cnonce_hex[33];
    hex_encode(c_pub, 32, cpub_hex);
    hex_encode(c_nonce, 16, cnonce_hex);
    uint64_t ts = epoch_sec();

    char auth_msg[768];
    int amlen = snprintf(auth_msg, sizeof(auth_msg), "%s|%s|%s|%s|%s|%s|%llu|%s",
            product_id, build_id, lic_key, g_cached_hwid, g_cached_jar_hex, g_cached_sym_hex,
            (unsigned long long)ts, cpub_hex);
    uint8_t proof[32];
    hmac_sha256(hs_auth_key, 32, (const uint8_t*)auth_msg, (size_t)amlen, proof);
    char proof_hex[65];
    hex_encode(proof, 32, proof_hex);
    secure_wipe(hs_auth_key, sizeof(hs_auth_key));

    char req_json[1280];
    snprintf(req_json, sizeof(req_json),
            "{\"productId\":\"%s\",\"buildId\":\"%s\",\"licenseKey\":\"%s\",\"hwid\":\"%s\","
            "\"jarDigest\":\"%s\",\"symDigest\":\"%s\",\"clientPub\":\"%s\",\"clientNonce\":\"%s\",\"ts\":%llu,\"proof\":\"%s\"}",
            product_id, build_id, lic_key, g_cached_hwid, g_cached_jar_hex, g_cached_sym_hex,
            cpub_hex, cnonce_hex, (unsigned long long)ts, proof_hex);
    secure_wipe(lic_key, sizeof(lic_key));

    char resp[8192];
    int status = 0;
    if (!http_post_json(url, decrypt_sym(HY_SYM_EP_HS, sep), req_json, resp, sizeof(resp), status)) {
        secure_wipe(c_priv, sizeof(c_priv));
        secure_wipe(dh_static, sizeof(dh_static));
        return false;
    }

    SymBuf sj_sess, sj_seph, sj_snonce, sj_nonce, sj_ct, sj_mac;
    char sess_id[72] = {}, seph_hex[80] = {}, snonce_hex[40] = {}, nonce_hex[32] = {}, ct_hex[4096] = {}, mac_hex[80] = {};
    if (!json_get_str(resp, decrypt_sym(HY_SYM_J_SESS, sj_sess), sess_id, sizeof(sess_id))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_SEPH, sj_seph), seph_hex, sizeof(seph_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_SNONCE, sj_snonce), snonce_hex, sizeof(snonce_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_NONCE, sj_nonce), nonce_hex, sizeof(nonce_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_CT, sj_ct), ct_hex, sizeof(ct_hex))
            || !json_get_str(resp, decrypt_sym(HY_SYM_J_MAC, sj_mac), mac_hex, sizeof(mac_hex))) {
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
    uint8_t* pt = (uint8_t*)heap_alloc(ct_len + 1);
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
    int silen = snprintf(sess_info, sizeof(sess_info), "%s%s|%s", decrypt_sym(HY_SYM_SESS_PFX, ssp), build_id, g_cached_hwid);
    uint8_t master_key[32], enc_key[32], mac_key[32];
    hkdf_sha256(salt, 32, ikm, 64, (const uint8_t*)sess_info, (size_t)silen, master_key, 32);
    hkdf_expand(master_key, (const uint8_t*)"ENC", 3, enc_key, 32);
    hkdf_expand(master_key, (const uint8_t*)"MAC", 3, mac_key, 32);
    secure_wipe(ikm, sizeof(ikm));
    secure_wipe(master_key, sizeof(master_key));

    char aad[512];
    int aad_len = snprintf(aad, sizeof(aad), "%s|%s|%s|%s|%s", sess_id, build_id, g_cached_hwid, cpub_hex, seph_hex);
    size_t mac_in_len = (size_t)aad_len + 12u + ct_len;
    uint8_t* mac_in = (uint8_t*)heap_alloc(mac_in_len);
    memcpy(mac_in, aad, (size_t)aad_len);
    memcpy(mac_in + aad_len, nonce12, 12);
    memcpy(mac_in + aad_len + 12u, ct, ct_len);
    uint8_t exp_mac[32];
    hmac_sha256(mac_key, 32, mac_in, mac_in_len, exp_mac);
    heap_free(mac_in);

    bool ok = ct_equal(exp_mac, mac, 32);
    if (ok) {
        chacha20_xor(enc_key, nonce12, 1u, ct, ct_len, pt);
        pt[ct_len] = '\0';
        // Format: vmShareHex|vaultShareHex|rollingHex64|hbSec|leaseSec|dynParamsHex
        char* p1 = strchr((char*)pt, '|');
        char* p2 = p1 ? strchr(p1 + 1, '|') : nullptr;
        char* p3 = p2 ? strchr(p2 + 1, '|') : nullptr;
        char* p4 = p3 ? strchr(p3 + 1, '|') : nullptr;
        char* p5 = p4 ? strchr(p4 + 1, '|') : nullptr;
        if (p1 && p2 && p3 && p4 && p5) {
            *p1 = *p2 = *p3 = *p4 = *p5 = '\0';
            uint8_t vm_b[8], vs_b[8], rk[32];
            if (hex_decode((const char*)pt, strlen((const char*)pt), vm_b, 8)
                    && hex_decode(p1 + 1, strlen(p1 + 1), vs_b, 8)
                    && hex_decode(p2 + 1, strlen(p2 + 1), rk, 32)) {
                uint64_t vm_u = 0, vs_u = 0;
                for (int b = 0; b < 8; b++) {
                    vm_u = (vm_u << 8) | vm_b[b];
                    vs_u = (vs_u << 8) | vs_b[b];
                }
                *out_vm_share = vm_u;
                *out_vault_share = vs_u;

                const char* dp = p5 + 1;
                size_t dplen = strlen(dp);
                for (int d = 0; d < 8 && (size_t)(d * 16 + 16) <= dplen; d++) {
                    uint8_t db[8];
                    if (hex_decode(dp + d * 16, 16, db, 8)) {
                        uint64_t v = 0;
                        for (int b = 0; b < 8; b++) v = (v << 8) | db[b];
                        g_srv_dyn_params[d] = v ^ (uint64_t)g_ptr_cookie;
                    }
                }

                snprintf(g_session_id, sizeof(g_session_id), "%s", sess_id);
                xor_mask_32(g_enc_key_masked, enc_key);
                xor_mask_32(g_mac_key_masked, mac_key);
                xor_mask_32(g_rolling_key_masked, rk);
                secure_wipe(rk, sizeof(rk));

                uint32_t hb = (uint32_t)atoi(p3 + 1);
                uint32_t lease = (uint32_t)atoi(p4 + 1);
                g_hb_interval_sec = hb > 0 ? hb : 15u;
                uint64_t dl = monotonic_ms() + (uint64_t)(lease > 0 ? lease : 45u) * 1000ULL;
                __atomic_store_n(&g_session_deadline_ms, dl, __ATOMIC_RELEASE);
                g_session_seq = 0;
                g_session_established = 1;

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
