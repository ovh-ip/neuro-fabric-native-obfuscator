#include "hydro_runtime.hpp"
#include "hydro_crypto.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace hy {

static HY_FORCEINLINE uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }
static HY_FORCEINLINE uint32_t rotl32(uint32_t x, uint32_t n) { return (x << n) | (x >> (32u - n)); }

static HY_FORCEINLINE uint32_t load_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static HY_FORCEINLINE void store_be32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static HY_FORCEINLINE uint32_t load_le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static HY_FORCEINLINE void store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buf[64];
    size_t buf_len;
};

static void sha256_transform(uint32_t st[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

static void sha256_init(Sha256Ctx& ctx) {
    ctx.state[0] = 0x6a09e667u; ctx.state[1] = 0xbb67ae85u;
    ctx.state[2] = 0x3c6ef372u; ctx.state[3] = 0xa54ff53au;
    ctx.state[4] = 0x510e527fu; ctx.state[5] = 0x9b05688cu;
    ctx.state[6] = 0x1f83d9abu; ctx.state[7] = 0x5be0cd19u;
    ctx.total_len = 0;
    ctx.buf_len = 0;
}

static void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
    ctx.total_len += len;
    while (len > 0) {
        size_t take = 64u - ctx.buf_len;
        if (take > len) take = len;
        memcpy(ctx.buf + ctx.buf_len, data, take);
        ctx.buf_len += take;
        data += take;
        len -= take;
        if (ctx.buf_len == 64u) {
            sha256_transform(ctx.state, ctx.buf);
            ctx.buf_len = 0;
        }
    }
}

static void sha256_final(Sha256Ctx& ctx, uint8_t out32[32]) {
    uint64_t bit_len = ctx.total_len * 8ULL;
    ctx.buf[ctx.buf_len++] = 0x80u;
    if (ctx.buf_len > 56u) {
        while (ctx.buf_len < 64u) ctx.buf[ctx.buf_len++] = 0;
        sha256_transform(ctx.state, ctx.buf);
        ctx.buf_len = 0;
    }
    while (ctx.buf_len < 56u) ctx.buf[ctx.buf_len++] = 0;
    for (int i = 0; i < 8; i++) ctx.buf[56 + i] = (uint8_t)(bit_len >> (56 - i * 8));
    sha256_transform(ctx.state, ctx.buf);
    for (int i = 0; i < 8; i++) store_be32(out32 + i * 4, ctx.state[i]);
    secure_wipe(&ctx, sizeof(ctx));
}

void sha256(const uint8_t* data, size_t len, uint8_t out32[32]) {
    Sha256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, data, len);
    sha256_final(ctx, out32);
}

void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* data, size_t dlen, uint8_t out32[32]) {
    uint8_t k0[64];
    memset(k0, 0, sizeof(k0));
    if (klen > 64u) {
        sha256(key, klen, k0);
    } else if (klen > 0u) {
        memcpy(k0, key, klen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    Sha256Ctx ctx;
    sha256_init(ctx);
    sha256_update(ctx, ipad, 64);
    sha256_update(ctx, data, dlen);
    uint8_t inner[32];
    sha256_final(ctx, inner);

    sha256_init(ctx);
    sha256_update(ctx, opad, 64);
    sha256_update(ctx, inner, 32);
    sha256_final(ctx, out32);

    secure_wipe(k0, sizeof(k0));
    secure_wipe(ipad, sizeof(ipad));
    secure_wipe(opad, sizeof(opad));
    secure_wipe(inner, sizeof(inner));
}

void hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    uint8_t t[32];
    size_t tlen = 0;
    size_t pos = 0;
    uint8_t ctr = 1;
    uint8_t msg[256];
    while (pos < out_len) {
        size_t need = tlen + info_len + 1u;
        uint8_t* buf = need <= sizeof(msg) ? msg : (uint8_t*)heap_alloc(need);
        if (tlen > 0) memcpy(buf, t, tlen);
        if (info_len > 0) memcpy(buf + tlen, info, info_len);
        buf[tlen + info_len] = ctr++;
        hmac_sha256(prk, 32, buf, need, t);
        if (buf != msg) { secure_wipe(buf, need); heap_free(buf); }
        tlen = 32;
        size_t take = out_len - pos;
        if (take > 32u) take = 32u;
        memcpy(out + pos, t, take);
        pos += take;
    }
    secure_wipe(t, sizeof(t));
    secure_wipe(msg, sizeof(msg));
}

void hkdf_sha256(const uint8_t* salt, size_t slen, const uint8_t* ikm, size_t ilen, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    uint8_t zero_salt[32];
    memset(zero_salt, 0, sizeof(zero_salt));
    const uint8_t* eff_salt = (salt && slen > 0) ? salt : zero_salt;
    size_t eff_slen = (salt && slen > 0) ? slen : 32u;
    uint8_t prk[32];
    hmac_sha256(eff_salt, eff_slen, ikm, ilen, prk);
    hkdf_expand(prk, info, info_len, out, out_len);
    secure_wipe(prk, sizeof(prk));
}

// TweetNaCl-exact RFC 7748 X25519 over 16x int64_t limbs (portable across 32/64-bit compilers)
using gf = int64_t[16];

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += 65536LL;
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1LL + 37LL * (c - 1LL) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void unpack25519(gf o, const uint8_t* n) {
    for (int i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7FFFLL;
}

static void pack25519(uint8_t* o, const gf n) {
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFEDLL;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFFLL - ((m[i - 1] >> 16) & 1LL);
            m[i - 1] &= 0xFFFFLL;
        }
        m[15] = t[15] - 0x7FFFLL - ((m[14] >> 16) & 1LL);
        int b = (int)((m[15] >> 16) & 1LL);
        m[14] &= 0xFFFFLL;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void gf_add(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void gf_sub(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void gf_mul(gf o, const gf a, const gf b) {
    int64_t t[31] = {};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    }
    for (int i = 0; i < 15; i++) t[i] += 38LL * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_sqr(gf o, const gf a) { gf_mul(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        gf_sqr(c, c);
        if (a != 2 && a != 4) gf_mul(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

void x25519(uint8_t out32[32], const uint8_t scalar32[32], const uint8_t point32[32]) {
    uint8_t z[32];
    memcpy(z, scalar32, 32);
    z[0] &= 248u;
    z[31] = (uint8_t)((z[31] & 127u) | 64u);

    gf x = {}, a = {}, b = {}, c = {}, d = {}, e = {}, f = {};
    gf _121665 = {0xDB41LL, 1LL};
    unpack25519(x, point32);
    for (int i = 0; i < 16; i++) b[i] = x[i];
    a[0] = d[0] = 1LL;

    for (int i = 254; i >= 0; i--) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, _121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    gf_mul(a, a, c);
    pack25519(out32, a);
    secure_wipe(z, sizeof(z));
}

void x25519_public(uint8_t out_pub[32], const uint8_t priv32[32]) {
    uint8_t base[32] = {};
    base[0] = 9u;
    x25519(out_pub, priv32, base);
}

static HY_FORCEINLINE void qr(uint32_t x[16], int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
}

void chacha20_xor(const uint8_t key32[32], const uint8_t nonce12[12], uint32_t counter, const uint8_t* in, size_t len, uint8_t* out) {
    uint32_t state[16];
    state[0] = 0x61707865u; state[1] = 0x3320646eu;
    state[2] = 0x79622d32u; state[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) state[4 + i] = load_le32(key32 + i * 4);
    state[12] = counter;
    for (int i = 0; i < 3; i++) state[13 + i] = load_le32(nonce12 + i * 4);

    size_t off = 0;
    uint8_t ks[64];
    while (off < len) {
        uint32_t x[16];
        memcpy(x, state, sizeof(x));
        for (int i = 0; i < 10; i++) {
            qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) store_le32(ks + i * 4, x[i] + state[i]);
        size_t n = len - off;
        if (n > 64u) n = 64u;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        state[12]++;
        off += n;
    }
    secure_wipe(state, sizeof(state));
    secure_wipe(ks, sizeof(ks));
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0u;
}

void csprng(uint8_t* out, size_t len) {
    bool ok = false;
#ifdef _WIN32
    uintptr_t hBc = load_sys_module(HY_HASH_BCRYPT, HY_SYM_BCRYPT_DLL);
    if (hBc) {
        using FnBCryptGenRandom = LONG(WINAPI*)(void*, uint8_t*, ULONG, ULONG);
        auto pGen = reinterpret_cast<FnBCryptGenRandom>(resolve_export(hBc, HY_HASH_BCRYPT_GEN));
        if (pGen && pGen(nullptr, out, (ULONG)len, 0x00000002u) == 0) {
            ok = true;
        }
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t got = 0;
        while (got < len) {
            ssize_t r = read(fd, out + got, len - got);
            if (r <= 0) break;
            got += (size_t)r;
        }
        close(fd);
        ok = (got == len);
    }
#endif
    if (!ok) {
        uint64_t seed = hy_tick() ^ (uint64_t)(uintptr_t)out ^ g_rt_entropy;
        for (size_t i = 0; i < len; i++) {
            seed = splitmix64(seed + (uint64_t)i);
            out[i] = (uint8_t)(seed >> ((i & 7u) * 8u));
        }
    }
}

void hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char HEX[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = HEX[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = HEX[in[i] & 0xF];
    }
    out[2 * len] = '\0';
}

static inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const char* hex, size_t hex_len, uint8_t* out, size_t expected_bytes) {
    if (!hex || hex_len != expected_bytes * 2u) return false;
    for (size_t i = 0; i < expected_bytes; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

} // namespace hy
