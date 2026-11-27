#pragma once

#include <stdint.h>
#include <stddef.h>

namespace hy {

void sha256(const uint8_t* data, size_t len, uint8_t out32[32]);
void hmac_sha256(const uint8_t* key, size_t klen, const uint8_t* data, size_t dlen, uint8_t out32[32]);
void hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);
void hkdf_sha256(const uint8_t* salt, size_t slen, const uint8_t* ikm, size_t ilen, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len);

void x25519(uint8_t out32[32], const uint8_t scalar32[32], const uint8_t point32[32]);
void x25519_public(uint8_t out_pub[32], const uint8_t priv32[32]);

void chacha20_xor(const uint8_t key32[32], const uint8_t nonce12[12], uint32_t counter, const uint8_t* in, size_t len, uint8_t* out);

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len);
void csprng(uint8_t* out, size_t len);

void hex_encode(const uint8_t* in, size_t len, char* out);
bool hex_decode(const char* hex, size_t hex_len, uint8_t* out, size_t expected_bytes);

} // namespace hy
