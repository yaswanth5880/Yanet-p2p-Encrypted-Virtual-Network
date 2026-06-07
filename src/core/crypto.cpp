/**
 * YaNet — crypto.cpp
 * Cryptographic operations using libsodium
 */

#include "yanet/crypto.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

namespace yanet {

CryptoEngine::CryptoEngine() = default;

bool CryptoEngine::initialize() {
    if (sodium_init() < 0) {
        std::cerr << "[YaNet] FATAL: libsodium initialization failed!" << std::endl;
        return false;
    }
    std::cout << "[YaNet] Crypto engine initialized (libsodium "
              << sodium_version_string() << ")" << std::endl;
    return true;
}

// ============================================================================
// Key Exchange
// ============================================================================

SharedKey CryptoEngine::computeSharedSecret(const SecretKey& ourSecret,
                                             const PublicKey& theirPublic) {
    SharedKey shared = {};

    // X25519 scalar multiplication
    if (crypto_scalarmult(shared.data(), ourSecret.data(), theirPublic.data()) != 0) {
        std::cerr << "[YaNet] Key exchange failed" << std::endl;
        secureZero(shared.data(), shared.size());
    }

    return shared;
}

SharedKey CryptoEngine::deriveSessionKey(const SharedKey& sharedSecret,
                                          const NodeAddress& initiator,
                                          const NodeAddress& responder) {
    SharedKey sessionKey = {};

    // Use BLAKE2b to derive session key from shared secret + both addresses
    // This ensures the same shared secret produces different session keys
    // depending on who initiated the connection
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, SHARED_KEY_SIZE);
    crypto_generichash_update(&state, sharedSecret.data(), SHARED_KEY_SIZE);
    crypto_generichash_update(&state, initiator.bytes.data(), ADDRESS_HASH_SIZE);
    crypto_generichash_update(&state, responder.bytes.data(), ADDRESS_HASH_SIZE);
    crypto_generichash_final(&state, sessionKey.data(), SHARED_KEY_SIZE);

    return sessionKey;
}

// ============================================================================
// Authenticated Encryption (XChaCha20-Poly1305)
// ============================================================================

ByteVector CryptoEngine::encrypt(const SharedKey& key,
                                  const uint8_t* plaintext, size_t len) {
    // Output: [nonce (24 bytes)][ciphertext + MAC]
    ByteVector output(NONCE_SIZE + len + MAC_SIZE);

    // Generate random nonce
    randombytes_buf(output.data(), NONCE_SIZE);

    // Encrypt with XChaCha20-Poly1305
    unsigned long long cipherLen = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        output.data() + NONCE_SIZE, &cipherLen,
        plaintext, len,
        nullptr, 0,       // no additional data
        nullptr,          // nsec (unused)
        output.data(),    // nonce
        key.data()        // key
    );

    output.resize(NONCE_SIZE + static_cast<size_t>(cipherLen));
    return output;
}

ByteVector CryptoEngine::encrypt(const SharedKey& key, const ByteVector& plaintext) {
    return encrypt(key, plaintext.data(), plaintext.size());
}

std::optional<ByteVector> CryptoEngine::decrypt(const SharedKey& key,
                                                  const uint8_t* ciphertext, size_t len) {
    if (len < NONCE_SIZE + MAC_SIZE) {
        return std::nullopt;  // Too short to contain nonce + MAC
    }

    size_t cipherLen = len - NONCE_SIZE;
    ByteVector plaintext(cipherLen - MAC_SIZE);

    unsigned long long plainLen = 0;
    int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(), &plainLen,
        nullptr,                          // nsec (unused)
        ciphertext + NONCE_SIZE, cipherLen, // ciphertext after nonce
        nullptr, 0,                        // no additional data
        ciphertext,                        // nonce (first 24 bytes)
        key.data()                         // key
    );

    if (result != 0) {
        return std::nullopt;  // Decryption failed (wrong key or tampered data)
    }

    plaintext.resize(static_cast<size_t>(plainLen));
    return plaintext;
}

std::optional<ByteVector> CryptoEngine::decrypt(const SharedKey& key,
                                                  const ByteVector& ciphertext) {
    return decrypt(key, ciphertext.data(), ciphertext.size());
}

// ============================================================================
// Utilities
// ============================================================================

void CryptoEngine::randomBytes(uint8_t* buf, size_t len) {
    randombytes_buf(buf, len);
}

uint64_t CryptoEngine::randomU64() {
    uint64_t val;
    randombytes_buf(&val, sizeof(val));
    return val;
}

bool CryptoEngine::secureCompare(const uint8_t* a, const uint8_t* b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

void CryptoEngine::secureZero(void* ptr, size_t len) {
    sodium_memzero(ptr, len);
}

} // namespace yanet
