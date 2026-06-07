/**
 * YaNet — A Peer-to-Peer Virtual Network
 * crypto.h — Cryptographic operations
 *
 * Wraps libsodium to provide:
 * - X25519 Diffie-Hellman key exchange
 * - XChaCha20-Poly1305 authenticated encryption (AEAD)
 * - Session key derivation
 * - Secure random number generation
 */

#pragma once

#include "types.h"
#include <optional>

namespace yanet {

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine() = default;

    // Initialize libsodium (must be called once at startup)
    static bool initialize();

    // ========================================================================
    // Key Exchange
    // ========================================================================

    // Compute shared secret from our secret key + their public key (X25519)
    static SharedKey computeSharedSecret(const SecretKey& ourSecret,
                                         const PublicKey& theirPublic);

    // Derive a session key from shared secret using BLAKE2b
    static SharedKey deriveSessionKey(const SharedKey& sharedSecret,
                                      const NodeAddress& initiator,
                                      const NodeAddress& responder);

    // ========================================================================
    // Authenticated Encryption (XChaCha20-Poly1305)
    // ========================================================================

    // Encrypt data with session key. Returns ciphertext (nonce prepended).
    static ByteVector encrypt(const SharedKey& key,
                              const uint8_t* plaintext, size_t len);

    static ByteVector encrypt(const SharedKey& key, const ByteVector& plaintext);

    // Decrypt data with session key. Input must have nonce prepended.
    static std::optional<ByteVector> decrypt(const SharedKey& key,
                                              const uint8_t* ciphertext, size_t len);

    static std::optional<ByteVector> decrypt(const SharedKey& key,
                                              const ByteVector& ciphertext);

    // ========================================================================
    // Utilities
    // ========================================================================

    // Generate cryptographically secure random bytes
    static void randomBytes(uint8_t* buf, size_t len);

    // Generate a random 64-bit number
    static uint64_t randomU64();

    // Constant-time memory comparison
    static bool secureCompare(const uint8_t* a, const uint8_t* b, size_t len);

    // Securely zero memory
    static void secureZero(void* ptr, size_t len);
};

} // namespace yanet
