/**
 * YaNet — test_crypto.cpp
 * Unit tests for cryptographic operations
 */

#include "yanet/crypto.h"
#include "yanet/identity.h"
#include <iostream>
#include <cassert>
#include <cstring>

int main() {
    std::cout << "=== YaNet Crypto Tests ===" << std::endl;

    assert(yanet::CryptoEngine::initialize());

    // Test 1: Encrypt and decrypt with same key
    {
        std::cout << "Test 1: Encrypt/decrypt roundtrip... ";
        yanet::SharedKey key = {};
        yanet::CryptoEngine::randomBytes(key.data(), key.size());

        std::string original = "Hello, YaNet! This is a secret message.";
        yanet::ByteVector plaintext(original.begin(), original.end());

        auto ciphertext = yanet::CryptoEngine::encrypt(key, plaintext);
        assert(ciphertext.size() > plaintext.size());  // Nonce + MAC overhead

        auto decrypted = yanet::CryptoEngine::decrypt(key, ciphertext);
        assert(decrypted.has_value());
        assert(decrypted->size() == plaintext.size());
        assert(std::string(decrypted->begin(), decrypted->end()) == original);

        std::cout << "PASS" << std::endl;
    }

    // Test 2: Decryption with wrong key fails
    {
        std::cout << "Test 2: Wrong key detection... ";
        yanet::SharedKey key1 = {}, key2 = {};
        yanet::CryptoEngine::randomBytes(key1.data(), key1.size());
        yanet::CryptoEngine::randomBytes(key2.data(), key2.size());

        std::string msg = "Secret data";
        yanet::ByteVector plain(msg.begin(), msg.end());

        auto cipher = yanet::CryptoEngine::encrypt(key1, plain);
        auto result = yanet::CryptoEngine::decrypt(key2, cipher);
        assert(!result.has_value());  // Must fail

        std::cout << "PASS" << std::endl;
    }

    // Test 3: Tampered ciphertext detection
    {
        std::cout << "Test 3: Tamper detection... ";
        yanet::SharedKey key = {};
        yanet::CryptoEngine::randomBytes(key.data(), key.size());

        std::string msg = "Integrity check";
        yanet::ByteVector plain(msg.begin(), msg.end());

        auto cipher = yanet::CryptoEngine::encrypt(key, plain);
        // Tamper with ciphertext (flip a byte after the nonce)
        cipher[yanet::NONCE_SIZE + 5] ^= 0xFF;

        auto result = yanet::CryptoEngine::decrypt(key, cipher);
        assert(!result.has_value());  // Must detect tampering

        std::cout << "PASS" << std::endl;
    }

    // Test 4: Key exchange produces matching session keys
    {
        std::cout << "Test 4: Key exchange... ";

        // Generate two identities
        yanet::Identity alice, bob;
        assert(alice.generate());
        assert(bob.generate());

        // Alice computes shared secret with Bob's public key
        auto aliceShared = yanet::CryptoEngine::computeSharedSecret(
            alice.secretKey(), bob.publicKey()
        );

        // Bob computes shared secret with Alice's public key
        auto bobShared = yanet::CryptoEngine::computeSharedSecret(
            bob.secretKey(), alice.publicKey()
        );

        // Both should derive the same shared secret (X25519 property)
        assert(aliceShared == bobShared);

        // Derive session keys (initiator = alice, responder = bob)
        auto aliceSession = yanet::CryptoEngine::deriveSessionKey(
            aliceShared, alice.address(), bob.address()
        );
        auto bobSession = yanet::CryptoEngine::deriveSessionKey(
            bobShared, alice.address(), bob.address()
        );

        assert(aliceSession == bobSession);

        // Test cross-encryption
        std::string msg = "Encrypted P2P message!";
        yanet::ByteVector plain(msg.begin(), msg.end());

        auto cipher = yanet::CryptoEngine::encrypt(aliceSession, plain);
        auto decrypted = yanet::CryptoEngine::decrypt(bobSession, cipher);
        assert(decrypted.has_value());
        assert(std::string(decrypted->begin(), decrypted->end()) == msg);

        std::cout << "PASS" << std::endl;
    }

    // Test 5: Session key derivation is role-dependent
    {
        std::cout << "Test 5: Role-dependent session keys... ";
        yanet::SharedKey shared = {};
        yanet::CryptoEngine::randomBytes(shared.data(), shared.size());

        yanet::Identity a, b;
        a.generate();
        b.generate();

        auto key1 = yanet::CryptoEngine::deriveSessionKey(shared, a.address(), b.address());
        auto key2 = yanet::CryptoEngine::deriveSessionKey(shared, b.address(), a.address());

        // Different initiator/responder order → different session key
        assert(key1 != key2);

        std::cout << "PASS" << std::endl;
    }

    // Test 6: Random bytes are non-zero
    {
        std::cout << "Test 6: Random bytes... ";
        uint8_t buf[32] = {};
        yanet::CryptoEngine::randomBytes(buf, sizeof(buf));
        bool allZero = true;
        for (auto b : buf) if (b != 0) allZero = false;
        assert(!allZero);
        std::cout << "PASS" << std::endl;
    }

    std::cout << "\n=== All crypto tests PASSED ===" << std::endl;
    return 0;
}
