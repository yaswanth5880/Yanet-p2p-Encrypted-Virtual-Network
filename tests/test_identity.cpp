/**
 * YaNet — test_identity.cpp
 * Unit tests for cryptographic identity
 */

#include "yanet/identity.h"
#include "yanet/crypto.h"
#include <iostream>
#include <cassert>
#include <filesystem>

namespace fs = std::filesystem;

int main() {
    std::cout << "=== YaNet Identity Tests ===" << std::endl;

    // Initialize crypto
    assert(yanet::CryptoEngine::initialize());

    // Test 1: Generate identity
    {
        std::cout << "Test 1: Generate identity... ";
        yanet::Identity id;
        assert(id.generate());
        assert(id.isValid());
        assert(!id.address().isZero());
        assert(id.address().toString().size() == 10);
        std::cout << "PASS (address: " << id.address().toString() << ")" << std::endl;
    }

    // Test 2: Two identities should be different
    {
        std::cout << "Test 2: Unique identities... ";
        yanet::Identity id1, id2;
        assert(id1.generate());
        assert(id2.generate());
        assert(id1.address() != id2.address());
        assert(id1.publicKey() != id2.publicKey());
        std::cout << "PASS" << std::endl;
    }

    // Test 3: Save and load identity
    {
        std::cout << "Test 3: Save/load roundtrip... ";
        std::string testFile = "test_identity_temp.json";

        yanet::Identity original;
        assert(original.generate());
        assert(original.saveToFile(testFile));

        yanet::Identity loaded;
        assert(loaded.loadFromFile(testFile));
        assert(loaded.isValid());
        assert(loaded.address() == original.address());
        assert(loaded.publicKey() == original.publicKey());
        assert(loaded.secretKey() == original.secretKey());

        fs::remove(testFile);
        std::cout << "PASS" << std::endl;
    }

    // Test 4: Address derivation is deterministic
    {
        std::cout << "Test 4: Deterministic address... ";
        yanet::Identity id;
        assert(id.generate());
        auto addr1 = id.deriveAddress();
        auto addr2 = id.deriveAddress();
        assert(addr1 == addr2);
        std::cout << "PASS" << std::endl;
    }

    // Test 5: NodeAddress string roundtrip
    {
        std::cout << "Test 5: NodeAddress string roundtrip... ";
        yanet::Identity id;
        assert(id.generate());
        std::string addrStr = id.address().toString();
        auto parsed = yanet::NodeAddress::fromString(addrStr);
        assert(parsed == id.address());
        std::cout << "PASS" << std::endl;
    }

    std::cout << "\n=== All identity tests PASSED ===" << std::endl;
    return 0;
}
