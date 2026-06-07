/**
 * YaNet — A Peer-to-Peer Virtual Network
 * identity.h — Cryptographic identity management
 *
 * Every YaNet node has a unique identity consisting of:
 * - An X25519 keypair (public + secret key)
 * - A 40-bit node address derived from BLAKE2b hash of the public key
 *
 * The identity is persisted to disk as a JSON file.
 */

#pragma once

#include "types.h"
#include <string>

namespace yanet {

class Identity {
public:
    Identity();
    ~Identity() = default;

    // Generate a brand new identity (new keypair)
    bool generate();

    // Load identity from a file (JSON format)
    bool loadFromFile(const std::string& path);

    // Save identity to a file (JSON format)
    bool saveToFile(const std::string& path) const;

    // Derive node address from public key (BLAKE2b hash, truncated to 5 bytes)
    NodeAddress deriveAddress() const;

    // Getters
    const PublicKey& publicKey() const { return publicKey_; }
    const SecretKey& secretKey() const { return secretKey_; }
    const NodeAddress& address() const { return address_; }

    // Check if identity has been generated/loaded
    bool isValid() const { return valid_; }

    // Get a human-readable summary
    std::string toString() const;

    // Compare identities by address
    bool operator==(const Identity& other) const { return address_ == other.address_; }

private:
    PublicKey   publicKey_ = {};
    SecretKey   secretKey_ = {};
    NodeAddress address_;
    bool        valid_ = false;
};

} // namespace yanet
