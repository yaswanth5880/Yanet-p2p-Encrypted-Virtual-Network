/**
 * YaNet — identity.cpp
 * Cryptographic identity generation and management
 */

#include "yanet/identity.h"
#include "yanet/crypto.h"

#include <sodium.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace yanet {

Identity::Identity() = default;

bool Identity::generate() {
    secretKey_ = {};
    publicKey_ = {};

    if (crypto_box_keypair(publicKey_.data(), secretKey_.data()) != 0) {
        std::cerr << "[YaNet] Failed to generate keypair" << std::endl;
        return false;
    }

    // Derive node address from public key
    address_ = deriveAddress();
    valid_ = true;

    std::cout << "[YaNet] Generated new identity: " << address_.toString() << std::endl;
    return true;
}

NodeAddress Identity::deriveAddress() const {
    // BLAKE2b hash of public key, truncated to 5 bytes (40 bits)
    NodeAddress addr;
    std::array<uint8_t, crypto_generichash_BYTES_MIN> fullHash;
    crypto_generichash_blake2b(
        fullHash.data(), fullHash.size(),
        publicKey_.data(), PUBLIC_KEY_SIZE,
        nullptr, 0  // no key
    );
    std::memcpy(addr.bytes.data(), fullHash.data(), ADDRESS_HASH_SIZE);
    return addr;
}

bool Identity::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }

    // Simple custom JSON-like parsing (no external dependency for phase 1)
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    // Find and parse public key hex
    auto extractHex = [&](const std::string& key) -> std::string {
        auto pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = content.find("\"", pos + key.size() + 2);
        if (pos == std::string::npos) return "";
        auto end = content.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        return content.substr(pos + 1, end - pos - 1);
    };

    std::string pubHex = extractHex("publicKey");
    std::string secHex = extractHex("secretKey");

    if (pubHex.size() != PUBLIC_KEY_SIZE * 2 || secHex.size() != SECRET_KEY_SIZE * 2) {
        std::cerr << "[YaNet] Invalid identity file format" << std::endl;
        return false;
    }

    // Decode hex to bytes
    auto hexToBytes = [](const std::string& hex, uint8_t* out, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
        }
    };

    hexToBytes(pubHex, publicKey_.data(), PUBLIC_KEY_SIZE);
    hexToBytes(secHex, secretKey_.data(), SECRET_KEY_SIZE);

    address_ = deriveAddress();
    valid_ = true;

    std::cout << "[YaNet] Loaded identity: " << address_.toString() << std::endl;
    return true;
}

bool Identity::saveToFile(const std::string& path) const {
    if (!valid_) return false;

    auto bytesToHex = [](const uint8_t* data, size_t len) -> std::string {
        std::ostringstream oss;
        for (size_t i = 0; i < len; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
        }
        return oss.str();
    };

    std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "[YaNet] Cannot write to " << path << std::endl;
        return false;
    }

    file << "{\n";
    file << "  \"address\": \"" << address_.toString() << "\",\n";
    file << "  \"publicKey\": \"" << bytesToHex(publicKey_.data(), PUBLIC_KEY_SIZE) << "\",\n";
    file << "  \"secretKey\": \"" << bytesToHex(secretKey_.data(), SECRET_KEY_SIZE) << "\"\n";
    file << "}\n";

    file.close();
    std::cout << "[YaNet] Saved identity to " << path << std::endl;
    return true;
}

std::string Identity::toString() const {
    std::ostringstream oss;
    oss << "Identity[" << address_.toString() << "]";
    if (!valid_) oss << " (invalid)";
    return oss.str();
}

} // namespace yanet
