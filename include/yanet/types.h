/**
 * YaNet — A Peer-to-Peer Virtual Network
 * types.h — Core type definitions
 */

#pragma once

#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <chrono>
#include <memory>
#include <functional>
#include <sstream>
#include <iomanip>

namespace yanet {

// ============================================================================
// Cryptographic Constants
// ============================================================================

// X25519 key sizes
constexpr size_t PUBLIC_KEY_SIZE  = 32;
constexpr size_t SECRET_KEY_SIZE  = 32;
constexpr size_t SHARED_KEY_SIZE  = 32;

// XChaCha20-Poly1305 sizes
constexpr size_t NONCE_SIZE       = 24;
constexpr size_t MAC_SIZE         = 16;

// BLAKE2b hash output for address derivation
constexpr size_t ADDRESS_HASH_SIZE = 5;  // 40-bit address

// ============================================================================
// Core Types
// ============================================================================

using PublicKey  = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using SecretKey  = std::array<uint8_t, SECRET_KEY_SIZE>;
using SharedKey  = std::array<uint8_t, SHARED_KEY_SIZE>;
using Nonce      = std::array<uint8_t, NONCE_SIZE>;
using ByteVector = std::vector<uint8_t>;
using Timestamp  = std::chrono::steady_clock::time_point;

// ============================================================================
// Node Address — 40-bit (5 byte) unique identifier derived from public key
// Displayed as 10-char hex string (e.g., "a1b2c3d4e5")
// ============================================================================

struct NodeAddress {
    std::array<uint8_t, ADDRESS_HASH_SIZE> bytes = {};

    NodeAddress() = default;

    explicit NodeAddress(const std::array<uint8_t, ADDRESS_HASH_SIZE>& b) : bytes(b) {}

    // Convert to 10-char hex string
    std::string toString() const {
        std::ostringstream oss;
        for (auto b : bytes) {
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    }

    // Parse from hex string
    static NodeAddress fromString(const std::string& hex) {
        NodeAddress addr;
        if (hex.size() != ADDRESS_HASH_SIZE * 2) return addr;
        for (size_t i = 0; i < ADDRESS_HASH_SIZE; ++i) {
            addr.bytes[i] = static_cast<uint8_t>(
                std::stoi(hex.substr(i * 2, 2), nullptr, 16)
            );
        }
        return addr;
    }

    bool operator==(const NodeAddress& other) const { return bytes == other.bytes; }
    bool operator!=(const NodeAddress& other) const { return bytes != other.bytes; }
    bool operator<(const NodeAddress& other) const  { return bytes < other.bytes; }

    bool isZero() const {
        for (auto b : bytes) if (b != 0) return false;
        return true;
    }
};

// ============================================================================
// Network Endpoint — IP:Port pair
// ============================================================================

struct Endpoint {
    uint32_t ip   = 0;    // IPv4 in network byte order
    uint16_t port = 0;    // Port in host byte order

    Endpoint() = default;
    Endpoint(uint32_t ip_, uint16_t port_) : ip(ip_), port(port_) {}

    bool operator==(const Endpoint& o) const { return ip == o.ip && port == o.port; }
    bool operator!=(const Endpoint& o) const { return !(*this == o); }

    std::string toString() const;  // Defined in transport.cpp

    bool isValid() const { return ip != 0 && port != 0; }
};

// ============================================================================
// Network ID — 64-bit identifier for a virtual network
// ============================================================================

struct NetworkId {
    uint64_t id = 0;

    NetworkId() = default;
    explicit NetworkId(uint64_t id_) : id(id_) {}

    std::string toString() const {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0') << std::setw(16) << id;
        return oss.str();
    }

    static NetworkId fromString(const std::string& hex) {
        return NetworkId(std::stoull(hex, nullptr, 16));
    }

    bool operator==(const NetworkId& o) const { return id == o.id; }
    bool operator!=(const NetworkId& o) const { return id != o.id; }
    bool operator<(const NetworkId& o) const  { return id < o.id; }
};

// ============================================================================
// Packet Types
// ============================================================================

enum class PacketType : uint8_t {
    HELLO       = 0x01,  // Initial handshake: send public key
    HELLO_ACK   = 0x02,  // Handshake response: send public key + encrypted ack
    DATA        = 0x03,  // Encrypted data payload (tunneled IP packet)
    KEEPALIVE   = 0x04,  // Keep connection alive
    PEER_INFO   = 0x05,  // Share known peer endpoints
    REGISTER    = 0x10,  // Register with rendezvous server
    LOOKUP      = 0x11,  // Look up peer on rendezvous server
    LOOKUP_RESP = 0x12,  // Rendezvous response with peer endpoint
    PUNCH       = 0x13,  // NAT hole-punch probe
    NETWORK_JOIN  = 0x20, // Request to join a virtual network
    NETWORK_LEAVE = 0x21, // Leave a virtual network
    NETWORK_CONFIG = 0x22, // Network configuration update
};

// ============================================================================
// Peer State
// ============================================================================

enum class PeerState {
    UNKNOWN,        // Never contacted
    HANDSHAKING,    // HELLO sent, waiting for HELLO_ACK
    ESTABLISHED,    // Handshake complete, session keys active
    STALE,          // No recent keepalive
    DEAD            // Timed out
};

// ============================================================================
// Result type for operations that can fail
// ============================================================================

template<typename T>
struct Result {
    T value;
    bool ok = false;
    std::string error;

    static Result<T> success(T val) { return { std::move(val), true, "" }; }
    static Result<T> failure(const std::string& err) { return { T{}, false, err }; }
};

// Specialization for void
template<>
struct Result<void> {
    bool ok = false;
    std::string error;

    static Result<void> success() { return { true, "" }; }
    static Result<void> failure(const std::string& err) { return { false, err }; }
};

} // namespace yanet
