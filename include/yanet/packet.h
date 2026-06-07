/**
 * YaNet — A Peer-to-Peer Virtual Network
 * packet.h — Wire protocol packet format
 *
 * Packet wire format:
 *   [Magic: 4 bytes]["YNET"]
 *   [Version: 1 byte]
 *   [Type: 1 byte]
 *   [Source Address: 5 bytes]
 *   [Destination Address: 5 bytes]
 *   [Sequence: 4 bytes]
 *   [Payload Length: 2 bytes]
 *   [Payload: variable]
 *
 * Total header size: 22 bytes
 */

#pragma once

#include "types.h"
#include "version.h"
#include <optional>
#include <cstring>

namespace yanet {

// Packet header size: 4(magic) + 1(ver) + 1(type) + 5(src) + 5(dst) + 4(seq) + 2(len) = 22
constexpr size_t PACKET_HEADER_SIZE = 22;
constexpr size_t PACKET_MAX_PAYLOAD = YANET_MAX_PACKET_SIZE - PACKET_HEADER_SIZE;

struct PacketHeader {
    uint32_t    magic    = YANET_PACKET_MAGIC;
    uint8_t     version  = YANET_PROTOCOL_VERSION;
    PacketType  type     = PacketType::DATA;
    NodeAddress source;
    NodeAddress dest;
    uint32_t    sequence = 0;
    uint16_t    payloadLength = 0;
};

class Packet {
public:
    Packet();
    explicit Packet(PacketType type);
    Packet(PacketType type, const NodeAddress& src, const NodeAddress& dst);

    // Setters
    void setType(PacketType type) { header_.type = type; }
    void setSource(const NodeAddress& addr) { header_.source = addr; }
    void setDest(const NodeAddress& addr) { header_.dest = addr; }
    void setSequence(uint32_t seq) { header_.sequence = seq; }

    // Set payload from raw bytes
    bool setPayload(const uint8_t* data, size_t len);
    bool setPayload(const ByteVector& data);

    // Getters
    PacketType type() const { return header_.type; }
    const NodeAddress& source() const { return header_.source; }
    const NodeAddress& dest() const { return header_.dest; }
    uint32_t sequence() const { return header_.sequence; }
    const PacketHeader& header() const { return header_; }
    const uint8_t* payload() const { return payload_.data(); }
    size_t payloadSize() const { return payload_.size(); }
    const ByteVector& payloadVector() const { return payload_; }

    // Serialize to wire format (ready to send over UDP)
    ByteVector serialize() const;

    // Deserialize from wire format (received from UDP)
    static std::optional<Packet> deserialize(const uint8_t* data, size_t len);

    // Validate packet integrity
    bool isValid() const;

    // Human-readable description
    std::string toString() const;

private:
    PacketHeader header_;
    ByteVector   payload_;

    // Helpers for byte-order conversion
    static void writeU32(uint8_t* dst, uint32_t val);
    static void writeU16(uint8_t* dst, uint16_t val);
    static uint32_t readU32(const uint8_t* src);
    static uint16_t readU16(const uint8_t* src);
};

} // namespace yanet
