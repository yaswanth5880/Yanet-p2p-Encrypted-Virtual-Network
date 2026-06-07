/**
 * YaNet — packet.cpp
 * Wire protocol packet serialization/deserialization
 */

#include "yanet/packet.h"
#include <iostream>
#include <sstream>
#include <cstring>

namespace yanet {

Packet::Packet() = default;

Packet::Packet(PacketType type) {
    header_.type = type;
}

Packet::Packet(PacketType type, const NodeAddress& src, const NodeAddress& dst) {
    header_.type = type;
    header_.source = src;
    header_.dest = dst;
}

bool Packet::setPayload(const uint8_t* data, size_t len) {
    if (len > PACKET_MAX_PAYLOAD) {
        std::cerr << "[YaNet] Payload too large: " << len
                  << " > " << PACKET_MAX_PAYLOAD << std::endl;
        return false;
    }
    payload_.assign(data, data + len);
    header_.payloadLength = static_cast<uint16_t>(len);
    return true;
}

bool Packet::setPayload(const ByteVector& data) {
    return setPayload(data.data(), data.size());
}

ByteVector Packet::serialize() const {
    ByteVector wire(PACKET_HEADER_SIZE + payload_.size());
    uint8_t* p = wire.data();

    // Magic (4 bytes, big-endian)
    writeU32(p, header_.magic);
    p += 4;

    // Version (1 byte)
    *p++ = header_.version;

    // Type (1 byte)
    *p++ = static_cast<uint8_t>(header_.type);

    // Source address (5 bytes)
    std::memcpy(p, header_.source.bytes.data(), ADDRESS_HASH_SIZE);
    p += ADDRESS_HASH_SIZE;

    // Destination address (5 bytes)
    std::memcpy(p, header_.dest.bytes.data(), ADDRESS_HASH_SIZE);
    p += ADDRESS_HASH_SIZE;

    // Sequence number (4 bytes, big-endian)
    writeU32(p, header_.sequence);
    p += 4;

    // Payload length (2 bytes, big-endian)
    writeU16(p, header_.payloadLength);
    p += 2;

    // Payload
    if (!payload_.empty()) {
        std::memcpy(p, payload_.data(), payload_.size());
    }

    return wire;
}

std::optional<Packet> Packet::deserialize(const uint8_t* data, size_t len) {
    if (len < PACKET_HEADER_SIZE) {
        return std::nullopt;
    }

    const uint8_t* p = data;

    Packet pkt;

    // Magic
    pkt.header_.magic = readU32(p);
    p += 4;
    if (pkt.header_.magic != YANET_PACKET_MAGIC) {
        return std::nullopt;  // Not a YaNet packet
    }

    // Version
    pkt.header_.version = *p++;
    if (pkt.header_.version != YANET_PROTOCOL_VERSION) {
        std::cerr << "[YaNet] Unknown protocol version: "
                  << static_cast<int>(pkt.header_.version) << std::endl;
        return std::nullopt;
    }

    // Type
    pkt.header_.type = static_cast<PacketType>(*p++);

    // Source address
    std::memcpy(pkt.header_.source.bytes.data(), p, ADDRESS_HASH_SIZE);
    p += ADDRESS_HASH_SIZE;

    // Destination address
    std::memcpy(pkt.header_.dest.bytes.data(), p, ADDRESS_HASH_SIZE);
    p += ADDRESS_HASH_SIZE;

    // Sequence
    pkt.header_.sequence = readU32(p);
    p += 4;

    // Payload length
    pkt.header_.payloadLength = readU16(p);
    p += 2;

    // Validate payload length
    size_t remainingBytes = len - PACKET_HEADER_SIZE;
    if (pkt.header_.payloadLength > remainingBytes) {
        std::cerr << "[YaNet] Packet truncated: payload claims "
                  << pkt.header_.payloadLength << " but only "
                  << remainingBytes << " bytes remain" << std::endl;
        return std::nullopt;
    }

    // Payload
    if (pkt.header_.payloadLength > 0) {
        pkt.payload_.assign(p, p + pkt.header_.payloadLength);
    }

    return pkt;
}

bool Packet::isValid() const {
    return header_.magic == YANET_PACKET_MAGIC
        && header_.version == YANET_PROTOCOL_VERSION
        && header_.payloadLength == payload_.size();
}

std::string Packet::toString() const {
    std::ostringstream oss;
    oss << "Packet[type=";
    switch (header_.type) {
        case PacketType::HELLO:       oss << "HELLO"; break;
        case PacketType::HELLO_ACK:   oss << "HELLO_ACK"; break;
        case PacketType::DATA:        oss << "DATA"; break;
        case PacketType::KEEPALIVE:   oss << "KEEPALIVE"; break;
        case PacketType::PEER_INFO:   oss << "PEER_INFO"; break;
        case PacketType::REGISTER:    oss << "REGISTER"; break;
        case PacketType::LOOKUP:      oss << "LOOKUP"; break;
        case PacketType::LOOKUP_RESP: oss << "LOOKUP_RESP"; break;
        case PacketType::PUNCH:         oss << "PUNCH"; break;
        case PacketType::NETWORK_JOIN:  oss << "NETWORK_JOIN"; break;
        case PacketType::NETWORK_LEAVE: oss << "NETWORK_LEAVE"; break;
        case PacketType::NETWORK_CONFIG:oss << "NETWORK_CONFIG"; break;
        default: oss << "UNKNOWN(0x" << std::hex << static_cast<int>(header_.type) << ")";
    }
    oss << " src=" << header_.source.toString()
        << " dst=" << header_.dest.toString()
        << " seq=" << header_.sequence
        << " payload=" << payload_.size() << "B]";
    return oss.str();
}

// ============================================================================
// Byte order helpers (big-endian / network byte order)
// ============================================================================

void Packet::writeU32(uint8_t* dst, uint32_t val) {
    dst[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >>  8) & 0xFF);
    dst[3] = static_cast<uint8_t>((val      ) & 0xFF);
}

void Packet::writeU16(uint8_t* dst, uint16_t val) {
    dst[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[1] = static_cast<uint8_t>((val     ) & 0xFF);
}

uint32_t Packet::readU32(const uint8_t* src) {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) <<  8) |
           (static_cast<uint32_t>(src[3]));
}

uint16_t Packet::readU16(const uint8_t* src) {
    return (static_cast<uint16_t>(src[0]) << 8) |
           (static_cast<uint16_t>(src[1]));
}

} // namespace yanet
