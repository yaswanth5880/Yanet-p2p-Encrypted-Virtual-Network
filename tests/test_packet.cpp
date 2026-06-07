/**
 * YaNet — test_packet.cpp
 * Unit tests for packet serialization
 */

#include "yanet/packet.h"
#include "yanet/crypto.h"
#include <iostream>
#include <cassert>
#include <cstring>

int main() {
    std::cout << "=== YaNet Packet Tests ===" << std::endl;

    assert(yanet::CryptoEngine::initialize());

    // Test 1: Serialize and deserialize empty packet
    {
        std::cout << "Test 1: Empty packet roundtrip... ";
        yanet::NodeAddress src = yanet::NodeAddress::fromString("a1b2c3d4e5");
        yanet::NodeAddress dst = yanet::NodeAddress::fromString("f6e7d8c9b0");

        yanet::Packet pkt(yanet::PacketType::KEEPALIVE, src, dst);
        pkt.setSequence(42);

        auto wire = pkt.serialize();
        assert(wire.size() == yanet::PACKET_HEADER_SIZE);

        auto parsed = yanet::Packet::deserialize(wire.data(), wire.size());
        assert(parsed.has_value());
        assert(parsed->type() == yanet::PacketType::KEEPALIVE);
        assert(parsed->source() == src);
        assert(parsed->dest() == dst);
        assert(parsed->sequence() == 42);
        assert(parsed->payloadSize() == 0);

        std::cout << "PASS" << std::endl;
    }

    // Test 2: Packet with payload
    {
        std::cout << "Test 2: Packet with payload... ";
        yanet::Packet pkt(yanet::PacketType::DATA);
        std::string msg = "Hello World!";
        yanet::ByteVector payload(msg.begin(), msg.end());
        assert(pkt.setPayload(payload));

        auto wire = pkt.serialize();
        auto parsed = yanet::Packet::deserialize(wire.data(), wire.size());
        assert(parsed.has_value());
        assert(parsed->payloadSize() == msg.size());
        assert(std::memcmp(parsed->payload(), msg.c_str(), msg.size()) == 0);

        std::cout << "PASS" << std::endl;
    }

    // Test 3: Invalid magic rejected
    {
        std::cout << "Test 3: Invalid magic rejected... ";
        yanet::Packet pkt(yanet::PacketType::HELLO);
        auto wire = pkt.serialize();
        wire[0] = 0xFF;  // Corrupt magic

        auto parsed = yanet::Packet::deserialize(wire.data(), wire.size());
        assert(!parsed.has_value());

        std::cout << "PASS" << std::endl;
    }

    // Test 4: Truncated packet rejected
    {
        std::cout << "Test 4: Truncated packet rejected... ";
        yanet::Packet pkt(yanet::PacketType::DATA);
        std::string msg = "Test data";
        pkt.setPayload(reinterpret_cast<const uint8_t*>(msg.c_str()), msg.size());

        auto wire = pkt.serialize();
        // Truncate (remove last 5 bytes)
        wire.resize(wire.size() - 5);

        auto parsed = yanet::Packet::deserialize(wire.data(), wire.size());
        assert(!parsed.has_value());

        std::cout << "PASS" << std::endl;
    }

    // Test 5: Too short data rejected
    {
        std::cout << "Test 5: Too short data rejected... ";
        uint8_t tiny[] = {0x59, 0x4E, 0x45, 0x54};  // Just magic, too short
        auto parsed = yanet::Packet::deserialize(tiny, sizeof(tiny));
        assert(!parsed.has_value());

        std::cout << "PASS" << std::endl;
    }

    // Test 6: Large payload
    {
        std::cout << "Test 6: Large payload... ";
        yanet::Packet pkt(yanet::PacketType::DATA);
        yanet::ByteVector bigPayload(2000, 0xAB);
        assert(pkt.setPayload(bigPayload));

        auto wire = pkt.serialize();
        auto parsed = yanet::Packet::deserialize(wire.data(), wire.size());
        assert(parsed.has_value());
        assert(parsed->payloadSize() == 2000);

        std::cout << "PASS" << std::endl;
    }

    // Test 7: Packet toString
    {
        std::cout << "Test 7: Packet toString... ";
        yanet::Packet pkt(yanet::PacketType::HELLO,
                          yanet::NodeAddress::fromString("a1b2c3d4e5"),
                          yanet::NodeAddress::fromString("f6e7d8c9b0"));
        std::string str = pkt.toString();
        assert(str.find("HELLO") != std::string::npos);
        assert(str.find("a1b2c3d4e5") != std::string::npos);
        std::cout << "PASS (" << str << ")" << std::endl;
    }

    std::cout << "\n=== All packet tests PASSED ===" << std::endl;
    return 0;
}
