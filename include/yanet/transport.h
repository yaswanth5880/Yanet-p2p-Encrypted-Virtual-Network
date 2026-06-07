/**
 * YaNet — A Peer-to-Peer Virtual Network
 * transport.h — UDP socket transport layer
 *
 * Provides non-blocking UDP send/receive with endpoint tracking.
 * Uses Winsock2 on Windows.
 */

#pragma once

#include "types.h"
#include "packet.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
using SOCKET = int;
constexpr int INVALID_SOCKET = -1;
constexpr int SOCKET_ERROR = -1;
#endif

#include <functional>
#include <optional>
#include <string>

namespace yanet {

// Callback for received packets
using PacketCallback = std::function<void(const Packet& pkt, const Endpoint& from)>;

class UDPTransport {
public:
    UDPTransport();
    ~UDPTransport();

    // Initialize Winsock (call once at startup)
    static bool initializeWinsock();
    static void cleanupWinsock();

    // Bind to a local port
    bool bind(uint16_t port);

    // Send raw bytes to an endpoint
    bool sendTo(const uint8_t* data, size_t len, const Endpoint& dest);

    // Send a serialized packet to an endpoint
    bool sendPacket(const Packet& pkt, const Endpoint& dest);

    // Receive (non-blocking, returns immediately if nothing available)
    // Returns true if a packet was received
    bool receive(ByteVector& outData, Endpoint& outFrom, int timeoutMs = 0);

    // Poll for incoming packets with timeout, call callback for each
    int poll(PacketCallback callback, int timeoutMs = 100);

    // Close the socket
    void close();

    // Getters
    uint16_t localPort() const { return localPort_; }
    bool isOpen() const { return socket_ != INVALID_SOCKET; }

    // Utility: parse "ip:port" string to Endpoint
    static Endpoint parseEndpoint(const std::string& str);

    // Utility: create Endpoint from IPv4 string and port
    static Endpoint makeEndpoint(const std::string& ip, uint16_t port);

private:
    SOCKET   socket_ = INVALID_SOCKET;
    uint16_t localPort_ = 0;
};

} // namespace yanet
