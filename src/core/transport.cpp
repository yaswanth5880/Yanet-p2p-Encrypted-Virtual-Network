/**
 * YaNet — transport.cpp
 * UDP socket transport layer using Winsock2
 */

#include "yanet/transport.h"
#include <iostream>
#include <sstream>
#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#endif

namespace yanet {

// ============================================================================
// Endpoint helper
// ============================================================================

std::string Endpoint::toString() const {
    struct in_addr addr;
    addr.s_addr = ip;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf) + ":" + std::to_string(port);
}

// ============================================================================
// UDPTransport
// ============================================================================

UDPTransport::UDPTransport() = default;

UDPTransport::~UDPTransport() {
    close();
}

bool UDPTransport::initializeWinsock() {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "[YaNet] WSAStartup failed: " << result << std::endl;
        return false;
    }
    std::cout << "[YaNet] Winsock initialized" << std::endl;
#endif
    return true;
}

void UDPTransport::cleanupWinsock() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool UDPTransport::bind(uint16_t port) {
    socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == INVALID_SOCKET) {
        std::cerr << "[YaNet] Failed to create UDP socket" << std::endl;
        return false;
    }

    // Enable address reuse
    int optval = 1;
    setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&optval), sizeof(optval));

    // Set non-blocking mode
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(socket_, FIONBIO, &mode);
#else
    int flags = fcntl(socket_, F_GETFL, 0);
    fcntl(socket_, F_SETFL, flags | O_NONBLOCK);
#endif

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (::bind(socket_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[YaNet] Failed to bind UDP socket to port " << port << std::endl;
        close();
        return false;
    }

    // Get the actual port (useful if port was 0)
    struct sockaddr_in boundAddr = {};
#ifdef _WIN32
    int addrLen = sizeof(boundAddr);
#else
    socklen_t addrLen = sizeof(boundAddr);
#endif
    getsockname(socket_, reinterpret_cast<struct sockaddr*>(&boundAddr), &addrLen);
    localPort_ = ntohs(boundAddr.sin_port);

    std::cout << "[YaNet] UDP transport bound to port " << localPort_ << std::endl;
    return true;
}

bool UDPTransport::sendTo(const uint8_t* data, size_t len, const Endpoint& dest) {
    if (socket_ == INVALID_SOCKET) return false;

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dest.ip;
    addr.sin_port = htons(dest.port);

    int sent = sendto(socket_, reinterpret_cast<const char*>(data),
                      static_cast<int>(len), 0,
                      reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if (sent == SOCKET_ERROR) {
        // Don't log WOULDBLOCK errors
#ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            std::cerr << "[YaNet] UDP send failed: " << WSAGetLastError() << std::endl;
        }
#endif
        return false;
    }

    return sent == static_cast<int>(len);
}

bool UDPTransport::sendPacket(const Packet& pkt, const Endpoint& dest) {
    ByteVector wire = pkt.serialize();
    return sendTo(wire.data(), wire.size(), dest);
}

bool UDPTransport::receive(ByteVector& outData, Endpoint& outFrom, int timeoutMs) {
    if (socket_ == INVALID_SOCKET) return false;

    // Use select() for timeout
    if (timeoutMs > 0) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(socket_, &readSet);

        struct timeval tv;
        tv.tv_sec = timeoutMs / 1000;
        tv.tv_usec = (timeoutMs % 1000) * 1000;

        int ready = select(0, &readSet, nullptr, nullptr, &tv);
        if (ready <= 0) return false;
    }

    uint8_t buffer[YANET_MAX_PACKET_SIZE];
    struct sockaddr_in fromAddr = {};
#ifdef _WIN32
    int fromLen = sizeof(fromAddr);
#else
    socklen_t fromLen = sizeof(fromAddr);
#endif

    int received = recvfrom(socket_, reinterpret_cast<char*>(buffer),
                            sizeof(buffer), 0,
                            reinterpret_cast<struct sockaddr*>(&fromAddr), &fromLen);

    if (received <= 0) return false;

    outData.assign(buffer, buffer + received);
    outFrom.ip = fromAddr.sin_addr.s_addr;
    outFrom.port = ntohs(fromAddr.sin_port);

    return true;
}

int UDPTransport::poll(PacketCallback callback, int timeoutMs) {
    int count = 0;
    ByteVector data;
    Endpoint from;

    // Try to receive as many packets as possible within timeout
    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        int remainingMs = timeoutMs;
        if (timeoutMs > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime
            ).count();
            remainingMs = timeoutMs - static_cast<int>(elapsed);
            if (remainingMs <= 0) break;
        }

        if (!receive(data, from, count == 0 ? remainingMs : 0)) {
            break;
        }

        auto pkt = Packet::deserialize(data.data(), data.size());
        if (pkt.has_value()) {
            callback(pkt.value(), from);
            ++count;
        }
    }

    return count;
}

void UDPTransport::close() {
    if (socket_ != INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(socket_);
#else
        ::close(socket_);
#endif
        socket_ = INVALID_SOCKET;
        localPort_ = 0;
    }
}

Endpoint UDPTransport::parseEndpoint(const std::string& str) {
    auto colonPos = str.rfind(':');
    if (colonPos == std::string::npos) return {};

    std::string ipStr = str.substr(0, colonPos);
    uint16_t port = static_cast<uint16_t>(std::stoi(str.substr(colonPos + 1)));

    return makeEndpoint(ipStr, port);
}

Endpoint UDPTransport::makeEndpoint(const std::string& ip, uint16_t port) {
    Endpoint ep;
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        ep.ip = addr.s_addr;
        ep.port = port;
    }
    return ep;
}

} // namespace yanet
