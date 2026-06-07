/**
 * YaNet — A Peer-to-Peer Virtual Network
 * peer.h — Peer management
 */

#pragma once

#include "types.h"
#include "crypto.h"
#include <mutex>
#include <map>
#include <vector>

namespace yanet {

class Peer {
public:
    Peer();
    explicit Peer(const NodeAddress& addr);
    Peer(const NodeAddress& addr, const PublicKey& pubKey);

    // Identity
    const NodeAddress& address() const { return address_; }
    const PublicKey& publicKey() const { return publicKey_; }
    void setPublicKey(const PublicKey& key) { publicKey_ = key; }

    // Connection state
    PeerState state() const { return state_; }
    void setState(PeerState s) { state_ = s; }

    // Endpoint management
    const Endpoint& endpoint() const { return endpoint_; }
    void setEndpoint(const Endpoint& ep) { endpoint_ = ep; }

    // Session key (set after handshake)
    const SharedKey& sessionKey() const { return sessionKey_; }
    void setSessionKey(const SharedKey& key) { sessionKey_ = key; hasSessionKey_ = true; }
    bool hasSessionKey() const { return hasSessionKey_; }

    // Timing
    void markSeen() { lastSeen_ = std::chrono::steady_clock::now(); }
    Timestamp lastSeen() const { return lastSeen_; }
    bool isExpired(int timeoutMs) const;

    // Sequence tracking
    uint32_t nextSequence() { return sequenceOut_++; }
    uint32_t lastReceivedSequence() const { return sequenceIn_; }
    void setLastReceivedSequence(uint32_t seq) { sequenceIn_ = seq; }

    // Latency tracking
    void setLatency(double ms) { latencyMs_ = ms; }
    double latency() const { return latencyMs_; }

    // Virtual IP for this peer in a given network
    uint32_t virtualIp() const { return virtualIp_; }
    void setVirtualIp(uint32_t ip) { virtualIp_ = ip; }

    std::string toString() const;

private:
    NodeAddress address_;
    PublicKey   publicKey_ = {};
    PeerState   state_ = PeerState::UNKNOWN;
    Endpoint    endpoint_;
    SharedKey   sessionKey_ = {};
    bool        hasSessionKey_ = false;
    Timestamp   lastSeen_;
    uint32_t    sequenceOut_ = 0;
    uint32_t    sequenceIn_ = 0;
    double      latencyMs_ = 0.0;
    uint32_t    virtualIp_ = 0;
};

class PeerTable {
public:
    PeerTable() = default;

    // Add or update a peer
    Peer& addPeer(const NodeAddress& addr);
    Peer& addPeer(const NodeAddress& addr, const PublicKey& pubKey);

    // Lookup
    Peer* findByAddress(const NodeAddress& addr);
    Peer* findByEndpoint(const Endpoint& ep);
    Peer* findByVirtualIp(uint32_t vip);

    // Remove
    void removePeer(const NodeAddress& addr);

    // Get all peers
    std::vector<Peer*> allPeers();

    // Cleanup expired peers
    int cleanupExpired(int timeoutMs);

    size_t size() const;

private:
    std::map<NodeAddress, Peer> peers_;
    mutable std::mutex mutex_;
};

} // namespace yanet
