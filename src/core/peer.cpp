/**
 * YaNet — peer.cpp
 * Peer management implementation
 */

#include "yanet/peer.h"
#include <sstream>
#include <algorithm>

namespace yanet {

// ============================================================================
// Peer
// ============================================================================

Peer::Peer() : lastSeen_(std::chrono::steady_clock::now()) {}

Peer::Peer(const NodeAddress& addr)
    : address_(addr), lastSeen_(std::chrono::steady_clock::now()) {}

Peer::Peer(const NodeAddress& addr, const PublicKey& pubKey)
    : address_(addr), publicKey_(pubKey),
      lastSeen_(std::chrono::steady_clock::now()) {}

bool Peer::isExpired(int timeoutMs) const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastSeen_
    ).count();
    return elapsed > timeoutMs;
}

std::string Peer::toString() const {
    std::ostringstream oss;
    oss << "Peer[" << address_.toString();

    switch (state_) {
        case PeerState::UNKNOWN:     oss << " UNKNOWN"; break;
        case PeerState::HANDSHAKING: oss << " HANDSHAKING"; break;
        case PeerState::ESTABLISHED: oss << " ESTABLISHED"; break;
        case PeerState::STALE:       oss << " STALE"; break;
        case PeerState::DEAD:        oss << " DEAD"; break;
    }

    if (endpoint_.isValid()) {
        oss << " ep=" << endpoint_.toString();
    }

    if (latencyMs_ > 0) {
        oss << " lat=" << latencyMs_ << "ms";
    }

    oss << "]";
    return oss.str();
}

// ============================================================================
// PeerTable
// ============================================================================

Peer& PeerTable::addPeer(const NodeAddress& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(addr);
    if (it != peers_.end()) {
        return it->second;
    }
    auto result = peers_.emplace(addr, Peer(addr));
    return result.first->second;
}

Peer& PeerTable::addPeer(const NodeAddress& addr, const PublicKey& pubKey) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(addr);
    if (it != peers_.end()) {
        it->second.setPublicKey(pubKey);
        return it->second;
    }
    auto result = peers_.emplace(addr, Peer(addr, pubKey));
    return result.first->second;
}

Peer* PeerTable::findByAddress(const NodeAddress& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(addr);
    return (it != peers_.end()) ? &it->second : nullptr;
}

Peer* PeerTable::findByEndpoint(const Endpoint& ep) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [addr, peer] : peers_) {
        if (peer.endpoint() == ep) return &peer;
    }
    return nullptr;
}

Peer* PeerTable::findByVirtualIp(uint32_t vip) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [addr, peer] : peers_) {
        if (peer.virtualIp() == vip) return &peer;
    }
    return nullptr;
}

void PeerTable::removePeer(const NodeAddress& addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    peers_.erase(addr);
}

std::vector<Peer*> PeerTable::allPeers() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Peer*> result;
    result.reserve(peers_.size());
    for (auto& [addr, peer] : peers_) {
        result.push_back(&peer);
    }
    return result;
}

int PeerTable::cleanupExpired(int timeoutMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    int removed = 0;
    for (auto it = peers_.begin(); it != peers_.end();) {
        if (it->second.isExpired(timeoutMs)) {
            it = peers_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

size_t PeerTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return peers_.size();
}

} // namespace yanet
