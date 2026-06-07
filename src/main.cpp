/**
 * YaNet — A Peer-to-Peer Virtual Network
 * main.cpp — Entry point
 *
 * Phase 1: Identity generation
 * Phase 2: Encrypted P2P messaging
 *
 * Usage:
 *   yanet.exe                         — Generate identity and start listening
 *   yanet.exe --generate              — Generate a new identity
 *   yanet.exe --connect <ip:port>     — Connect to a peer
 *   yanet.exe --port <port>           — Listen on a specific port
 *   yanet.exe --send <ip:port> <msg>  — Send an encrypted message to a peer
 */

#include "yanet/version.h"
#include "yanet/types.h"
#include "yanet/identity.h"
#include "yanet/crypto.h"
#include "yanet/transport.h"
#include "yanet/packet.h"
#include "yanet/peer.h"

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

// ============================================================================
// Global state
// ============================================================================

static std::atomic<bool> g_running{true};
static yanet::Identity g_identity;
static yanet::UDPTransport g_transport;
static yanet::PeerTable g_peers;

// ============================================================================
// Signal handler for graceful shutdown
// ============================================================================

void signalHandler(int sig) {
    std::cout << "\n[YaNet] Shutting down..." << std::endl;
    g_running = false;
}

// ============================================================================
// Print banner
// ============================================================================

void printBanner() {
    std::cout << R"(
  ╦ ╦┌─┐╔╗╔┌─┐┌┬┐
  ╚╦╝├─┤║║║├┤  │
   ╩ ┴ ┴╝╚╝└─┘ ┴
)" << std::endl;
    std::cout << "  YaNet v" << YANET_VERSION_STRING
              << " — Peer-to-Peer Virtual Network" << std::endl;
    std::cout << "  ─────────────────────────────────────" << std::endl;
    std::cout << std::endl;
}

// ============================================================================
// Print usage
// ============================================================================

void printUsage(const char* argv0) {
    std::cout << "Usage: " << argv0 << " [options]\n\n"
              << "Options:\n"
              << "  --generate           Generate a new identity\n"
              << "  --port <port>        Listen on specified port (default: " << YANET_DEFAULT_PORT << ")\n"
              << "  --connect <ip:port>  Connect to a remote peer\n"
              << "  --send <ip:port> <msg>  Send a message to a peer\n"
              << "  --identity <file>    Path to identity file (default: identity.secret)\n"
              << "  --help               Show this help\n"
              << std::endl;
}

// ============================================================================
// Ensure data directory exists
// ============================================================================

std::string getDataDir() {
    std::string dir = "yanet_data";
    fs::create_directories(dir);
    return dir;
}

// ============================================================================
// Handle incoming HELLO packet (handshake initiation)
// ============================================================================

void handleHello(const yanet::Packet& pkt, const yanet::Endpoint& from) {
    std::cout << "[YaNet] <── HELLO from " << pkt.source().toString()
              << " via " << from.toString() << std::endl;

    // Extract their public key from payload
    if (pkt.payloadSize() < yanet::PUBLIC_KEY_SIZE) {
        std::cerr << "[YaNet] HELLO packet too short" << std::endl;
        return;
    }

    yanet::PublicKey theirPubKey;
    std::memcpy(theirPubKey.data(), pkt.payload(), yanet::PUBLIC_KEY_SIZE);

    // Register peer
    auto& peer = g_peers.addPeer(pkt.source(), theirPubKey);
    peer.setEndpoint(from);
    peer.markSeen();

    // Compute session key
    auto sharedSecret = yanet::CryptoEngine::computeSharedSecret(
        g_identity.secretKey(), theirPubKey
    );
    auto sessionKey = yanet::CryptoEngine::deriveSessionKey(
        sharedSecret, pkt.source(), g_identity.address()
    );
    peer.setSessionKey(sessionKey);
    peer.setState(yanet::PeerState::ESTABLISHED);

    // Send HELLO_ACK with our public key
    yanet::Packet ack(yanet::PacketType::HELLO_ACK,
                      g_identity.address(), pkt.source());
    ack.setPayload(g_identity.publicKey().data(), yanet::PUBLIC_KEY_SIZE);
    ack.setSequence(peer.nextSequence());
    g_transport.sendPacket(ack, from);

    std::cout << "[YaNet] ──> HELLO_ACK sent to " << pkt.source().toString()
              << " | Session ESTABLISHED" << std::endl;
}

// ============================================================================
// Handle incoming HELLO_ACK packet (handshake completion)
// ============================================================================

void handleHelloAck(const yanet::Packet& pkt, const yanet::Endpoint& from) {
    std::cout << "[YaNet] <── HELLO_ACK from " << pkt.source().toString() << std::endl;

    if (pkt.payloadSize() < yanet::PUBLIC_KEY_SIZE) return;

    yanet::PublicKey theirPubKey;
    std::memcpy(theirPubKey.data(), pkt.payload(), yanet::PUBLIC_KEY_SIZE);

    auto* peer = g_peers.findByAddress(pkt.source());
    if (!peer) {
        peer = &g_peers.addPeer(pkt.source(), theirPubKey);
    }
    peer->setPublicKey(theirPubKey);
    peer->setEndpoint(from);
    peer->markSeen();

    // Compute session key (same as peer, using our initiator role)
    auto sharedSecret = yanet::CryptoEngine::computeSharedSecret(
        g_identity.secretKey(), theirPubKey
    );
    auto sessionKey = yanet::CryptoEngine::deriveSessionKey(
        sharedSecret, g_identity.address(), pkt.source()
    );
    peer->setSessionKey(sessionKey);
    peer->setState(yanet::PeerState::ESTABLISHED);

    std::cout << "[YaNet] Session ESTABLISHED with " << pkt.source().toString() << std::endl;
}

// ============================================================================
// Handle incoming DATA packet (encrypted message)
// ============================================================================

void handleData(const yanet::Packet& pkt, const yanet::Endpoint& from) {
    auto* peer = g_peers.findByAddress(pkt.source());
    if (!peer || !peer->hasSessionKey()) {
        std::cerr << "[YaNet] DATA from unknown/unauthed peer "
                  << pkt.source().toString() << std::endl;
        return;
    }

    peer->markSeen();

    // Decrypt payload
    auto plaintext = yanet::CryptoEngine::decrypt(
        peer->sessionKey(), pkt.payload(), pkt.payloadSize()
    );

    if (!plaintext.has_value()) {
        std::cerr << "[YaNet] Decryption failed from " << pkt.source().toString() << std::endl;
        return;
    }

    std::string message(plaintext->begin(), plaintext->end());
    std::cout << "[YaNet] <── MESSAGE from " << pkt.source().toString()
              << ": " << message << std::endl;
}

// ============================================================================
// Handle incoming KEEPALIVE
// ============================================================================

void handleKeepalive(const yanet::Packet& pkt, const yanet::Endpoint& from) {
    auto* peer = g_peers.findByAddress(pkt.source());
    if (peer) {
        peer->markSeen();
    }
}

// ============================================================================
// Main packet dispatch
// ============================================================================

void onPacketReceived(const yanet::Packet& pkt, const yanet::Endpoint& from) {
    switch (pkt.type()) {
        case yanet::PacketType::HELLO:     handleHello(pkt, from); break;
        case yanet::PacketType::HELLO_ACK: handleHelloAck(pkt, from); break;
        case yanet::PacketType::DATA:      handleData(pkt, from); break;
        case yanet::PacketType::KEEPALIVE: handleKeepalive(pkt, from); break;
        default:
            std::cout << "[YaNet] Unhandled packet: " << pkt.toString() << std::endl;
    }
}

// ============================================================================
// Send HELLO to initiate handshake with a peer
// ============================================================================

void initiateHandshake(const yanet::Endpoint& target) {
    std::cout << "[YaNet] ──> Sending HELLO to " << target.toString() << std::endl;

    yanet::Packet hello(yanet::PacketType::HELLO, g_identity.address(), yanet::NodeAddress());
    hello.setPayload(g_identity.publicKey().data(), yanet::PUBLIC_KEY_SIZE);
    g_transport.sendPacket(hello, target);
}

// ============================================================================
// Send an encrypted message to a peer
// ============================================================================

bool sendMessage(const yanet::NodeAddress& peerAddr, const std::string& message) {
    auto* peer = g_peers.findByAddress(peerAddr);
    if (!peer || !peer->hasSessionKey()) {
        std::cerr << "[YaNet] No established session with " << peerAddr.toString() << std::endl;
        return false;
    }

    // Encrypt message
    yanet::ByteVector plaintext(message.begin(), message.end());
    auto ciphertext = yanet::CryptoEngine::encrypt(peer->sessionKey(), plaintext);

    // Build and send DATA packet
    yanet::Packet dataPkt(yanet::PacketType::DATA, g_identity.address(), peerAddr);
    dataPkt.setPayload(ciphertext);
    dataPkt.setSequence(peer->nextSequence());

    if (g_transport.sendPacket(dataPkt, peer->endpoint())) {
        std::cout << "[YaNet] ──> Encrypted message sent to " << peerAddr.toString()
                  << " (" << ciphertext.size() << " bytes)" << std::endl;
        return true;
    }

    return false;
}

// ============================================================================
// Interactive command loop
// ============================================================================

void commandLoop() {
    std::cout << "\n[YaNet] Interactive mode. Commands:\n"
              << "  connect <ip:port>   — Start handshake with peer\n"
              << "  msg <message>       — Send message to last connected peer\n"
              << "  peers               — List connected peers\n"
              << "  info                — Show node info\n"
              << "  quit                — Exit\n\n";

    yanet::NodeAddress lastPeer;

    while (g_running) {
        std::cout << "yanet> ";
        std::string line;
        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        // Parse command
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            g_running = false;
            break;
        }
        else if (cmd == "connect") {
            std::string epStr;
            iss >> epStr;
            if (epStr.empty()) {
                std::cout << "Usage: connect <ip:port>" << std::endl;
                continue;
            }
            auto ep = yanet::UDPTransport::parseEndpoint(epStr);
            if (!ep.isValid()) {
                std::cout << "Invalid endpoint: " << epStr << std::endl;
                continue;
            }
            initiateHandshake(ep);
        }
        else if (cmd == "msg" || cmd == "send") {
            std::string rest;
            std::getline(iss >> std::ws, rest);
            if (rest.empty()) {
                std::cout << "Usage: msg <message>" << std::endl;
                continue;
            }
            // Find first established peer
            auto peers = g_peers.allPeers();
            bool sent = false;
            for (auto* peer : peers) {
                if (peer->state() == yanet::PeerState::ESTABLISHED) {
                    sendMessage(peer->address(), rest);
                    sent = true;
                    break;
                }
            }
            if (!sent) {
                std::cout << "No established peer connections." << std::endl;
            }
        }
        else if (cmd == "peers") {
            auto peers = g_peers.allPeers();
            if (peers.empty()) {
                std::cout << "No peers connected." << std::endl;
            } else {
                std::cout << "Connected peers (" << peers.size() << "):" << std::endl;
                for (auto* peer : peers) {
                    std::cout << "  " << peer->toString() << std::endl;
                }
            }
        }
        else if (cmd == "info") {
            std::cout << "Node Address : " << g_identity.address().toString() << std::endl;
            std::cout << "Listening    : port " << g_transport.localPort() << std::endl;
            std::cout << "Peers        : " << g_peers.size() << std::endl;
            std::cout << "Protocol     : v" << YANET_PROTOCOL_VERSION << std::endl;
        }
        else {
            std::cout << "Unknown command: " << cmd << std::endl;
        }
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    printBanner();

    // ── Parse arguments ─────────────────────────────────────────────────
    uint16_t port = YANET_DEFAULT_PORT;
    std::string identityFile = "";
    std::string connectTo = "";
    std::string sendTarget = "";
    std::string sendMessage = "";
    bool generateOnly = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "--generate" || arg == "-g") {
            generateOnly = true;
        }
        else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        }
        else if ((arg == "--connect" || arg == "-c") && i + 1 < argc) {
            connectTo = argv[++i];
        }
        else if ((arg == "--identity" || arg == "-i") && i + 1 < argc) {
            identityFile = argv[++i];
        }
        else if (arg == "--send" && i + 2 < argc) {
            sendTarget = argv[++i];
            sendMessage = argv[++i];
        }
    }

    // ── Initialize crypto ───────────────────────────────────────────────
    if (!yanet::CryptoEngine::initialize()) {
        std::cerr << "[YaNet] FATAL: Cannot initialize cryptography" << std::endl;
        return 1;
    }

    // ── Set up data directory ───────────────────────────────────────────
    std::string dataDir = getDataDir();
    if (identityFile.empty()) {
        identityFile = dataDir + "/identity.secret";
    }

    // ── Load or generate identity ───────────────────────────────────────
    if (fs::exists(identityFile)) {
        if (!g_identity.loadFromFile(identityFile)) {
            std::cerr << "[YaNet] Failed to load identity from " << identityFile << std::endl;
            return 1;
        }
    } else {
        std::cout << "[YaNet] No identity found, generating new one..." << std::endl;
        if (!g_identity.generate()) {
            std::cerr << "[YaNet] Failed to generate identity" << std::endl;
            return 1;
        }
        g_identity.saveToFile(identityFile);
    }

    std::cout << "[YaNet] Node address: " << g_identity.address().toString() << std::endl;
    std::cout << std::endl;

    if (generateOnly) {
        std::cout << "[YaNet] Identity generated. Exiting." << std::endl;
        return 0;
    }

    // ── Initialize transport ────────────────────────────────────────────
    if (!yanet::UDPTransport::initializeWinsock()) {
        return 1;
    }

    if (!g_transport.bind(port)) {
        std::cerr << "[YaNet] Failed to bind to port " << port << std::endl;
        yanet::UDPTransport::cleanupWinsock();
        return 1;
    }

    // ── Set up signal handler ───────────────────────────────────────────
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // ── Connect to peer if specified ────────────────────────────────────
    if (!connectTo.empty()) {
        auto ep = yanet::UDPTransport::parseEndpoint(connectTo);
        if (ep.isValid()) {
            initiateHandshake(ep);
        } else {
            std::cerr << "[YaNet] Invalid endpoint: " << connectTo << std::endl;
        }
    }

    // ── Start receive thread ────────────────────────────────────────────
    std::thread receiveThread([&]() {
        while (g_running) {
            g_transport.poll(onPacketReceived, 100);
        }
    });

    // ── Start keepalive thread ──────────────────────────────────────────
    std::thread keepaliveThread([&]() {
        while (g_running) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(YANET_KEEPALIVE_INTERVAL_MS)
            );

            auto peers = g_peers.allPeers();
            for (auto* peer : peers) {
                if (peer->state() == yanet::PeerState::ESTABLISHED) {
                    yanet::Packet ka(yanet::PacketType::KEEPALIVE,
                                     g_identity.address(), peer->address());
                    ka.setSequence(peer->nextSequence());
                    g_transport.sendPacket(ka, peer->endpoint());
                }
            }

            // Cleanup expired peers
            g_peers.cleanupExpired(YANET_PEER_TIMEOUT_MS);
        }
    });

    // ── Interactive command loop on main thread ─────────────────────────
    commandLoop();

    // ── Cleanup ─────────────────────────────────────────────────────────
    g_running = false;

    if (receiveThread.joinable()) receiveThread.join();
    if (keepaliveThread.joinable()) keepaliveThread.join();

    g_transport.close();
    yanet::UDPTransport::cleanupWinsock();

    std::cout << "[YaNet] Goodbye!" << std::endl;
    return 0;
}
