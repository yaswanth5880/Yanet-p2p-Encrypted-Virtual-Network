# YaNet — A Peer-to-Peer Virtual Network

```
  ╦ ╦┌─┐╔╗╔┌─┐┌┬┐
  ╚╦╝├─┤║║║├┤  │
   ╩ ┴ ┴╝╚╝└─┘ ┴
```

**YaNet** is a peer-to-peer encrypted virtual networking tool, inspired by [ZeroTier](https://www.zerotier.com/). It creates secure, direct connections between nodes across the internet, allowing them to communicate as if they were on the same local network.

## Features

- 🔐 **End-to-end encryption** — X25519 key exchange + XChaCha20-Poly1305 (via libsodium)
- 🌐 **Peer-to-peer** — Direct connections between nodes, no central server for data
- 🪪 **Cryptographic identity** — Every node has a unique 40-bit address derived from its public key
- 📦 **Custom wire protocol** — Efficient binary packet format with magic bytes, versioning, and sequencing
- 🔄 **Keepalive** — Automatic connection monitoring and stale peer cleanup
- 💻 **Interactive CLI** — Built-in command shell for managing connections

## Quick Start

### Build

```bash
# Configure (from project root)
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build
cmake --build build --config Release

# Run
.\build\Release\yanet.exe
```

### Usage

```bash
# Node A: Start listening (generates identity on first run)
yanet.exe --port 9994

# Node B: Connect to Node A
yanet.exe --port 9995 --connect 192.168.1.100:9994

# Interactive commands:
yanet> connect 192.168.1.100:9994   # Connect to a peer
yanet> msg Hello, World!            # Send encrypted message
yanet> peers                        # List connected peers
yanet> info                         # Show node info
yanet> quit                         # Exit
```

## Architecture

```
┌─────────────────────────────────┐
│           YaNet Node            │
├─────────────────────────────────┤
│  CLI / Interactive Shell        │
├─────────────────────────────────┤
│  Identity Manager (X25519)      │
│  Crypto Engine (XChaCha20)      │
├─────────────────────────────────┤
│  Packet Engine (wire protocol)  │
│  Peer Manager (state machine)   │
├─────────────────────────────────┤
│  UDP Transport (Winsock2)       │
└─────────────────────────────────┘
```

## Wire Protocol

Each YaNet packet has a 22-byte header:

| Field       | Size    | Description                           |
|-------------|---------|---------------------------------------|
| Magic       | 4 bytes | `YNET` (0x594E4554)                   |
| Version     | 1 byte  | Protocol version                      |
| Type        | 1 byte  | Packet type (HELLO, DATA, etc.)       |
| Source Addr  | 5 bytes | Sender's node address                 |
| Dest Addr    | 5 bytes | Recipient's node address              |
| Sequence    | 4 bytes | Packet sequence number                |
| Payload Len  | 2 bytes | Length of payload following header     |

## Security

- **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)
- **Encryption**: XChaCha20-Poly1305 (AEAD)
- **Address Derivation**: BLAKE2b hash of public key
- **Library**: libsodium (audited, battle-tested)

## License

MIT License — Yaswanth
