# YaNet Protocol Specification

## Version: 1

## Overview

YaNet uses a custom binary protocol over UDP. All multi-byte integers are encoded in **big-endian** (network byte order).

## Packet Header (22 bytes)

```
Offset  Size  Field           Description
------  ----  -----           -----------
0       4     Magic           0x594E4554 ("YNET")
4       1     Version         Protocol version (currently 1)
5       1     Type            Packet type
6       5     Source Address   Sender's 40-bit node address
11      5     Dest Address     Recipient's 40-bit node address
16      4     Sequence        Packet sequence number
20      2     Payload Length   Length of payload following header
22      N     Payload         Type-dependent payload
```

## Packet Types

| Type | Value | Direction | Payload |
|------|-------|-----------|---------|
| HELLO | 0x01 | → | Sender's public key (32 bytes) |
| HELLO_ACK | 0x02 | ← | Responder's public key (32 bytes) |
| DATA | 0x03 | ↔ | Encrypted payload (nonce + ciphertext + MAC) |
| KEEPALIVE | 0x04 | ↔ | Empty |
| PEER_INFO | 0x05 | ↔ | List of known peer endpoints |
| REGISTER | 0x10 | → Server | Node address + public key |
| LOOKUP | 0x11 | → Server | Target node address |
| LOOKUP_RESP | 0x12 | ← Server | Target's endpoint (IP:port) |
| PUNCH | 0x13 | ↔ | NAT hole-punch probe |

## Handshake Protocol

```
    Node A                    Node B
      |                         |
      |--- HELLO (pubKeyA) ---->|
      |                         |
      |<-- HELLO_ACK (pubKeyB) -|
      |                         |
      |  [Both derive session   |
      |   key via X25519 +      |
      |   BLAKE2b KDF]          |
      |                         |
      |--- DATA (encrypted) --->|
      |<-- DATA (encrypted) ----|
```

## Encryption

### Key Exchange
1. Both parties exchange public keys via HELLO/HELLO_ACK
2. Each computes: `sharedSecret = X25519(mySecretKey, theirPublicKey)`
3. Session key derived: `sessionKey = BLAKE2b(sharedSecret || initiatorAddr || responderAddr)`

### Data Encryption
- Algorithm: XChaCha20-Poly1305 (AEAD)
- Nonce: 24 bytes, randomly generated per packet
- Format: `[nonce (24B)][ciphertext][MAC (16B)]`

## Node Address

- Derived from: `BLAKE2b(publicKey)[0:5]`
- Displayed as: 10-character hex string (e.g., `a1b2c3d4e5`)
- Collision probability: ~1 in 1 trillion with 1M nodes
