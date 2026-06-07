/**
 * YaNet — A Peer-to-Peer Virtual Network
 * version.h — Version constants
 *
 * Copyright (c) 2026, Yaswanth
 * Licensed under the MIT License.
 */

#pragma once

#define YANET_VERSION_MAJOR 0
#define YANET_VERSION_MINOR 1
#define YANET_VERSION_PATCH 0
#define YANET_VERSION_STRING "0.1.0"
#define YANET_VERSION_BUILD 1

// Protocol version — increment when wire format changes
#define YANET_PROTOCOL_VERSION 1

// Magic bytes for packet identification ("YNET")
#define YANET_PACKET_MAGIC 0x594E4554

// Default ports
#define YANET_DEFAULT_PORT 9994
#define YANET_DEFAULT_API_PORT 9995

// Timing constants (milliseconds)
#define YANET_KEEPALIVE_INTERVAL_MS 10000
#define YANET_PEER_TIMEOUT_MS 60000
#define YANET_HANDSHAKE_TIMEOUT_MS 5000

// Buffer sizes
#define YANET_MAX_PACKET_SIZE 2800
#define YANET_MTU 1400
#define YANET_MAX_PEERS 256
