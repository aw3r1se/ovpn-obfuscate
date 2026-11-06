/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/*
 * UDP packet obfuscation (the "obfuscate-udp" directive).
 *
 * This implementation wraps a
 * fully formed OpenVPN link packet (post-encryption, at the UDP socket
 * boundary) so that the bytes on the wire do not resemble OpenVPN traffic.
 *
 * Multi-layer scheme (applied in this order on send, reversed on receive):
 *   Phase 1: random padding with marker-based boundary detection
 *   Phase 2: 32-bit XOR cascade (MurmurHash3 c1)
 *   Phase 3: AES-128-XTS partial encryption
 *   Phase 4: 64-bit XOR cascade (MurmurHash3 c2)
 *
 * The peer must implement the same format with complementary transmit/receive
 * key halves. The scheme operates entirely below the OpenVPN
 * protocol, so it is independent of tun vs. tap mode.
 */

#ifndef OPENVPN_OBFS_UDP_H
#define OPENVPN_OBFS_UDP_H

#include "buffer.h"

/* Key length the directive expects: 128 hex chars == 64 binary bytes. */
#define OBFS_UDP_KEY_HEX_LEN 128
#define OBFS_UDP_KEY_BIN_LEN 64
#define OBFS_UDP_MAX_PADDING 1500

/* Opaque obfuscation context, one per link socket. */
struct obfs_udp;

/**
 * Allocate and initialize an obfuscation context.
 *
 * @param key_hex      exactly 128 hex characters (decodes to 64 bytes).
 *                     Each 32-byte half is a directional AES-128-XTS key;
 *                     its SHA-256 digest supplies the padding and XOR keys.
 * @param max_padding  maximum random padding length, clamped to 0..1500.
 * @return a newly allocated context, or NULL on error (the failure is logged).
 *         Free it with obfs_udp_free().
 */
struct obfs_udp *obfs_udp_init(const char *key_hex, int max_padding);

/**
 * Obfuscate a UDP packet in place before sending.  The buffer must have
 * enough forward capacity (tailroom) to hold the appended padding; the frame
 * tailroom is enlarged for this when the directive is configured.
 *
 * @return true on success, false if the packet should be dropped.
 */
bool obfs_udp_obfuscate(struct obfs_udp *o, struct buffer *buf);

/**
 * Reverse the obfuscation of a received UDP packet in place.
 *
 * @return true on success, false if the packet should be dropped.
 */
bool obfs_udp_deobfuscate(struct obfs_udp *o, struct buffer *buf);

/**
 * Free an obfuscation context (NULL is tolerated).
 */
void obfs_udp_free(struct obfs_udp *o);

#endif /* OPENVPN_OBFS_UDP_H */
