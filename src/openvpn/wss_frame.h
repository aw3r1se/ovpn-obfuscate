/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OPENVPN_WSS_FRAME_H
#define OPENVPN_WSS_FRAME_H

#include "buffer.h"

/* The supplied legacy WSS peer uses little-endian extended frame lengths. */
bool obfs_ws_encode(const uint8_t *payload, size_t len, unsigned int opcode,
                   const uint8_t mask[4], struct buffer *out);
/* 0 = need more header, -1 = invalid; otherwise header length. */
int obfs_ws_header(const uint8_t *data, size_t available, size_t maximum,
                  size_t *payload_len, unsigned int *opcode);
bool obfs_ws_upgrade_response(const char *response, size_t length, const char *accept);

#endif
