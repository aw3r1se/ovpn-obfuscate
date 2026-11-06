/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OPENVPN_OBFS_TCP_H
#define OPENVPN_OBFS_TCP_H

#include "buffer.h"

struct obfs_tcp;
struct obfs_tcp *obfs_tcp_new(const char *key);
void obfs_tcp_free(struct obfs_tcp *state);
bool obfs_tcp_active(const struct obfs_tcp *state);
bool obfs_tcp_encode(struct obfs_tcp *state, struct buffer *buf);
bool obfs_tcp_decode(struct obfs_tcp *state, struct buffer *buf);
/* A deterministic entry point for interoperability tests, not a config option. */
bool obfs_tcp_seed(struct obfs_tcp *state, unsigned int seed);
int obfs_tcp_length_encode(int len, unsigned int multiplier);
int obfs_tcp_length_decode(int len, int maximum);

#endif
