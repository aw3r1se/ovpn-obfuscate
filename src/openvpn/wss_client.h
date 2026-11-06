/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OPENVPN_WSS_CLIENT_H
#define OPENVPN_WSS_CLIENT_H

struct options;
struct link_socket;
struct signal_info;
struct wss_client;
struct wss_client *obfs_wss_new(const struct options *options);
void obfs_wss_free(struct wss_client *state);
bool obfs_wss_connect(struct link_socket *sock, struct signal_info *signal);
bool obfs_wss_pending(struct link_socket *sock);
bool obfs_wss_wants_write(const struct link_socket *sock);
bool obfs_wss_flush(struct link_socket *sock);
int obfs_wss_read(struct link_socket *sock, struct buffer *out);
int obfs_wss_write(struct link_socket *sock, const struct buffer *payload, unsigned int opcode);

#endif
