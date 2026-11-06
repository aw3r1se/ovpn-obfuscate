/* SPDX-License-Identifier: GPL-2.0-only
 * Client-only legacy WSS transport. Memory BIOs keep OpenSSL from
 * racing OpenVPN's overlapped Windows socket reads. TLS and frame boundaries
 * remain independent of the underlying recv() boundaries.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syshead.h"
#include "socket.h"
#include "options.h"
#include "sig.h"
#include "wss_frame.h"
#include "wss_client.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#ifdef _WIN32
#include <wincrypt.h>
#endif

#define WSS_BUFFER_LIMIT 131072

struct wss_client
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *incoming, *outgoing;
    const struct options *options;
    uint8_t plain[WSS_BUFFER_LIMIT];
    size_t plain_len;
    bool failed;
#ifdef _WIN32
    size_t write_queued;
#endif
};

static void
wss_fail(struct link_socket *sock, const char *reason)
{
    unsigned long error = ERR_peek_last_error();
    msg(M_WARN, "WSS: %s (TLS error=%lu)", reason, error);
    sock->wss->failed = true;
    sock->stream_reset = true;
}

static bool
wss_load_trust(SSL_CTX *ctx)
{
#ifdef _WIN32
    HCERTSTORE store = CertOpenSystemStoreA(0, "ROOT");
    if (!store)
    {
        return false;
    }
    PCCERT_CONTEXT cert = NULL;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL)
    {
        const unsigned char *p = cert->pbCertEncoded;
        X509 *x509 = d2i_X509(NULL, &p, cert->cbCertEncoded);
        if (x509)
        {
            /* Duplicate roots are harmless. Do not leave their errors queued. */
            X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x509);
            X509_free(x509);
            ERR_clear_error();
        }
    }
    CertCloseStore(store, 0);
    return true;
#else
    return SSL_CTX_set_default_verify_paths(ctx) == 1;
#endif
}

struct wss_client *
obfs_wss_new(const struct options *options)
{
    struct wss_client *s = calloc(1, sizeof(*s));
    if (!s)
    {
        return NULL;
    }
    s->options = options;
    s->ctx = SSL_CTX_new(TLS_client_method());
    if (!s->ctx)
    {
        obfs_wss_free(s);
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(s->ctx, TLS1_2_VERSION) != 1)
    {
        obfs_wss_free(s);
        return NULL;
    }
    if (options->wss_allow_self_signed)
    {
        msg(M_WARN, "WSS: outer TLS certificate verification disabled by explicit profile option");
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_NONE, NULL);
    }
    else
    {
        SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
        if (!wss_load_trust(s->ctx))
        {
            obfs_wss_free(s);
            return NULL;
        }
    }
    s->ssl = SSL_new(s->ctx);
    s->incoming = BIO_new(BIO_s_mem());
    s->outgoing = BIO_new(BIO_s_mem());
    if (!s->ssl || !s->incoming || !s->outgoing)
    {
        BIO_free(s->incoming);
        BIO_free(s->outgoing);
        s->incoming = s->outgoing = NULL;
        obfs_wss_free(s);
        return NULL;
    }
    BIO_set_mem_eof_return(s->incoming, -1);
    SSL_set_bio(s->ssl, s->incoming, s->outgoing);
    SSL_set_connect_state(s->ssl);
    const char *host = options->wss_sni_enabled && options->wss_sni
                       ? options->wss_sni : options->wss_host;
    if (options->wss_sni_enabled
        && SSL_set_tlsext_host_name(s->ssl, (char *)(options->wss_sni ? options->wss_sni : host)) != 1)
    {
        obfs_wss_free(s);
        return NULL;
    }
    if (!options->wss_allow_self_signed)
    {
        uint8_t address[16];
        const bool ip = inet_pton(AF_INET, host, address) == 1
                        || inet_pton(AF_INET6, host, address) == 1;
        int verified = ip ? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(s->ssl), host)
                          : SSL_set1_host(s->ssl, host);
        if (verified != 1)
        {
            obfs_wss_free(s);
            return NULL;
        }
    }
    return s;
}

void
obfs_wss_free(struct wss_client *s)
{
    if (s)
    {
        SSL_free(s->ssl); /* owns the memory BIOs after SSL_set_bio */
        SSL_CTX_free(s->ctx);
        free(s);
    }
}

/* The handshake shares a single deadline, including TLS, HTTP and socket I/O. */
static bool
wss_wait(struct link_socket *sock, bool writing, time_t deadline, struct signal_info *sig)
{
    while (time(NULL) < deadline)
    {
        if (sig)
        {
            get_signal(&sig->signal_received);
            if (sig->signal_received)
            {
                return false;
            }
        }
#ifdef _WIN32
        fd_set set;
        FD_ZERO(&set);
        FD_SET(sock->sd, &set);
        struct timeval interval = { 0, 200000 };
        int result = select(0, writing ? NULL : &set,
                            writing ? &set : NULL, NULL, &interval);
#else
        struct pollfd descriptor = { .fd = sock->sd, .events = (short)(writing ? POLLOUT : POLLIN) };
        int result = poll(&descriptor, 1, 200);
        if (result < 0 && errno == EINTR)
        {
            continue;
        }
#endif
        if (result > 0)
        {
            return true;
        }
        if (result < 0)
        {
            return false;
        }
    }
    return false;
}

static bool
wss_handshake_flush(struct link_socket *sock, time_t deadline, struct signal_info *sig)
{
    BIO *bio = sock->wss->outgoing;
    while (BIO_ctrl_pending(bio))
    {
        char *data;
        long available = BIO_get_mem_data(bio, &data);
        if (!wss_wait(sock, true, deadline, sig))
        {
            return false;
        }
        int sent = (int)send(sock->sd, data, (int)available, 0);
        if (sent <= 0)
        {
            return false;
        }
        char discarded[4096];
        int remaining = sent;
        while (remaining > 0)
        {
            int count = remaining < (int)sizeof(discarded) ? remaining : (int)sizeof(discarded);
            int consumed = BIO_read(bio, discarded, count);
            if (consumed <= 0)
            {
                return false;
            }
            remaining -= consumed;
        }
    }
    return true;
}

static bool
wss_handshake_input(struct link_socket *sock, time_t deadline, struct signal_info *sig)
{
    uint8_t data[16384];
    if (!wss_handshake_flush(sock, deadline, sig) || !wss_wait(sock, false, deadline, sig))
    {
        return false;
    }
    int count = (int)recv(sock->sd, (char *)data, sizeof(data), 0);
    return count > 0 && BIO_write(sock->wss->incoming, data, count) == count;
}

bool
obfs_wss_connect(struct link_socket *sock, struct signal_info *sig)
{
    struct wss_client *s = sock->wss;
    const struct options *o = s->options;
    int timeout = o->ce.connect_timeout > 0 ? o->ce.connect_timeout : 30;
    time_t deadline = time(NULL) + timeout;
    while (true)
    {
        ERR_clear_error();
        int result = SSL_do_handshake(s->ssl);
        if (result == 1)
        {
            break;
        }
        if (SSL_get_error(s->ssl, result) != SSL_ERROR_WANT_READ
            || !wss_handshake_input(sock, deadline, sig))
        {
            wss_fail(sock, "outer TLS handshake failed or timed out");
            return false;
        }
    }
    if (!wss_handshake_flush(sock, deadline, sig))
    {
        wss_fail(sock, "failed to flush TLS handshake");
        return false;
    }
    uint8_t random[16], hash[EVP_MAX_MD_SIZE];
    char key[25], accept[29];
    unsigned int hash_len;
    if (RAND_bytes(random, sizeof(random)) != 1)
    {
        return false;
    }
    EVP_EncodeBlock((unsigned char *)key, random, sizeof(random));
    const char *accept_key = key;
    const char *names[] = { "Host", "Connection", "Pragma", "Cache-Control", "User-Agent",
                           "Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Language",
                           "Sec-WebSocket-Key" };
    char origin[512];
    snprintf(origin, sizeof(origin), "https://%s", o->wss_host);
    const char *values[] = { o->wss_host, "Upgrade", "no-cache", "no-cache",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                            "websocket", origin, "13", "en-US,en;q=0.9,ru;q=0.8", key };
    struct buffer request = alloc_buf(16384);
    bool request_ok = buf_printf(&request, "GET %s HTTP/1.1\r\n", o->wss_uri ? o->wss_uri : "/");
    bool used[20] = { false };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
    {
        const char *value = values[i];
        for (int j = 0; j < o->wss_header_count; ++j)
        {
            if (!strcasecmp(names[i], o->wss_header_name[j]))
            {
                value = o->wss_header_value[j];
                used[j] = true;
            }
        }
        if (value && *value)
        {
            request_ok = buf_printf(&request, "%s: %s\r\n", names[i], value) && request_ok;
        }
        if (i == 9)
        {
            accept_key = value;
        }
    }
    for (int j = 0; j < o->wss_header_count; ++j)
    {
        if (!used[j] && *o->wss_header_value[j])
        {
            request_ok = buf_printf(&request, "%s: %s\r\n", o->wss_header_name[j], o->wss_header_value[j])
                         && request_ok;
        }
    }
    request_ok = buf_printf(&request, "\r\n") && request_ok;
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    bool digest_ok = digest && accept_key && *accept_key
                     && EVP_DigestInit_ex(digest, EVP_sha1(), NULL) == 1
                     && EVP_DigestUpdate(digest, accept_key, strlen(accept_key)) == 1
                     && EVP_DigestUpdate(digest, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36) == 1
                     && EVP_DigestFinal_ex(digest, hash, &hash_len) == 1 && hash_len == 20;
    EVP_MD_CTX_free(digest);
    if (!request_ok || !digest_ok)
    {
        free_buf(&request);
        wss_fail(sock, "HTTP Upgrade headers invalid or too large");
        return false;
    }
    EVP_EncodeBlock((unsigned char *)accept, hash, hash_len);
    ERR_clear_error();
    int written = SSL_write(s->ssl, BPTR(&request), BLEN(&request));
    bool sent = written == BLEN(&request) && wss_handshake_flush(sock, deadline, sig);
    free_buf(&request);
    if (!sent)
    {
        wss_fail(sock, "HTTP Upgrade write failed");
        return false;
    }
    char response[4097];
    size_t count = 0;
    bool complete = false;
    while (count < sizeof(response) - 1 && time(NULL) < deadline)
    {
        ERR_clear_error();
        int result = SSL_read(s->ssl, response + count, 1);
        if (result == 1)
        {
            ++count;
            if (count >= 4 && !memcmp(response + count - 4, "\r\n\r\n", 4))
            {
                complete = true;
                break;
            }
        }
        else if (SSL_get_error(s->ssl, result) != SSL_ERROR_WANT_READ
                 || !wss_handshake_input(sock, deadline, sig))
        {
            break;
        }
    }
    response[count] = '\0';
    if (!complete || !obfs_ws_upgrade_response(response, count, accept))
    {
        wss_fail(sock, "invalid or incomplete WebSocket Upgrade response");
        return false;
    }
    msg(M_INFO, "WSS: TLS and WebSocket Upgrade complete (legacy little-endian frames)");
    return true;
}

static bool
wss_consume_output(struct wss_client *s, size_t length)
{
    char discarded[4096];
    while (length)
    {
        int chunk = length < sizeof(discarded) ? (int)length : (int)sizeof(discarded);
        if (BIO_read(s->outgoing, discarded, chunk) != chunk)
        {
            return false;
        }
        length -= (size_t)chunk;
    }
    return true;
}

bool
obfs_wss_wants_write(const struct link_socket *sock)
{
    return sock->wss && BIO_ctrl_pending(sock->wss->outgoing) != 0;
}

bool
obfs_wss_flush(struct link_socket *sock)
{
    struct wss_client *s = sock->wss;
    if (s->failed)
    {
        return false;
    }
    while (true)
    {
#ifdef _WIN32
        if (s->write_queued)
        {
            sockethandle_t handle = { .s = sock->sd };
            int completed = sockethandle_finalize(handle, &sock->writes, NULL, NULL);
            if (completed < 0 && SocketHandleGetLastError(handle) == ERROR_IO_INCOMPLETE)
            {
                return true;
            }
            if (completed <= 0 || (size_t)completed > s->write_queued
                || !wss_consume_output(s, (size_t)completed))
            {
                wss_fail(sock, "encrypted socket write failed");
                return false;
            }
            s->write_queued = 0;
        }
#endif
        size_t pending = BIO_ctrl_pending(s->outgoing);
        if (!pending)
        {
#ifdef _WIN32
            /* INITIAL is writable; queuing the next operation resets this event. */
            ASSERT(SetEvent(sock->writes.overlapped.hEvent));
#endif
            return true;
        }
        if (pending > WSS_BUFFER_LIMIT)
        {
            wss_fail(sock, "TLS output buffer exhausted");
            return false;
        }
        char *data;
        long available = BIO_get_mem_data(s->outgoing, &data);
        if (available <= 0)
        {
            wss_fail(sock, "cannot access TLS output");
            return false;
        }
#ifdef _WIN32
        int capacity = sock->writes.buf_init.capacity - sock->writes.buf_init.offset;
        if (capacity <= 0)
        {
            wss_fail(sock, "invalid socket write buffer capacity");
            return false;
        }
        int chunk = available < capacity ? (int)available : capacity;
        struct buffer encrypted;
        buf_set_read(&encrypted, (uint8_t *)data, chunk);
        socket_send_queue(sock, &encrypted, &sock->info.lsa->actual);
        s->write_queued = (size_t)chunk;
#else
        ssize_t sent = send(sock->sd, data, (size_t)available, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
        {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            return true;
        }
        if (sent <= 0 || !wss_consume_output(s, (size_t)sent))
        {
            wss_fail(sock, "encrypted socket write failed");
            return false;
        }
#endif
    }
}

int
obfs_wss_write(struct link_socket *sock, const struct buffer *payload, unsigned int opcode)
{
    struct wss_client *s = sock->wss;
    if (s->failed || BLEN(payload) < 0 || BLEN(payload) > 65535)
    {
        wss_fail(sock, "invalid WebSocket payload length");
        return -1;
    }
    struct buffer frame = alloc_buf(BLEN(payload) + 8);
    uint8_t mask[4];
    bool ok = RAND_bytes(mask, 4) == 1
              && obfs_ws_encode(BPTR(payload), BLEN(payload), opcode, mask, &frame);
    ERR_clear_error();
    int result = ok ? SSL_write(s->ssl, BPTR(&frame), BLEN(&frame)) : -1;
    ok = ok && result == BLEN(&frame);
    free_buf(&frame);
    if (!ok)
    {
        wss_fail(sock, "TLS frame write failed");
        return -1;
    }
    return obfs_wss_flush(sock) ? BLEN(payload) : -1;
}

bool
obfs_wss_pending(struct link_socket *sock)
{
    struct wss_client *s = sock->wss;
    if (s->failed)
    {
        /* Wake the loop once so the failure is handled; see obfs_wss_read(). */
        return true;
    }
    while (true)
    {
        size_t payload_len = 0;
        unsigned int opcode = 0;
        int header = obfs_ws_header(s->plain, s->plain_len, sock->stream_buf.maxlen,
                                   &payload_len, &opcode);
        if (header < 0)
        {
            wss_fail(sock, "invalid legacy WebSocket frame");
            return true;
        }
        if (header > 0 && s->plain_len >= header + payload_len)
        {
            if (opcode == 2)
            {
                return true;
            }
            if (opcode == 8)
            {
                wss_fail(sock, "WebSocket server closed the connection");
                return true;
            }
            if (opcode == 9)
            {
                struct buffer ping;
                buf_set_read(&ping, s->plain + header, (int)payload_len);
                if (obfs_wss_write(sock, &ping, 10) < 0)
                {
                    return true;
                }
            }
            s->plain_len -= header + payload_len;
            memmove(s->plain, s->plain + header + payload_len, s->plain_len);
            continue;
        }
        if (s->plain_len == sizeof(s->plain))
        {
            wss_fail(sock, "WebSocket receive buffer exhausted");
            return true;
        }
        ERR_clear_error();
        int received = SSL_read(s->ssl, s->plain + s->plain_len,
                                (int)(sizeof(s->plain) - s->plain_len));
        if (received > 0)
        {
            s->plain_len += received;
            continue;
        }
        if (SSL_get_error(s->ssl, received) != SSL_ERROR_WANT_READ)
        {
            wss_fail(sock, "TLS receive failed or closed");
            return true;
        }
        return false;
    }
}

int
obfs_wss_read(struct link_socket *sock, struct buffer *out)
{
    struct wss_client *s = sock->wss;
    if (!obfs_wss_pending(sock))
    {
#ifdef _WIN32
        sockethandle_t sh = { .s = sock->sd };
        struct buffer raw = sock->reads.buf_init;
        int received = sockethandle_finalize(sh, &sock->reads, &raw, NULL);
#else
        uint8_t data[16384];
        struct buffer raw;
        int received = (int)recv(sock->sd, (char *)data, sizeof(data), MSG_NOSIGNAL);
        buf_set_read(&raw, data, received > 0 ? received : 0);
#endif
        if (received == 0)
        {
            wss_fail(sock, "TCP peer closed the connection");
        }
        else if (received > 0 && BIO_write(s->incoming, BPTR(&raw), received) != received)
        {
            wss_fail(sock, "cannot buffer incoming TLS bytes");
        }
        if (received < 0 || !obfs_wss_pending(sock))
        {
            return out->len = received < 0 ? received : 0;
        }
    }
    if (s->failed)
    {
        /*
         * Report the failure as a reset so read_incoming_link() reconnects
         * instead of waiting for a socket event that may never come.
         */
        return out->len = -1;
    }
    size_t len;
    unsigned int opcode;
    int header = obfs_ws_header(s->plain, s->plain_len, sock->stream_buf.maxlen, &len, &opcode);
    if (header <= 0 || opcode != 2 || !buf_write(out, s->plain + header, (int)len))
    {
        wss_fail(sock, "cannot deliver WebSocket packet");
        return out->len = 0;
    }
    s->plain_len -= header + len;
    memmove(s->plain, s->plain + header + len, s->plain_len);
    return out->len;
}
