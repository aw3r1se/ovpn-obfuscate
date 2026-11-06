/* SPDX-License-Identifier: GPL-2.0-only
 * TCP scrambler, recovered from the supplied
 * client. These functions operate on complete OpenVPN packets, not recv chunks.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syshead.h"
#include "obfs_tcp.h"
#include "error.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

struct obfs_tcp
{
    char *key;
    uint8_t mask[1024];
    size_t mask_len;
    uint64_t tx_bytes, rx_bytes;
    uint8_t seed;
    bool first_send;
};

struct obfs_tcp *
obfs_tcp_new(const char *key)
{
    if (!key || !*key || strlen(key) > 4096)
    {
        return NULL;
    }
    struct obfs_tcp *s = calloc(1, sizeof(*s));
    if (s)
    {
        s->key = strdup(key);
        s->first_send = true;
        if (!s->key)
        {
            free(s);
            return NULL;
        }
    }
    return s;
}

void
obfs_tcp_free(struct obfs_tcp *s)
{
    if (s)
    {
        if (s->key)
        {
            secure_memzero(s->key, strlen(s->key));
            free(s->key);
        }
        secure_memzero(s, sizeof(*s));
        free(s);
    }
}

bool
obfs_tcp_seed(struct obfs_tcp *s, unsigned int seed)
{
    if (!s || seed > 254 || s->tx_bytes || s->rx_bytes)
    {
        return false;
    }
    const size_t len = strlen(s->key);
    uint8_t chunk[16];
    s->mask_len = 0;
    s->seed = (uint8_t)seed;
    for (size_t offset = 0; offset < len && offset < sizeof(s->mask); offset += 16)
    {
        const size_t count = len - offset < 16 ? len - offset : 16;
        for (size_t i = 0; i < count; ++i)
        {
            chunk[i] = (uint8_t)s->key[(offset + i + seed) % len];
        }
        unsigned int digest_len = 0;
        if (EVP_Digest(chunk, count, s->mask + offset, &digest_len, EVP_md5(), NULL) != 1
            || digest_len != 16)
        {
            s->mask_len = 0;
            return false;
        }
        s->mask_len += digest_len;
    }
    secure_memzero(chunk, sizeof(chunk));
    return true;
}

bool
obfs_tcp_active(const struct obfs_tcp *s)
{
    return s && s->mask_len > 0;
}

bool
obfs_tcp_encode(struct obfs_tcp *s, struct buffer *buf)
{
    const int len = BLEN(buf);
    if (!s || len < 1)
    {
        return false;
    }
    uint8_t *data = BPTR(buf);
    if (s->first_send && data[0] != 0x38 && data[0] != 0x50)
    {
        msg(M_WARN, "OBFS TCP: unsupported initial packet opcode; restarting connection");
        return false;
    }
    if (!s->mask_len)
    {
        uint8_t seed;
        if (RAND_bytes(&seed, 1) != 1 || !obfs_tcp_seed(s, seed % 255))
        {
            return false;
        }
    }
    uint8_t *tmp = calloc((size_t)len, 1);
    if (!tmp)
    {
        return false;
    }
    for (int i = 0; i < len; ++i)
    {
        uint8_t value = data[i] ^ s->mask[(s->tx_bytes + i) % s->mask_len];
        if (s->first_send && i == 0)
        {
            /*
             * The seed is carried in the first byte of the very first packet,
             * so the peer can rebuild the same mask.  This overwrites that
             * packet's opcode byte, which is why encode() above requires it to
             * be 0x38 or 0x50: those are the only two values a first packet
             * can carry, so the peer can restore the opcode from context
             * instead of from the wire.
             *
             * Only this direction substitutes.  Decode() never undoes it and
             * never looks for a seed, so the server's first byte arrives
             * intact (see the 0x40 vector in test_obfs_tcp.c).
             */
            value = s->seed;
        }
        tmp[i] |= value & 0x55;
        tmp[(i + len / 2) % len] |= value & 0xaa;
    }
    for (int i = 0; i < len; ++i)
    {
        data[i] = tmp[len - 1 - i];
    }
    free(tmp);
    s->tx_bytes += len;
    s->first_send = false;
    return true;
}

bool
obfs_tcp_decode(struct obfs_tcp *s, struct buffer *buf)
{
    const int len = BLEN(buf);
    if (!obfs_tcp_active(s) || len < 1)
    {
        return false;
    }
    uint8_t *data = BPTR(buf);
    uint8_t *tmp = calloc((size_t)len, 1);
    if (!tmp)
    {
        return false;
    }
    for (int i = 0; i < len; ++i)
    {
        uint8_t value = data[len - 1 - i];
        tmp[i] |= value & 0x55;
        tmp[(i + len - len / 2) % len] |= value & 0xaa;
    }
    for (int i = 0; i < len; ++i)
    {
        data[i] = tmp[i] ^ s->mask[(s->rx_bytes + i) % s->mask_len];
    }
    free(tmp);
    s->rx_bytes += len;
    return true;
}

int
obfs_tcp_length_encode(int len, unsigned int multiplier)
{
    const unsigned int encoded = (unsigned int)len + (multiplier % 7) * 5621;
    return encoded <= 65534 ? (int)encoded : len;
}

int
obfs_tcp_length_decode(int len, int maximum)
{
    while (len > maximum && len > 5621)
    {
        len -= 5621;
    }
    return len;
}
