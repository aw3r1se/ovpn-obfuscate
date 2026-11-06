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
 * This is a byte-exact reimplementation of a third-party obfuscation-patched
 * OpenVPN 2.x client, recovered by reverse engineering.  The wire format must
 * match that client (and therefore the service's server) exactly.
 *
 * Per-packet scheme (applied on send, reversed on receive):
 *   Phase 1: random padding with a marker-based boundary (control packets are
 *            force-padded to at least 32 bytes)
 *   Phase 2: 32-bit XOR cascade (multiplier 0xCC9E2D51), key XOR'd into the
 *            LAST word
 *   Phase 3: AES-128-XTS over the head of the packet, tweak = last 16 bytes
 *   Phase 4: 64-bit XOR cascade (multiplier 0x87C37B91114253D5)
 *
 * Key schedule (64-byte key): the two 32-byte halves are used independently
 * for the two directions.  For each half:
 *   xts_key      = the 32 raw bytes (AES-128-XTS key)
 *   marker_byte  = SHA256(half)[0]
 *   xor32        = SHA256(half)[1..4]   (native byte order)
 * The first half drives the send (obfuscate) direction, the second half the
 * receive (deobfuscate) direction.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "obfs_udp.h"
#include "error.h"
#include "buffer.h"

#include "memdbg.h"

#ifdef ENABLE_CRYPTO_OPENSSL

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* --- Constants (byte-identical to the reverse-engineered client) --- */
#define OBFS_MAX_PACKET_SIZE 0x5C0 /* 1472 */
#define OBFS_MIN_PACKET_SIZE 0x20  /* 32   */
#define OBFS_CTRL_MIN_PADDING 0x11 /* 17   */
#define OBFS_PADDING_FLAG 0x80
#define OBFS_IV_LEN 16
#define OBFS_XTS_KEY_LEN 32

#define OBFS_MURMUR_C1_32 0xCC9E2D51U
#define OBFS_MURMUR_C2_64 0x87C37B91114253D5ULL

/* OpenVPN data-channel opcodes (same in tun and tap mode). */
#define OBFS_P_DATA_V1 6
#define OBFS_P_DATA_V2 9

/* One per-direction key schedule. */
struct obfs_dir
{
    uint8_t marker_byte;     /* SHA256(half)[0]      */
    uint32_t xor32;          /* SHA256(half)[1..4]   */
    EVP_CIPHER_CTX *ctx;     /* AES-128-XTS context  */
};

struct obfs_udp
{
    int max_padding;
    struct obfs_dir send;    /* obfuscate:  key[0..31]   */
    struct obfs_dir recv;    /* deobfuscate: key[32..63] */
    uint64_t rng_state;      /* non-cryptographic, only chooses the pad length */
};

/* --- Small endianness-safe load/store helpers (avoid unaligned UB) --- */
static inline uint32_t
obfs_ld32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void
obfs_st32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static inline uint64_t
obfs_ld64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void
obfs_st64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

/* xorshift64* -- only used to pick a random padding length; the exact
 * distribution is irrelevant to wire compatibility. */
static inline uint64_t
obfs_rng_next(struct obfs_udp *o)
{
    uint64_t x = o->rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    o->rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* --- hex decode --- */
static bool
obfs_parse_hex(const char *hex, uint8_t *out, int out_len)
{
    for (int i = 0; i < out_len; ++i)
    {
        unsigned int byte;
        if (!isxdigit((unsigned char)hex[i * 2])
            || !isxdigit((unsigned char)hex[i * 2 + 1])
            || sscanf(hex + i * 2, "%2x", &byte) != 1)
        {
            return false;
        }
        out[i] = (uint8_t)byte;
    }
    return true;
}

/* --- Phase 2: 32-bit XOR cascade ---
 * The cascade covers the trailing aligned words (the first len%4 bytes are
 * skipped).  The key is XOR'd into the LAST word, then each word is mixed with
 * the (already updated) word to its right. */
static void
obfs_xor_cascade_32_encrypt(uint32_t xor32, uint8_t *data, int len)
{
    const int offset = len & 3;
    uint8_t *base = data + offset;
    const int n = len >> 2;

    if (n < 2)
    {
        return;
    }

    obfs_st32(base + 4 * (n - 1), obfs_ld32(base + 4 * (n - 1)) ^ xor32);

    for (int i = n - 2; i >= 1; --i)
    {
        obfs_st32(base + 4 * i,
                  obfs_ld32(base + 4 * i) ^ (obfs_ld32(base + 4 * (i + 1)) * OBFS_MURMUR_C1_32));
    }
}

static void
obfs_xor_cascade_32_decrypt(uint32_t xor32, uint8_t *data, int len)
{
    const int offset = len & 3;
    uint8_t *base = data + offset;
    const int n = len >> 2;

    if (n < 2)
    {
        return;
    }

    for (int i = 1; i < n - 1; ++i)
    {
        obfs_st32(base + 4 * i,
                  obfs_ld32(base + 4 * i) ^ (obfs_ld32(base + 4 * (i + 1)) * OBFS_MURMUR_C1_32));
    }

    obfs_st32(base + 4 * (n - 1), obfs_ld32(base + 4 * (n - 1)) ^ xor32);
}

/* --- Phase 4: 64-bit XOR cascade --- */
static void
obfs_xor_cascade_64_encrypt(uint8_t *data, int len)
{
    const int n = len >> 3;
    const int tail = len & 7;

    if (n >= 2)
    {
        uint64_t chain = obfs_ld64(data);
        for (int i = 1; i < n; ++i)
        {
            chain = chain * OBFS_MURMUR_C2_64 ^ obfs_ld64(data + 8 * i);
            obfs_st64(data + 8 * i, chain);
        }
    }

    if (tail > 0 && n >= 1)
    {
        const uint64_t tail_val = obfs_ld64(data + 8 * (n - 1)) * OBFS_MURMUR_C2_64;
        const int aligned = n * 8;
        for (int i = 0; i < tail; ++i)
        {
            data[aligned + i] = (uint8_t)(data[aligned + i] ^ (uint8_t)(tail_val >> (i * 8)));
        }
    }
}

static void
obfs_xor_cascade_64_decrypt(uint8_t *data, int len)
{
    const int n = len >> 3;
    const int tail = len & 7;

    /* Tail first (mirror of the encrypt order). */
    if (tail > 0 && n >= 1)
    {
        const uint64_t tail_val = obfs_ld64(data + 8 * (n - 1)) * OBFS_MURMUR_C2_64;
        const int aligned = n * 8;
        for (int i = 0; i < tail; ++i)
        {
            data[aligned + i] = (uint8_t)(data[aligned + i] ^ (uint8_t)(tail_val >> (i * 8)));
        }
    }

    if (n >= 2)
    {
        for (int i = n - 1; i >= 1; --i)
        {
            obfs_st64(data + 8 * i,
                      obfs_ld64(data + 8 * i) ^ (obfs_ld64(data + 8 * (i - 1)) * OBFS_MURMUR_C2_64));
        }
    }
}

/* --- Phase 3: AES-128-XTS over the head of the packet ---
 * crypt_len = 16 for data packets (opcode 6/9, total >= 48), else total-16.
 * The tweak (IV) is always the last 16 bytes; they are never themselves
 * encrypted.  The cipher context already carries the direction (enc/dec). */
static bool
obfs_xts_crypt(EVP_CIPHER_CTX *ctx, uint8_t *data, int crypt_len, const uint8_t *iv)
{
    int out_len = 0, final_len = 0;

    if (crypt_len < OBFS_IV_LEN)
    {
        msg(D_LINK_RW, "OBFS: xts_crypt: len is too small (%d)", crypt_len);
        return false;
    }
    if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1) != 1)
    {
        msg(D_LINK_RW, "OBFS: cipher_ctx_reset() has failed");
        return false;
    }
    if (EVP_CipherUpdate(ctx, data, &out_len, data, crypt_len) != 1)
    {
        msg(D_LINK_RW, "OBFS: cipher_ctx_update() has failed");
        return false;
    }
    if (EVP_CipherFinal_ex(ctx, data + out_len, &final_len) != 1)
    {
        msg(D_LINK_RW, "OBFS: cipher_ctx_final() has failed");
        return false;
    }
    if (out_len + final_len != crypt_len)
    {
        msg(D_LINK_RW, "OBFS: crypto length mismatch (%d+%d!=%d)", out_len, final_len, crypt_len);
        return false;
    }
    return true;
}

/* --- Phase 1: padding (send only) --- */
static bool
obfs_apply_padding(struct obfs_udp *o, struct buffer *buf, int pad_len)
{
    const int orig_len = BLEN(buf);
    const int total_len = orig_len + pad_len;

    if (buf_forward_capacity(buf) < pad_len)
    {
        msg(D_LINK_RW, "OBFS: not enough buffer space for padding");
        return false;
    }

    uint8_t *pad_start = BPTR(buf) + orig_len;

    if (RAND_bytes(pad_start, pad_len) != 1)
    {
        msg(D_LINK_RW, "OBFS: RAND_bytes failed for padding");
        return false;
    }

    /*
     * Marker is recomputed at the receiver from the (known) total length.
     * The modulus is 0xFF -- 255, not 256 -- because that is what the peer
     * computes.  Do not "fix" it to & 0xFF or % 256: the wire format changes.
     */
    const uint8_t marker = (uint8_t)(o->send.marker_byte ^ (uint8_t)(total_len % 0xFF));

    /* Chain-XOR from end to start, bumping bytes to avoid a premature match. */
    uint8_t chain = 0;
    for (int i = pad_len - 1; i >= 1; --i)
    {
        uint8_t cur = pad_start[i];
        uint8_t xored = (uint8_t)(chain ^ cur);
        if (xored == marker)
        {
            pad_start[i] = (uint8_t)(cur + 1);
            xored = (uint8_t)((cur + 1) ^ chain);
        }
        chain = xored;
    }

    /* First padding byte makes the full padding XOR equal to the marker. */
    pad_start[0] = (uint8_t)(marker ^ chain);

    BPTR(buf)[0] = (uint8_t)(BPTR(buf)[0] | OBFS_PADDING_FLAG);
    buf->len = total_len;

    return true;
}

/* Derive one direction's schedule from a 32-byte key half. */
static bool
obfs_dir_init(struct obfs_dir *d, const uint8_t *half32, int enc)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];

    SHA256(half32, OBFS_XTS_KEY_LEN, digest);
    d->marker_byte = digest[0];
    memcpy(&d->xor32, digest + 1, 4);

    d->ctx = EVP_CIPHER_CTX_new();
    if (!d->ctx)
    {
        return false;
    }
    if (EVP_CipherInit_ex(d->ctx, EVP_aes_128_xts(), NULL, half32, NULL, enc) != 1)
    {
        return false;
    }
    EVP_CIPHER_CTX_set_padding(d->ctx, 0);
    return true;
}

struct obfs_udp *
obfs_udp_init(const char *key_hex, int max_padding)
{
    if (!key_hex || strlen(key_hex) != OBFS_UDP_KEY_HEX_LEN)
    {
        msg(M_WARN, "OBFS: key must be exactly %d hex characters", OBFS_UDP_KEY_HEX_LEN);
        return NULL;
    }

    uint8_t key_bin[OBFS_UDP_KEY_BIN_LEN]; /* 64 bytes */
    if (!obfs_parse_hex(key_hex, key_bin, OBFS_UDP_KEY_BIN_LEN))
    {
        msg(M_WARN, "OBFS: invalid hex character in key");
        return NULL;
    }

    struct obfs_udp *o;
    ALLOC_OBJ_CLEAR(o, struct obfs_udp);

    o->max_padding = max_padding;
    if (o->max_padding > OBFS_UDP_MAX_PADDING)
    {
        o->max_padding = OBFS_UDP_MAX_PADDING;
    }
    if (o->max_padding < 0)
    {
        o->max_padding = 0;
    }

    /* Seed the (non-crypto) padding-length RNG. */
    if (RAND_bytes((uint8_t *)&o->rng_state, sizeof(o->rng_state)) != 1 || o->rng_state == 0)
    {
        o->rng_state = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)(uintptr_t)o << 1);
    }

    /* First half drives send (encrypt), second half drives receive (decrypt). */
    if (!obfs_dir_init(&o->send, key_bin, 1) || !obfs_dir_init(&o->recv, key_bin + 32, 0))
    {
        msg(M_WARN, "OBFS: failed to initialize AES-128-XTS context");
        secure_memzero(key_bin, sizeof(key_bin));
        obfs_udp_free(o);
        return NULL;
    }

    secure_memzero(key_bin, sizeof(key_bin));
    msg(M_INFO, "OBFS: UDP obfuscation initialized (padding=%d)", o->max_padding);
    return o;
}

bool
obfs_udp_obfuscate(struct obfs_udp *o, struct buffer *buf)
{
    if (!o || BLEN(buf) <= 0)
    {
        return false;
    }

    uint8_t *data = BPTR(buf);
    const int data_len = BLEN(buf);

    if (data_len > OBFS_MAX_PACKET_SIZE)
    {
        msg(D_LINK_RW, "OBFS: obfuscate: packet is too large (%d)", data_len);
        return false;
    }

    /* opcode is read from the plaintext first byte, before the padding flag. */
    const uint8_t opcode = (uint8_t)(data[0] >> 3);
    const bool is_data = (opcode == OBFS_P_DATA_V1 || opcode == OBFS_P_DATA_V2);

    /* --- Phase 1: choose and apply padding --- */
    int max_add = OBFS_MAX_PACKET_SIZE - data_len;
    if (max_add > o->max_padding)
    {
        max_add = o->max_padding;
    }
    if (data_len + max_add < OBFS_MIN_PACKET_SIZE)
    {
        msg(D_LINK_RW, "OBFS: UDP padding limit too small for %d-byte packet (need at least %d)",
            data_len, OBFS_MIN_PACKET_SIZE - data_len);
        return false;
    }

    int min_pad = is_data ? 0 : OBFS_CTRL_MIN_PADDING;
    if (data_len + min_pad < OBFS_MIN_PACKET_SIZE)
    {
        min_pad = OBFS_MIN_PACKET_SIZE - data_len;
    }

    int pad_len = max_add;
    if (min_pad < max_add)
    {
        /* min_pad < max_add is guaranteed above, so range is always positive. */
        int range = max_add - min_pad;
        pad_len = (int)(min_pad + obfs_rng_next(o) % (uint64_t)(range + 1));
    }
    if (pad_len < 0)
    {
        pad_len = 0;
    }

    if (pad_len > 0)
    {
        if (!obfs_apply_padding(o, buf, pad_len))
        {
            return false;
        }
        data = BPTR(buf);
    }

    const int total_len = BLEN(buf);

    /* --- Phase 2: 32-bit XOR cascade --- */
    obfs_xor_cascade_32_encrypt(o->send.xor32, data, total_len);

    /* --- Phase 3: AES-128-XTS --- */
    {
        const int crypt_len = (total_len >= 0x30 && is_data) ? OBFS_IV_LEN : total_len - OBFS_IV_LEN;
        if (!obfs_xts_crypt(o->send.ctx, data, crypt_len, data + total_len - OBFS_IV_LEN))
        {
            msg(D_LINK_RW, "OBFS: obfuscate_udp() has failed");
            return false;
        }
    }

    /* --- Phase 4: 64-bit XOR cascade --- */
    obfs_xor_cascade_64_encrypt(data, total_len);

    buf->len = total_len;
    return true;
}

bool
obfs_udp_deobfuscate(struct obfs_udp *o, struct buffer *buf)
{
    if (!o || BLEN(buf) <= 0)
    {
        return false;
    }

    uint8_t *data = BPTR(buf);
    const int data_len = BLEN(buf);

    if (data_len < OBFS_MIN_PACKET_SIZE)
    {
        msg(D_LINK_RW, "OBFS: unobfuscate: data_len too small (%d)", data_len);
        return false;
    }
    if (data_len > OBFS_MAX_PACKET_SIZE)
    {
        msg(D_LINK_RW, "OBFS: unobfuscate: data_len too large (%d)", data_len);
        return false;
    }

    uint8_t *const iv = data + data_len - OBFS_IV_LEN;

    /* --- Phase A: reverse 64-bit XOR cascade --- */
    obfs_xor_cascade_64_decrypt(data, data_len);

    /* --- Phase B: AES-128-XTS decrypt ---
     * The opcode is unknown until decrypted.  For large packets we first try
     * the data-packet layout (16 bytes) into a scratch buffer; if the decoded
     * opcode is not a data opcode, re-decrypt with the control layout. */
    if (data_len < 0x30)
    {
        if (!obfs_xts_crypt(o->recv.ctx, data, data_len - OBFS_IV_LEN, iv))
        {
            msg(D_LINK_RW, "OBFS: unobfuscate_udp() has failed");
            return false;
        }
    }
    else
    {
        uint8_t scratch[OBFS_IV_LEN];
        memcpy(scratch, data, OBFS_IV_LEN);
        if (!obfs_xts_crypt(o->recv.ctx, scratch, OBFS_IV_LEN, iv))
        {
            msg(D_LINK_RW, "OBFS: unobfuscate_udp() has failed");
            return false;
        }
        const uint8_t opcode = (uint8_t)((scratch[0] >> 3) & 0x0F);
        if (opcode == OBFS_P_DATA_V1 || opcode == OBFS_P_DATA_V2)
        {
            memcpy(data, scratch, OBFS_IV_LEN);
        }
        else if (!obfs_xts_crypt(o->recv.ctx, data, data_len - OBFS_IV_LEN, iv))
        {
            msg(D_LINK_RW, "OBFS: unobfuscate_udp() has failed");
            return false;
        }
    }

    /* --- Phase C: reverse 32-bit XOR cascade --- */
    obfs_xor_cascade_32_decrypt(o->recv.xor32, data, data_len);

    /* --- Phase D: remove padding --- */
    if (data[0] & OBFS_PADDING_FLAG)
    {
        const uint8_t expected = (uint8_t)(o->recv.marker_byte ^ (uint8_t)(data_len % 0xFF));
        uint8_t chain = 0;
        int new_len = -1;

        for (int i = data_len - 1; i > 0; --i)
        {
            chain = (uint8_t)(chain ^ data[i]);
            if (chain == expected)
            {
                new_len = i;
                break;
            }
        }

        if (new_len < 0)
        {
            msg(D_LINK_RW, "OBFS: find_padding_chunk() failed");
            return false;
        }

        data[0] = (uint8_t)(data[0] & ~OBFS_PADDING_FLAG);
        buf->len = new_len;
    }

    return true;
}

void
obfs_udp_free(struct obfs_udp *o)
{
    if (!o)
    {
        return;
    }
    if (o->send.ctx)
    {
        EVP_CIPHER_CTX_free(o->send.ctx);
        o->send.ctx = NULL;
    }
    if (o->recv.ctx)
    {
        EVP_CIPHER_CTX_free(o->recv.ctx);
        o->recv.ctx = NULL;
    }
    secure_memzero(o, sizeof(*o));
    free(o);
}

#else  /* ENABLE_CRYPTO_OPENSSL */

/* The obfuscation scheme relies on OpenSSL's EVP/RAND/SHA API.  On mbedTLS or
 * wolfSSL builds the directive is accepted by the parser but obfuscation is
 * unavailable; init fails loudly so the mismatch is obvious. */

struct obfs_udp *
obfs_udp_init(const char *key_hex, int max_padding)
{
    (void)key_hex;
    (void)max_padding;
    msg(M_WARN, "OBFS: obfuscate-udp requires an OpenSSL build of OpenVPN");
    return NULL;
}

bool
obfs_udp_obfuscate(struct obfs_udp *o, struct buffer *buf)
{
    (void)o;
    (void)buf;
    return false;
}

bool
obfs_udp_deobfuscate(struct obfs_udp *o, struct buffer *buf)
{
    (void)o;
    (void)buf;
    return false;
}

void
obfs_udp_free(struct obfs_udp *o)
{
    (void)o;
}

#endif /* ENABLE_CRYPTO_OPENSSL */
