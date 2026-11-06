/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syshead.h"
#include "wss_frame.h"

bool
obfs_ws_encode(const uint8_t *payload, size_t len, unsigned int opcode,
              const uint8_t mask[4], struct buffer *out)
{
    if (len > 65535 || !mask || !buf_init(out, 0))
    {
        return false;
    }
    /* Extended lengths are little-endian (legacy peer format) and capped at
     * 16 bits, so the 8-byte (127) form is never emitted. */
    uint8_t header[8] = { (uint8_t)(0x80 | opcode), 0 };
    size_t header_len = len < 126 ? 6 : 8;
    size_t mask_offset = len < 126 ? 2 : 4;
    header[1] = (uint8_t)(0x80 | (len < 126 ? len : 126));
    if (len >= 126)
    {
        header[2] = (uint8_t)len;
        header[3] = (uint8_t)(len >> 8);
    }
    memcpy(header + mask_offset, mask, 4);
    if (!buf_write(out, header, (int)header_len)
        || (len && (!payload || !buf_write(out, payload, (int)len))))
    {
        return false;
    }
    for (size_t i = 0; i < len; ++i)
    {
        BPTR(out)[header_len + i] ^= mask[i % 4];
    }
    return true;
}

int
obfs_ws_header(const uint8_t *data, size_t available, size_t maximum,
              size_t *payload_len, unsigned int *opcode)
{
    if (available < 2)
    {
        return 0;
    }
    if (!(data[0] & 0x80) || (data[0] & 0x70) || (data[1] & 0x80))
    {
        return -1;
    }
    *opcode = data[0] & 15;
    if (*opcode != 1 && *opcode != 2 && *opcode != 8 && *opcode != 9 && *opcode != 10)
    {
        return -1;
    }
    unsigned int marker = data[1] & 127;
    size_t extra = marker == 126 ? 2 : marker == 127 ? 8 : 0;
    if (available < 2 + extra)
    {
        return 0;
    }
    uint64_t size = marker;
    if (extra)
    {
        size = 0;
        for (size_t i = 0; i < extra; ++i)
        {
            size |= (uint64_t)data[2 + i] << (i * 8);
        }
    }
    if (size > maximum || (*opcode >= 8 && size > 125))
    {
        return -1;
    }
    *payload_len = (size_t)size;
    return (int)(2 + extra);
}

static bool
ws_header_token(const char *begin, const char *end, const char *token)
{
    const size_t length = strlen(token);
    while (begin < end)
    {
        while (begin < end && (*begin == ' ' || *begin == '\t' || *begin == ','))
        {
            ++begin;
        }
        const char *next = memchr(begin, ',', (size_t)(end - begin));
        if (!next)
        {
            next = end;
        }
        const char *trimmed = next;
        while (trimmed > begin && (trimmed[-1] == ' ' || trimmed[-1] == '\t'))
        {
            --trimmed;
        }
        if ((size_t)(trimmed - begin) == length && !strncasecmp(begin, token, length))
        {
            return true;
        }
        begin = next < end ? next + 1 : end;
    }
    return false;
}

bool
obfs_ws_upgrade_response(const char *response, size_t length, const char *accept)
{
    if (!response || !accept || !*accept || length < 17 || memchr(response, '\0', length)
        || strncmp(response, "HTTP/1.1 101 ", 13))
    {
        return false;
    }
    const char *end = response + length;
    const char *line = response;
    bool first = true, upgrade = false, connection = false, accepted = false;
    while (line < end)
    {
        const char *newline = memchr(line, '\n', (size_t)(end - line));
        if (!newline || newline == line || newline[-1] != '\r')
        {
            return false;
        }
        const char *line_end = newline - 1;
        if (line_end == line)
        {
            return !first && newline + 1 == end && upgrade && connection && accepted;
        }
        if (first)
        {
            first = false;
            line = newline + 1;
            continue;
        }
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (!colon || colon == line || *line == ' ' || *line == '\t')
        {
            return false;
        }
        const char *value = colon + 1;
        while (value < line_end && (*value == ' ' || *value == '\t'))
        {
            ++value;
        }
        while (line_end > value && (line_end[-1] == ' ' || line_end[-1] == '\t'))
        {
            --line_end;
        }
        size_t name_length = (size_t)(colon - line);
        if (name_length == 7 && !strncasecmp(line, "Upgrade", 7))
        {
            upgrade = upgrade || ws_header_token(value, line_end, "websocket");
        }
        else if (name_length == 10 && !strncasecmp(line, "Connection", 10))
        {
            connection = connection || ws_header_token(value, line_end, "upgrade");
        }
        else if (name_length == 20 && !strncasecmp(line, "Sec-WebSocket-Accept", 20))
        {
            if (accepted || (size_t)(line_end - value) != strlen(accept)
                || memcmp(value, accept, strlen(accept)))
            {
                return false;
            }
            accepted = true;
        }
        line = newline + 1;
    }
    return false;
}
