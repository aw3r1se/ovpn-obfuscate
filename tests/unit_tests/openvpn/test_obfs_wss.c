/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syshead.h"
#include <setjmp.h>
#include <cmocka.h>
#include "wss_frame.h"

static void
test_ws_vectors(void **unused)
{
    (void)unused;
    struct buffer frame = alloc_buf(400);
    uint8_t mask[] = { 0x37, 0xfa, 0x21, 0x3d };
    const uint8_t expected[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    assert_true(obfs_ws_encode((const uint8_t *)"Hello", 5, 1, mask, &frame));
    assert_int_equal(BLEN(&frame), sizeof(expected));
    assert_memory_equal(BPTR(&frame), expected, sizeof(expected));
    uint8_t data[300] = { 0 };
    assert_true(obfs_ws_encode(data, sizeof(data), 2, mask, &frame));
    const uint8_t header[] = { 0x82, 0xfe, 0x2c, 0x01 };
    assert_memory_equal(BPTR(&frame), header, sizeof(header));
    size_t len;
    unsigned int opcode;
    uint8_t inbound[] = { 0x82, 0x7e, 0x2c, 0x01 };
    assert_int_equal(obfs_ws_header(inbound, 3, 1500, &len, &opcode), 0);
    assert_int_equal(obfs_ws_header(inbound, 4, 1500, &len, &opcode), 4);
    assert_int_equal(len, 300);
    assert_int_equal(opcode, 2);
    inbound[1] |= 0x80;
    assert_int_equal(obfs_ws_header(inbound, 4, 1500, &len, &opcode), -1);
    uint8_t reserved[] = { 0xc2, 0 };
    assert_int_equal(obfs_ws_header(reserved, 2, 1500, &len, &opcode), -1);
    reserved[0] = 0x83;
    assert_int_equal(obfs_ws_header(reserved, 2, 1500, &len, &opcode), -1);
    assert_true(obfs_ws_encode(NULL, 0, 10, mask, &frame));
    free_buf(&frame);
}

static void
test_ws_upgrade(void **unused)
{
    (void)unused;
    const char *accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    const char *valid = "HTTP/1.1 101 Switching Protocols\r\n"
                        "uPgRaDe: WebSocket\r\nConnection: keep-alive, Upgrade\r\n"
                        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_true(obfs_ws_upgrade_response(valid, strlen(valid), accept));
    const char *missing = "HTTP/1.1 101 Switching Protocols\r\n"
                          "X-Debug: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_false(obfs_ws_upgrade_response(missing, strlen(missing), accept));
    const char *wrong = "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: wrong\r\n"
                        "X-Debug: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_false(obfs_ws_upgrade_response(wrong, strlen(wrong), accept));
    const char *duplicate = "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_false(obfs_ws_upgrade_response(duplicate, strlen(duplicate), accept));
    assert_false(obfs_ws_upgrade_response(valid, strlen(valid) - 1, accept));
    assert_false(obfs_ws_upgrade_response(valid, strlen(valid), ""));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ws_vectors),
        cmocka_unit_test(test_ws_upgrade),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
