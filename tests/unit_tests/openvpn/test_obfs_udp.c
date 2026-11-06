/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syshead.h"
#include <setjmp.h>
#include <cmocka.h>
#include "obfs_udp.h"

static void
test_udp_roundtrip(void **unused)
{
    (void)unused;
    /* Different XTS halves within each direction, and reversed peer halves. */
    const char *key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const char *peer = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                       "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    struct obfs_udp *sender = obfs_udp_init(key, 32);
    struct obfs_udp *receiver = obfs_udp_init(peer, 32);
    assert_non_null(sender);
    assert_non_null(receiver);
    const unsigned int opcodes[] = { 6, 7, 9, 10 };
    for (size_t op = 0; op < 4; ++op)
    {
        for (int len = 16; len <= 1400; len += 17)
        {
            struct buffer b = alloc_buf(len + 64);
            uint8_t expected[1472];
            for (int i = 0; i < len; ++i)
            {
                expected[i] = (uint8_t)i;
            }
            expected[0] = (uint8_t)(opcodes[op] << 3);
            assert_true(buf_write(&b, expected, len));
            assert_true(obfs_udp_obfuscate(sender, &b));
            assert_true(obfs_udp_deobfuscate(receiver, &b));
            assert_int_equal(BLEN(&b), len);
            assert_memory_equal(BPTR(&b), expected, len);
            free_buf(&b);
        }
    }
    obfs_udp_free(sender);
    obfs_udp_free(receiver);
}

static void
test_udp_limits(void **unused)
{
    (void)unused;
    const char *key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    assert_null(obfs_udp_init(NULL, 32));
    char invalid[129];
    memset(invalid, '0', 128);
    invalid[1] = 'g';
    invalid[128] = 0;
    assert_null(obfs_udp_init(invalid, 32));
    struct obfs_udp *sender = obfs_udp_init(key, 0);
    assert_non_null(sender);
    struct buffer packet = alloc_buf(1600);
    uint8_t short_packet[31] = { 0x38 };
    assert_true(buf_write(&packet, short_packet, sizeof(short_packet)));
    assert_false(obfs_udp_obfuscate(sender, &packet));
    assert_int_equal(BLEN(&packet), sizeof(short_packet));
    assert_memory_equal(BPTR(&packet), short_packet, sizeof(short_packet));
    assert_false(obfs_udp_deobfuscate(sender, &packet));
    buf_reset_len(&packet);
    uint8_t oversized[1473] = { 0x38 };
    assert_true(buf_write(&packet, oversized, sizeof(oversized)));
    assert_false(obfs_udp_obfuscate(sender, &packet));
    assert_false(obfs_udp_deobfuscate(sender, &packet));
    free_buf(&packet);
    obfs_udp_free(sender);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_udp_roundtrip),
        cmocka_unit_test(test_udp_limits),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
