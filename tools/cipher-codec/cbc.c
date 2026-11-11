/* SPDX-License-Identifier: MIT
 * Scalar AES-128 CBC encryption with 5 or 10 rounds; no padding.
 * Implements the round operations specified in FIPS 197. The five-round
 * variant is a firmware-format compatibility primitive, not secure encryption.
 * Reads stdin and writes stdout only; never opens firmware or device files.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static uint8_t sbox[256];

static uint8_t xtime(uint8_t a)
{
    return (uint8_t)((a << 1) ^ ((a & 128u) ? 0x1bu : 0u));
}

static uint8_t multiply(uint8_t a, uint8_t b)
{
    uint8_t out = 0;
    for (unsigned i = 0; i < 8; ++i) {
        if (b & 1u) out ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return out;
}

static uint8_t rotate(uint8_t a, unsigned n)
{
    return (uint8_t)((a << n) | (a >> (8u - n)));
}

static void make_sbox(void)
{
    for (unsigned a = 0; a < 256; ++a) {
        uint8_t inverse = a ? 1u : 0u;
        for (unsigned i = 0; i < 254; ++i) inverse = multiply(inverse, (uint8_t)a);
        sbox[a] = inverse ^ rotate(inverse, 1) ^ rotate(inverse, 2)
                  ^ rotate(inverse, 3) ^ rotate(inverse, 4) ^ 0x63u;
    }
}

static void expand_key(const uint8_t key[16], uint8_t keys[176], unsigned rounds)
{
    uint8_t rc = 1;
    memcpy(keys, key, 16);
    for (unsigned at = 16; at < 16u * (rounds + 1u); at += 4) {
        uint8_t t[4];
        memcpy(t, keys + at - 4, 4);
        if (at % 16u == 0) {
            uint8_t first = t[0];
            t[0] = sbox[t[1]] ^ rc;
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[first];
            rc = xtime(rc);
        }
        for (unsigned i = 0; i < 4; ++i) keys[at + i] = keys[at - 16 + i] ^ t[i];
    }
}

static void encrypt_block(uint8_t state[16], const uint8_t keys[176], unsigned rounds)
{
    for (unsigned i = 0; i < 16; ++i) state[i] ^= keys[i];
    for (unsigned round = 1; round <= rounds; ++round) {
        uint8_t shifted[16];
        for (unsigned column = 0; column < 4; ++column)
            for (unsigned row = 0; row < 4; ++row)
                shifted[4u * column + row] = sbox[state[4u * ((column + row) % 4u) + row]];
        memcpy(state, shifted, 16);
        if (round != rounds) {
            for (unsigned column = 0; column < 4; ++column) {
                uint8_t *p = state + 4u * column;
                uint8_t all = p[0] ^ p[1] ^ p[2] ^ p[3], first = p[0];
                p[0] ^= all ^ xtime(p[0] ^ p[1]);
                p[1] ^= all ^ xtime(p[1] ^ p[2]);
                p[2] ^= all ^ xtime(p[2] ^ p[3]);
                p[3] ^= all ^ xtime(p[3] ^ first);
            }
        }
        for (unsigned i = 0; i < 16; ++i) state[i] ^= keys[16u * round + i];
    }
}

static int unhex(const char *text, uint8_t out[16])
{
    if (strlen(text) != 32) return 0;
    for (unsigned i = 0; i < 16; ++i) {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; ++j) {
            unsigned c = (unsigned char)text[2u * i + j], digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10u;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10u;
            else return 0;
            value = value * 16u + digit;
        }
        out[i] = (uint8_t)value;
    }
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t key[16], previous[16], keys[176], buffer[65536];
    unsigned rounds;
    if (argc != 4 || !unhex(argv[1], key) || !unhex(argv[2], previous)
        || (strcmp(argv[3], "5") != 0 && strcmp(argv[3], "10") != 0)) {
        fputs("usage: g9-cbc KEY_HEX IV_HEX {5|10}; binary stdin/stdout; no padding\n", stderr);
        return 2;
    }
    rounds = (unsigned)strtoul(argv[3], NULL, 10);
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) {
        fputs("cannot select binary standard streams\n", stderr);
        return 3;
    }
#endif
    make_sbox();
    expand_key(key, keys, rounds);
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), stdin);
        if (ferror(stdin) || count % 16u != 0) {
            fputs("input read failure or non-block-aligned input\n", stderr);
            return 4;
        }
        for (size_t at = 0; at < count; at += 16) {
            for (unsigned i = 0; i < 16; ++i) buffer[at + i] ^= previous[i];
            encrypt_block(buffer + at, keys, rounds);
            memcpy(previous, buffer + at, 16);
        }
        if (fwrite(buffer, 1, count, stdout) != count) return 5;
        if (count < sizeof(buffer)) break;
    }
    if (fflush(stdout) == EOF) return 5;
    return 0;
}
