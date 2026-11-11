/* SPDX-License-Identifier: MIT
 * Pure integer compiler control. No camera entry point, hooks or I/O.
 * Return the magnitude of a signed 32-bit bit pattern as an unsigned value.
 * The most-negative input remains 0x80000000, without C signed overflow.
 */
_Static_assert(sizeof(unsigned int) == 4, "32-bit unsigned int required");

unsigned int g9_build_probe(unsigned int value)
{
    unsigned int sign_mask = 0u - (value >> 31);
    return (value ^ sign_mask) - sign_mask;
}
