/* SPDX-License-Identifier: MIT
 * Emulation address only. This is not a camera memory allocation.
 */
ENTRY(g9_build_probe)
SECTIONS
{
    . = 0x00010000;
    .text : { KEEP(*(.text.g9_build_probe)) *(.text*) *(.rodata*) }
    .data : { *(.data*) }
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    /DISCARD/ : { *(.comment) *(.ARM.exidx*) *(.ARM.extab*) }
}
ASSERT(SIZEOF(.data) == 0, "probe must not require initialized data")
ASSERT(SIZEOF(.bss) == 0, "probe must not require zero-initialized data")
