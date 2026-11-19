"""Strict ELF64 little-endian ARM64 executable/PT_LOAD alignment gate."""
import struct
import sys
from pathlib import Path


def inspect(data):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('elf-ident')
    kind, machine, version = struct.unpack_from('<HHI', data, 16)
    if kind != 3 or machine != 183 or version != 1:
        raise ValueError('elf-target')  # PIE, AArch64, current version
    phoff = struct.unpack_from('<Q', data, 32)[0]
    ehsize, phsize, count = struct.unpack_from('<HHH', data, 52)
    if ehsize != 64 or phsize != 56 or not 0 < count < 1024 or phoff < 64:
        raise ValueError('elf-headers')
    if phoff + count * phsize > len(data):
        raise ValueError('elf-truncated')
    loads = 0
    interpreter = False
    for i in range(count):
        typ, flags, off, va, _, size, mem, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        if off + size > len(data):
            raise ValueError('elf-range')
        if typ == 3:
            if data[off:off+size] != b'/system/bin/linker64\0':
                raise ValueError('elf-interpreter')
            interpreter = True
        if typ == 1:
            loads += 1
            if size > mem or align < 16384 or align & (align - 1) or off % align != va % align:
                raise ValueError('elf-load-alignment')
    if not loads or not interpreter:
        raise ValueError('elf-missing-segments')


if __name__ == '__main__':
    try:
        inspect(Path(sys.argv[1]).read_bytes())
    except (ValueError, OSError, IndexError, struct.error):
        print('FAIL: android-final-elf', file=sys.stderr)
        sys.exit(1)
    print('PASS: android-final-elf')
