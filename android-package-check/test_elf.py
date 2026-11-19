import struct
import unittest
from elf_check import inspect


def fixture():
    data = bytearray(256)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 3, 183, 1)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, 256, 256, 16384)
    text = b'/system/bin/linker64\0'
    data[200:200+len(text)] = text
    struct.pack_into('<IIQQQQQQ', data, 120, 3, 4, 200, 200, 0, len(text), len(text), 1)
    return data


class Tests(unittest.TestCase):
    def test_good(self): inspect(fixture())
    def test_interpreter(self):
        data = fixture(); data[201] = ord('x')
        with self.assertRaises(ValueError): inspect(data)
        data = fixture(); struct.pack_into('<I', data, 120, 0)
        with self.assertRaises(ValueError): inspect(data)

    def test_reject(self):
        cases = []
        for offset, fmt, value in [(18,'H',62),(16,'H',2),(112,'Q',4096),(80,'Q',1),(96,'Q',9999),(56,'H',0),(32,'Q',99999)]:
            data = fixture(); struct.pack_into('<'+fmt, data, offset, value); cases.append(data)
        cases += [fixture()[:50], fixture()[:150], bytearray(256)]
        for data in cases:
            with self.subTest(data=data[:20]):
                with self.assertRaises(ValueError): inspect(data)


if __name__ == '__main__': unittest.main()
