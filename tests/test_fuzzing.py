#!/usr/bin/env python3
import time
import struct
from unittest import TestCase
from fsocks.fuzzing.base import FuzzError
from fsocks.fuzzing.symmetric import XOR, RailFence
from fsocks.fuzzing.codec import Base16, Base32, Base64, Base85,\
    AtBash, XXencode, UUencode


class TestCipher(TestCase):
    def _do_test_cipher(self, cipher):
        src = [
            b'hello, world',
            b'\x00hello, world',
            b'hello, world\x00',
            b'\x70hello, world\xff',
            b'\x00\xff',
            b'\xff',
            b'',
        ]
        for s in src:
            e = cipher.encrypt(s)
            self.assertEqual(s, cipher.decrypt(e))

    def _do_test_bench(self, cipher):
        text = b'HELLO' * 200
        for i in range(6):
            begin = time.time()
            et = cipher.encrypt(text)
            etime = time.time()
            dt = cipher.decrypt(et)
            dtime = time.time()
            self.assertEqual(dt, text)
            print('{} {} bytes: {:.2f}ms/{:.2f}ms/{:.2f}ms'.format(
                cipher.__class__.__name__, len(text),
                1000 * (etime - begin),
                1000 * (dtime - etime),
                1000 * (dtime - begin)))
            text += text


class TestXOR(TestCipher):
    def get_cipher(self, ikey):
        return XOR(struct.pack('!B', ikey))

    def test_basic(self):
        for i in 0x26, 0x7f, 0x00:
            cipher = self.get_cipher(i)
            self._do_test_cipher(cipher)

    def test_corner(self):
        self.assertRaises(FuzzError, XOR, b'\x00\x01')
        self.assertRaises(FuzzError, XOR, b'\xff\xff')
        self.assertRaises(TypeError, XOR, [])

    def test_bench(self):
        cipher = self.get_cipher(2)
        self._do_test_bench(cipher)


class TestRailFence(TestCipher):
    def get_cipher(self, ikey):
        return RailFence(struct.pack('!H', ikey))

    def test_basic(self):
        ciphers = self.get_cipher(1), self.get_cipher(2), self.get_cipher(3),\
            self.get_cipher(50), self.get_cipher(0)
        for c in ciphers:
            self._do_test_cipher(c)

    def test_corner(self):
        self.assertRaises(TypeError, RailFence, [])
        self.assertRaises(TypeError, RailFence, 'string')
        text = b'hello'
        for i in range(0, 2):
            e = self.get_cipher(i)
            self.assertEqual(text, e.encrypt(text))
        for i in range(len(text), len(text) + 5):
            e = self.get_cipher(i)
            self.assertEqual(text, e.encrypt(text))

    def test_bench(self):
        cipher = self.get_cipher(2)
        self._do_test_bench(cipher)


class TestBaseXX(TestCipher):
    def test_basic(self):
        ciphers = Base16(), Base32(), Base64(), Base85()
        for c in ciphers:
            self._do_test_cipher(c)

    def test_bench(self):
        ciphers = Base16(), Base32(), Base64(), Base85()
        for c in ciphers:
            self._do_test_bench(c)


class TestAtBash(TestCipher):
    def test_basic(self):
        self._do_test_cipher(AtBash())

    def test_bench(self):
        self._do_test_bench(AtBash())


class TestXXEncode(TestCipher):
    def test_basic(self):
        self._do_test_cipher(XXencode())
        self._do_test_cipher(UUencode())
    def test_bench(self):
        self._do_test_bench(XXencode())
        self._do_test_bench(UUencode())
