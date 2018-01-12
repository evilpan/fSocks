#!/usr/bin/env python3
import time
from unittest import TestCase
from fsocks.cipher.integer_key import XOR, RailFence


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
    def test_basic(self):
        ciphers = XOR(0x26), XOR(0x7f), XOR(0x00), XOR(-1), XOR(0x777)
        for c in ciphers:
            self._do_test_cipher(c)

    def test_corner(self):
        e1, e2 = XOR(-1), XOR(999)
        data = b'test'
        self.assertEqual(e1.encrypt(data), e2.encrypt(data))

    def test_bench(self):
        cipher = XOR(2)
        self._do_test_bench(cipher)


class TestRailFence(TestCipher):
    def test_basic(self):
        ciphers = RailFence(1), RailFence(2), RailFence(3),\
            RailFence(50), RailFence(0), RailFence(-1)
        for c in ciphers:
            self._do_test_cipher(c)

    def test_corner(self):
        text = b'hello'
        e = RailFence(0)
        for i in range(-10, 2):
            e.numrails = i
            self.assertEqual(text, e.encrypt(text))
        for i in range(len(text), len(text) + 5):
            e.numrails = i
            self.assertEqual(text, e.encrypt(text))

    def test_bench(self):
        cipher = RailFence(2)
        self._do_test_bench(cipher)
