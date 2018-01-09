#!/usr/bin/env python3

from unittest import TestCase
from fsocks.cipher import codec, xor


class TestXor(TestCase):
    def test_codec(self):
        e = xor.XOR(0x26)
        origin = b'hello, world'
        encodeded = e.encrypt(origin)
        self.assertEqual(origin, e.decrypt(encodeded))
