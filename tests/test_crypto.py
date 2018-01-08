#!/usr/bin/env python3

from unittest import TestCase
from fsocks import crypto


class TestXor(TestCase):
    def test_codec(self):
        origin = b'hello, world'
        encodeded = crypto.encrypt(origin)
        self.assertEqual(origin, crypto.decrypt(encodeded))
