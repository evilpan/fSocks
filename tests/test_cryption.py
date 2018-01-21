#!/usr/bin/env python3
from unittest import TestCase
from fsocks.cryption import AES256CBC


class TestAES(TestCase):
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

    def test_basic(self):
        cipher = AES256CBC('my_password')
        self._do_test_cipher(cipher)
