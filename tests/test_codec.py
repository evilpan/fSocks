#!/usr/bin/env python3
from fsocks.cipher.codec import Base16, Base32, Base64, Base85,\
    AtBash
from .test_cipher import TestCipher


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
