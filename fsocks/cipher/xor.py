#!/usr/bin/env python3
from .base import BaseCipher


class XOR(BaseCipher):

    def __init__(self, key: int):
        self.key = key

    def xor_codec(self, data):
        source = bytearray(data)
        result = bytearray()
        for b in source:
            b = b ^ self.key
            result.append(b)
        result = bytes(result)
        assert len(data) == len(result)
        return result

    def do_encrypt(self, data):
        return self.xor_codec(data)

    def do_decrypt(self, data):
        return self.xor_codec(data)
