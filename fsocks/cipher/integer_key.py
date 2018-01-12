#!/usr/bin/env python3
import math
from .base import BaseCipher


class XOR(BaseCipher):

    def __init__(self, key: int):
        self.key = key

    def do_encrypt(self, data):
        return self.xor_codec(data)

    def do_decrypt(self, data):
        return self.xor_codec(data)

    def xor_codec(self, data):
        result = bytearray()
        key = self.key if 0 <= self.key <= 0xFF else 0x26
        for b in data:
            result.append(b ^ key)
        result = bytes(result)
        assert len(data) == len(result)
        return result


class RailFence(BaseCipher):
    """ https://en.wikipedia.org/wiki/Rail_fence_cipher
    We don't strip the non-ASCII here
    """

    def __init__(self, key: int):
        self.numrails = key

    def do_encrypt(self, data):
        if not self.reasonable(data):
            return data
        return bytes(self.fence(data))

    def do_decrypt(self, data):
        if not self.reasonable(data):
            return data
        lst = range(len(data))
        pos = dict(((v, i) for i, v in enumerate(self.fence(lst))))
        return bytes((data[pos[n]] for n in lst))

    def reasonable(self, data):
        return 1 < self.numrails < len(data)

    def fence(self, lst):
        fence = [[None for _ in range(len(lst))] for _ in range(self.numrails)]
        rails = list(range(self.numrails - 1)) \
            + list(range(self.numrails - 1, 0, -1))
        for n, x in enumerate(lst):
            fence[rails[n % len(rails)]][n] = x
        return (c for rail in fence for c in rail if c is not None)
