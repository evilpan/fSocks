#!/usr/bin/env python3
import math
from random import randint
import struct
from .base import BaseFuzz, FuzzError

__all__ = ['XOR', 'RailFence']


class XOR(BaseFuzz):

    def __init__(self, key: bytes=None):
        if key is None:
            self.ikey = randint(0, 0xFF)
            self.key = struct.pack('!B', self.ikey)
        else:
            self.key = key
            try:
                self.ikey, = struct.unpack('!B', self.key)
            except struct.error:
                raise FuzzError

    def encrypt(self, data):
        return self.xor_codec(data)

    def decrypt(self, data):
        return self.xor_codec(data)

    def xor_codec(self, data):
        result = bytearray()
        for b in data:
            result.append(b ^ self.ikey)
        result = bytes(result)
        assert len(data) == len(result)
        return result


class RailFence(BaseFuzz):
    """ https://en.wikipedia.org/wiki/Rail_fence_cipher
    We don't strip the non-ASCII here
    """

    def __init__(self, key: bytes=None):
        # ikey = number of rails
        if key is None:
            self.ikey = randint(1, 10)
            self.key = struct.pack('!H', self.ikey)
        else:
            self.key = key
            self.ikey, = struct.unpack('!H', self.key)

    def encrypt(self, data):
        if not self.reasonable(data):
            return data
        return bytes(self.fence(data))

    def decrypt(self, data):
        if not self.reasonable(data):
            return data
        lst = range(len(data))
        pos = dict(((v, i) for i, v in enumerate(self.fence(lst))))
        return bytes((data[pos[n]] for n in lst))

    def reasonable(self, data):
        return 1 < self.ikey < len(data)

    def fence(self, lst):
        fence = [[None for _ in range(len(lst))] for _ in range(self.ikey)]
        rails = list(range(self.ikey - 1)) \
            + list(range(self.ikey - 1, 0, -1))
        for n, x in enumerate(lst):
            fence[rails[n % len(rails)]][n] = x
        return (c for rail in fence for c in rail if c is not None)
