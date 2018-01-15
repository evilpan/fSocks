#!/usr/bin/env python3
import math
import struct
from .base import BaseCipher

__all__ = ['XOR', 'RailFence']


class IntKeyCipher(BaseCipher):
    """ class that accepts one int value as initial key """
    def __init__(self, key=0):
        if isinstance(key, int):
            self.ikey = key
            self.key = struct.pack('!I', abs(key))
        elif isinstance(key, bytes):
            self.key = key
            self.ikey, = struct.unpack('!I', key)
        else:
            raise ValueError('error type {} to initialize cipher'.format(
                self.__class__))


class XOR(IntKeyCipher):

    def encrypt(self, data):
        return self.xor_codec(data)

    def decrypt(self, data):
        return self.xor_codec(data)

    def xor_codec(self, data):
        result = bytearray()
        k = self.ikey if 0 <= self.ikey <= 0xFF else 0x26
        for b in data:
            result.append(b ^ k)
        result = bytes(result)
        assert len(data) == len(result)
        return result


class RailFence(IntKeyCipher):
    """ https://en.wikipedia.org/wiki/Rail_fence_cipher
    We don't strip the non-ASCII here
    """

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
