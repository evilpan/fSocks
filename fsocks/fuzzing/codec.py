import base64
from .base import BaseCipher


__all__ = ['Plain', 'Base64', 'Base32', 'Base16',
           'Base85', 'XXencode', 'UUencode', 'AtBash']


class CodecCipher(BaseCipher):
    """
    CodecCipher is not really a cipher
    It just do some fuzzing
    """

    def __init__(self):
        self.key = b''

    def encode(self, data):
        pass

    def decode(self, data):
        pass

    def encrypt(self, data):
        return self.encode(data)

    def decrypt(self, data):
        return self.decode(data)


class Plain(CodecCipher):
    def encode(self, data):
        return data

    def decode(self, data):
        return data


class Base64(CodecCipher):
    def encode(self, data):
        return base64.b64encode(data)

    def decode(self, data):
        return base64.b64decode(data)


class Base32(CodecCipher):
    def encode(self, data):
        return base64.b32encode(data)

    def decode(self, data):
        return base64.b32decode(data)


class Base16(CodecCipher):
    def encode(self, data):
        return base64.b16encode(data)

    def decode(self, data):
        return base64.b16decode(data)


class Base85(CodecCipher):
    def encode(self, data):
        return base64.b85encode(data)

    def decode(self, data):
        return base64.b85decode(data)


def byte2bit(value):
    return bin(value)[2:].zfill(8)


def bit2byte(bits):
    return int(bits, base=2)


class XXencode(CodecCipher):
    """XXencode"""
    table = bytearray(b'+-0123456789'
                      b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                      b'abcdefghijklmnopqrstuvwxyz')

    def encode(self, data):
        data = bytearray(data)
        result = bytearray()
        remains = len(data) % 3
        paddings = 0 if not remains else 3 - remains
        for _ in range(paddings):
            data.append(0)
        for i in range(0, len(data), 3):
            bits = ''
            for j in range(3):
                bits += byte2bit(data[i + j])
            assert len(bits) == 24
            for k in range(0, 24, 6):
                nb = bit2byte(bits[k: k + 6])
                result.append(self.table[nb])
        return bytes(result)

    def decode(self, data):
        data = bytearray(data)
        result = bytearray()
        bits = ''
        for b in data:
            nb = self.table.find(b)
            bits += byte2bit(nb)[2:]
        assert len(bits) % 8 == 0
        for i in range(0, len(bits), 8):
            result.append(bit2byte(bits[i: i + 8]))
        # how to correctly strip the padded zeros?
        return bytes(result)


class UUencode(XXencode):
    table = bytearray(range(32, 96))


class AtBash(CodecCipher):

    def encode(self, data):
        result = bytearray()
        for b in data:
            result.append(abs(0xFF - b))
        return bytes(result)

    def decode(self, data):
        return self.encrypt(data)
