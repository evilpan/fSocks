#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from fsocks import config, logger


class BaseCryption:
    def __init__(self, password):
        self.password = password.encode()

    def encrypt(self, source: bytes):
        return source

    def decrypt(self, source: bytes):
        return source


class AES256CBC(BaseCryption):

    def __init__(self, password):
        super().__init__(password)
        # use SHA-256 over our key to get a proper-sized AES key
        self.key = SHA256.new(self.password).digest()
        self.mode = AES.MODE_CBC

    def encrypt(self, source: bytes):
        # generate IV
        IV = Random.new().read(AES.block_size)
        encryptor = AES.new(self.key, self.mode, IV)
        # calculate needed padding
        padding = AES.block_size - len(source) % AES.block_size
        # Python 2.x: source += chr(padding) * padding
        source += bytes([padding]) * padding
        # store the IV at the beginning and encrypt
        data = IV + encryptor.encrypt(source)
        return data

    def decrypt(self, source: bytes):
        # extract the IV from the beginning
        IV = source[:AES.block_size]
        decryptor = AES.new(self.key, self.mode, IV)
        # decrypt
        data = decryptor.decrypt(source[AES.block_size:])
        # pick the padding value from the end; Python 2.x: ord(data[-1])
        padding = data[-1]
        # Python 2.x: chr(padding) * padding
        if data[-padding:] != bytes([padding]) * padding:
            raise ValueError("Invalid padding...")
        # remove the padding
        return data[:-padding]
