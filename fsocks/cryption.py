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
        self.key = SHA256.new(self.password).digest()  # use SHA-256 over our key to get a proper-sized AES key
        self.mode = AES.MODE_CBC

    def encrypt(self, source: bytes):
        IV = Random.new().read(AES.block_size)  # generate IV
        encryptor = AES.new(self.key, self.mode, IV)
        padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
        source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
        data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
        return data

    def decrypt(self, source: bytes):
        IV = source[:AES.block_size]  # extract the IV from the beginning
        decryptor = AES.new(self.key, self.mode, IV)
        data = decryptor.decrypt(source[AES.block_size:])  # decrypt
        padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
        if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
            raise ValueError("Invalid padding...")
        return data[:-padding]  # remove the padding
