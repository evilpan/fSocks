import traceback
import logging
import struct
from functools import reduce
from fsocks.log import logger


class CipherError(ValueError):
    pass


class BaseCipher:


    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, data: bytes):
        """
        :param data: input plain data
        :rtype: bytes
        """
        try:
            return self.do_encrypt(data)
        except (IndexError, ValueError) as e:
            raise CipherError('{}: {}'.format(data, e))
            if logger.level == logging.DEBUG:
                traceback.print_exc()

    def decrypt(self, data: bytes):
        """
        :param data: input encrypted data
        :rtype: bytes
        """
        try:
            return self.do_decrypt(data)
        except (IndexError, ValueError) as e:
            if logger.level == logging.DEBUG:
                traceback.print_exc()
            else:
                raise CipherError('{}: {}'.format(data, e))

    def do_encrypt(self, data):
        pass

    def do_decrypt(self, data):
        pass

    def name(self):
        return self.__class__.__name__

    def key(self):
        return getattr(self, 'key', b'')


class CipherChain(BaseCipher):

    def __init__(self, ciphers):
        self.ciphers = ciphers

    def do_encrypt(self, data):
        result = data
        for cipher in self.ciphers:
            result = cipher.encrypt(result)
        return result

    def do_decrypt(self, data):
        result = data
        for cipher in self.ciphers:
            result = cipher.decrypt(result)
        return result
