import traceback
import logging
import struct
from functools import reduce
from fsocks.log import logger


class CipherError(ValueError):
    pass


class BaseCipher:


    def __init__(self, key: bytes=b''):
        self.key = key

    def encrypt(self, data):
        pass

    def decrypt(self, data):
        pass

    def safe_encrypt(self, data: bytes):
        """
        :param data: input plain data
        :rtype: bytes
        """
        try:
            return self.encrypt(data)
        except (IndexError, ValueError) as e:
            raise CipherError('{}: {}'.format(data, e))
            if logger.level == logging.DEBUG:
                traceback.print_exc()

    def safe_decrypt(self, data: bytes):
        """
        :param data: input encrypted data
        :rtype: bytes
        """
        try:
            return self.decrypt(data)
        except (IndexError, ValueError) as e:
            if logger.level == logging.DEBUG:
                traceback.print_exc()
            else:
                raise CipherError('{}: {}'.format(data, e))

    @property
    def _name(self):
        return self.__class__.__name__

    @property
    def _key(self):
        return getattr(self, 'key', b'')

    def to_bytes(self):
        name_len = len(self._name)
        key_len = len(self._key)
        return struct.pack('!B{}sB{}s'.format(name_len, key_len),
                           name_len, self._name.encode(),
                           key_len, self._key)


class CipherChain(BaseCipher):

    def __init__(self, cipher_list):
        self.cipher_list = cipher_list

    def encrypt(self, data):
        result = data
        for cipher in self.cipher_list:
            result = cipher.encrypt(result)
        return result

    def decrypt(self, data):
        result = data
        for cipher in self.cipher_list:
            result = cipher.decrypt(result)
        return result

    def to_bytes(self):
        result = b''
        for cipher in self.cipher_list:
            result += cipher.to_bytes()
        return result

    def __str__(self):
        return ','.join([c._name for c in self.cipher_list])
