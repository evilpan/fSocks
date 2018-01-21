import traceback
import logging
import struct
from functools import reduce
from fsocks.log import logger


class FuzzError(ValueError):
    pass


class BaseFuzz:
    """ Every fuzz method have following rules:
    1. accept a bytes string as initial key
    2. if initial key is None, use a (suitable)random one
    3. fuzz.decrypt(fuzz.encrypt(data)) === data
    """

    def __init__(self, key: bytes=None):
        pass

    def encrypt(self, data: bytes):
        pass

    def decrypt(self, data: bytes):
        pass

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


class FuzzChain:

    def __init__(self, fuzz_list):
        self.fuzz_list = fuzz_list

    def encrypt(self, data):
        result = data
        for fuzz in self.fuzz_list:
            result = fuzz.encrypt(result)
        return result

    def decrypt(self, data):
        result = data
        for fuzz in reversed(self.fuzz_list):
            result = fuzz.decrypt(result)
        return result

    def to_bytes(self):
        result = b''
        for fuzz in self.fuzz_list:
            result += fuzz.to_bytes()
        return result

    def __str__(self):
        return '->'.join([c._name for c in self.fuzz_list])
