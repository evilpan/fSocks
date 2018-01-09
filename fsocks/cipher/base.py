#!/usr/bin/env python3


class CipherError(Exception):
    pass


class BaseCipher:

    def encrypt(self, data: bytes, **kwargs):
        """
        :param data: input plain data
        :rtype: bytes
        """
        try:
            return self._do_encrypt(self, data, **kwargs)
        except (IndexError, ValueError) as e:
            raise CipherError(e.message)

    def decrypt(self, data: bytes, **kwargs):
        """
        :param data: input encrypted data
        :rtype: bytes
        """
        try:
            return self._do_decrypt(self, data, **kwargs)
        except (IndexError, ValueError) as e:
            raise CipherError(e.message)

    def _do_encrypt(self, data, **kwargs):
        pass

    def _do_decrypt(self, data, **kwargs):
        pass


class CodecCipher(BaseCipher):
    """
    CodecCipher is not really a cipher
    It just do some fuzzing
    """

    def encode(self, data):
        pass

    def decode(self, data):
        pass

    def _do_encrypt(self, data, **kwargs):
        return self.encode(data)

    def _do_decrypt(self, data, **kwargs):
        return self.decode(data)
