

class CipherError(ValueError):
    pass


class BaseCipher:

    def encrypt(self, data: bytes):
        """
        :param data: input plain data
        :rtype: bytes
        """
        try:
            return self.do_encrypt(data)
        except (IndexError, ValueError) as e:
            raise CipherError('{}: {}'.format(data, e))

    def decrypt(self, data: bytes):
        """
        :param data: input encrypted data
        :rtype: bytes
        """
        try:
            return self.do_decrypt(data)
        except (IndexError, ValueError) as e:
            raise CipherError('{}: {}'.format(data, e))

    def do_encrypt(self, data):
        pass

    def do_decrypt(self, data):
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

    def do_encrypt(self, data):
        return self.encode(data)

    def do_decrypt(self, data):
        return self.decode(data)
