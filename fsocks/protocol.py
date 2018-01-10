from enum import Enum, unique
from .cipher import ALL_CIPHERS


@unique
class MTYPE(Enum):
    HELLO = 0x01
    HANDSHAKE = 0x02


class Greeting:

    def __init__(self, mtype, transaction, timestamp):
        self.mtype = mtype
        self.transaction = transaction
        self.timestamp = timestamp


class Handshake:

    def __init__(self, mtype, cipher, key):
        self.mtype = mtype
        self.cipher = cipher
        self.key = key
