import time
import struct
from enum import Enum, unique
from .cipher import ALL_CIPHERS


@unique
class MTYPE(Enum):
    HELLO = 0x01
    HANDSHAKE = 0x02


class Greeting:

    def __init__(self):
        self.mtype = MTYPE.HELLO
        self.timestamp = int(time.time)

    def to_bytes(self):
        pass


class Handshake:

    def __init__(self, mtype, cipher, key):
        self.mtype = mtype
        self.cipher = cipher
        self.key = key
