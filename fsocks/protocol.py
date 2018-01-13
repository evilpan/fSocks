import time
import struct
from enum import Enum, unique
from .cipher import ALL_CIPHERS


@unique
class MTYPE(Enum):
    HELLO = 0x01
    HANDSHAKE = 0x02
    REQUEST = 0x03
    REPLY = 0x04
    RELAYING = 0x05
    CLOSE = 0x06
