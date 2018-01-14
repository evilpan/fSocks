import struct
import inspect
from random import randint
from time import time
from enum import Enum, unique
from functools import wraps
from . import logger, fuzzing


MAGIC = 0x1986


class ProtocolError(Exception):
    pass


def safe_process(func):
    @wraps(func)
    def func_wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
        except struct.error as e:
            raise ProtocolError(str(e))
        return result
    return func_wrapper


def all_ciphers():
    clist = []
    for name, obj in inspect.getmembers(fuzzing):
        if name != 'CipherChain' and inspect.isclass(obj):
            clist.append(obj())
    return clist

@unique
class ENCTYPE(Enum):
    ENCRYPT = 0x01
    FUZZING = 0x02


@unique
class MTYPE(Enum):
    HELLO = 0x01
    HANDSHAKE = 0x02
    REQUEST = 0x03
    REPLY = 0x04
    RELAYING = 0x05
    CLOSE = 0x06


class Message:
    def __init__(self, mtype):
        self.magic = MAGIC
        self.mtype = mtype


class Hello(Message):
    def __init__(self, nonce=None, timestamp=None):
        super().__init__(MTYPE.HELLO)
        self.nonce = nonce or randint(0, 0xFFFF)
        self.timestamp = timestamp or int(time())

    @classmethod
    @safe_process
    def from_stream(cls, s):
        magic, mtype, nonce, timestamp = struct.unpack(
            '!HBIQ', s.read(2+1+4+8))
        if magic != MAGIC:
            raise ProtocolError('HELLO magic error')
        if mtype != MTYPE.HELLO.value:
            raise ProtocolError('MTYPE error')
        return cls(nonce, timestamp)

    @safe_process
    def to_bytes(self):
        return struct.pack('!HBIQ', self.magic,
                           self.mtype.value,
                           self.nonce, self.timestamp)

    def __str__(self):
        return '<{} {} {}>'.format(
            self.mtype.name, hex(self.nonce), self.timestamp)


class HandShake(Message):
    def __init__(self, nonce=None, timestamp=None, cipher=None):
        super().__init__(MTYPE.HANDSHAKE)
        self.nonce = nonce or randint(0, 0xFFFF)
        self.timestamp = timestamp or int(time())
        if cipher is None:
            self.cipher = fuzzing.CipherChain(all_ciphers())
        elif isinstance(cipher, fuzzing.CipherChain):
            self.cipher = cipher
        else:
            raise ProtocolError('Cipher must be contained in chain')

    @classmethod
    @safe_process
    def from_stream(cls, s):
        magic, mtype, nonce, timestamp = struct.unpack(
            '!HBIQ', s.read(2+1+4+8))
        if magic != MAGIC:
            raise ProtocolError('HELLO magic error')
        if mtype != MTYPE.HANDSHAKE.value:
            raise ProtocolError('MTYPE error')
        cipher_list = []
        while True:
            name_len, = struct.unpack('!B', s.read(1))
            if name_len == 0:
                break
            name, key_len = struct.unpack('!{}sB'.format(name_len),
                                          s.read(name_len + 1))
            cipher_cls = getattr(fuzzing, name.decode(), None)
            if cipher_cls is None:
                raise ProtocolError('No cipher named {}'.format(name))
            if key_len == 0:
                cipher_list.append(cipher_cls())
            else:
                key, = struct.unpack('!{}s'.format(key_len), s.read(key_len))
                cipher_list.append(cipher_cls(key))
        logger.debug('Received {} ciphers'.format(len(cipher_list)))
        if len(cipher_list) == 0:
            raise ProtocolError('No cipher available')
        return cls(nonce, timestamp, fuzzing.CipherChain(cipher_list))

    @safe_process
    def to_bytes(self):
        result = struct.pack('!HBIQ', self.magic,
                             self.mtype.value,
                             self.nonce, self.timestamp)
        result += self.cipher.to_bytes() + struct.pack('!B', 0) # end-of-ciphers
        return result

    def __str__(self):
        return '<HandShake {}>'.format(self.cipher)
