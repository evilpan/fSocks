import struct
import inspect
from random import randint
from time import time
from enum import Enum, unique
from functools import wraps
from . import logger, fuzzing


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
    magic = 0x1986
    mtype = None

    @staticmethod
    def read_common(stream):
        magic, mtype, nonce = struct.unpack(
            '!HBI', stream.read(2+1+4))
        if magic != Message.magic:
            raise ProtocolError('Invalid magic')
        try:
            mtype = MTYPE(mtype)
        except ValueError:
            raise ProtocolError('Invalid Mtype 0x%x' % mtype)
        return mtype, nonce


class Hello(Message):
    mtype = MTYPE.HELLO

    def __init__(self, nonce=None, timestamp=None):
        self.nonce = nonce or randint(0, 0xFFFF)
        self.timestamp = timestamp or int(time())

    @classmethod
    @safe_process
    def from_stream(cls, s):
        mtype, nonce = Message.read_common(s)
        timestamp, = struct.unpack('!Q', s.read(8))
        if mtype is not MTYPE.HELLO:
            raise ProtocolError('Not a Hello message')
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
    mtype = MTYPE.HANDSHAKE

    def __init__(self, nonce=None, timestamp=None, cipher=None):
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
        mtype, nonce = Message.read_common(s)
        timestamp, = struct.unpack('!Q', s.read(8))
        if mtype is not MTYPE.HANDSHAKE:
            raise ProtocolError('Not a HandShake message')
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


class Request(Message):
    def __init__(self, peer):
        self.peer = peer

    @staticmethod
    @safe_process
    def from_stream(cls, s):
        pass
