import io
import struct
from random import randint
from time import time
from enum import Enum, unique
from functools import wraps
from . import logger, fuzzing, socks


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


@safe_process
def read_packet(stream):
    etype, = struct.unpack('!H', stream.read(2))
    elen, = struct.unpack('!I', stream.read(4))
    edata = stream.read(elen)
    mtype = edata[2]
    mtype = MTYPE(mtype)
    # TODO: decrypt edata
    s = io.BytesIO(edata)
    if mtype is MTYPE.HELLO:
        return Hello.from_stream(s)
    elif mtype is MTYPE.HANDSHAKE:
        return HandShake.from_stream(s)
    elif mtype is MTYPE.REQUEST:
        return Request.from_stream(s)
    elif mtype is MTYPE.REPLY:
        return Reply.from_stream(s)
    elif mtype is MTYPE.RELAYING:
        return Relaying.from_stream(s)
    elif mtype is MTYPE.CLOSE:
        return Close.from_stream(s)
    else:
        return None


@safe_process
def form_packet(data, etype=0):
    return struct.pack('!HI', etype, len(data)) \
        + data

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

    def __init__(self, **kwargs):
        self.nonce = kwargs.pop('nonce', randint(0, 0xFFFF))

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

    def common_bytes(self):
        return struct.pack('!HBI', self.magic,
                           self.mtype.value, self.nonce)

    def to_packet(self):
        return form_packet(self.to_bytes(), etype=0)


class Hello(Message):
    mtype = MTYPE.HELLO

    def __init__(self, timestamp=None, **kwargs):
        self.timestamp = timestamp or int(time())
        super().__init__(**kwargs)

    @classmethod
    @safe_process
    def from_stream(cls, s):
        mtype, nonce = Message.read_common(s)
        timestamp, = struct.unpack('!Q', s.read(8))
        if mtype is not MTYPE.HELLO:
            raise ProtocolError('Not a Hello message')
        return cls(timestamp, nonce=nonce)

    @safe_process
    def to_bytes(self):
        return self.common_bytes() + \
            struct.pack('!Q', self.timestamp)

    def __str__(self):
        return '<{} {} {}>'.format(
            self.mtype.name, hex(self.nonce), self.timestamp)


class HandShake(Message):
    mtype = MTYPE.HANDSHAKE

    def __init__(self, cipher=None, timestamp=None, **kwargs):
        self.timestamp = timestamp or int(time())
        if cipher is None:
            self.cipher = fuzzing.CipherChain(fuzzing.cipher_list())
        elif isinstance(cipher, fuzzing.CipherChain):
            self.cipher = cipher
        else:
            raise ProtocolError('Cipher must be wrapped in chain')
        super().__init__(**kwargs)

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
        return cls(fuzzing.CipherChain(cipher_list), timestamp, nonce=nonce)

    @safe_process
    def to_bytes(self):
        result = self.common_bytes() + \
            struct.pack('!Q', self.timestamp)
        result += self.cipher.to_bytes() + struct.pack('!B', 0) # end-of-ciphers
        return result

    def __str__(self):
        return '<HandShake {}>'.format(self.cipher)


class _SocksWrapper(Message):
    mtype = None
    is_request = None

    def __init__(self, src, dst, msg, **kwargs):
        # set unknown dst to 0
        self.src = src
        self.dst = dst
        self.msg = msg
        super().__init__(**kwargs)

    @classmethod
    @safe_process
    def from_stream(cls, s):
        mtype, nonce = Message.read_common(s)
        if mtype is not cls.mtype:
            raise ProtocolError('Not a {} message'.format(cls.mtype.name))
        src, dst = struct.unpack('!II', s.read(8))
        msg = socks.Message.from_stream(s, request=cls.is_request)
        return cls(src, dst, msg, nonce=nonce)

    def to_bytes(self):
        return self.common_bytes() \
            + struct.pack('!II', self.src, self.dst) \
            + self.msg.to_bytes()

    def __str__(self):
        return '[{} {}]'.format(self.mtype.name, self.msg)


class Request(_SocksWrapper):
    mtype = MTYPE.REQUEST
    is_request = True


class Reply(_SocksWrapper):
    mtype = MTYPE.REPLY
    is_request = False


class Relaying(Message):
    mtype = MTYPE.RELAYING
    def __init__(self, src, dst, payload, **kwargs):
        self.src = src
        self.dst = dst
        self.payload = payload
        super().__init__(**kwargs)

    @classmethod
    @safe_process
    def from_stream(cls, s):
        mtype, nonce = Message.read_common(s)
        if mtype is not cls.mtype:
            raise ProtocolError('Not a Relay message')
        src, dst = struct.unpack('!II', s.read(8))
        payload = s.read() # all remaining
        return cls(src, dst, payload, nonce=nonce)

    def to_bytes(self):
        return self.common_bytes() \
            + struct.pack('!II', self.src, self.dst) \
            + self.payload


class Close(Message):
    mtype = MTYPE.CLOSE
    def __init__(self, src, **kwargs):
        self.src = src
        super().__init__(**kwargs)

    @classmethod
    @safe_process
    def from_stream(cls, s):
        mtype, nonce = Message.read_common(s)
        src, = struct.unpack('!I', s.read(4))
        return cls(src, nonce=nonce)

    def to_bytes(self):
        return self.common_bytes() + struct.pack('!I', self.src)
