#!/usr/bin/env python3
import struct
import ipaddress
from enum import Enum, unique


class SocksError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@unique
class VER(Enum):
    SOCKS4 = 0x04
    SOCKS5 = 0x05


@unique
class METHOD(Enum):
    NO_AUTHENTICATION_REQUIRED = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE_METHODS = 0xFF


@unique
class CMD(Enum):
    CONNECT = 0x01
    BIND = 0x02
    UDP = 0x03


@unique
class ATYPE(Enum):
    IPV4 = 0x01
    DOMAINNAME = 0x03
    IPV6 = 0x04


@unique
class REP(Enum):
    SUCCEEDED = 0x00
    GENERAL_SOCKS_SERVER_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Message:
    """SOCKS message
    Request:
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    Reply:
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    """
    RSV = 0x00

    def __init__(self, ver, code, atype, addr):
        self.ver = ver
        self.code = code
        self.atype = atype
        self.addr = addr

    @property
    def is_request(self):
        return self.code in CMD

    @classmethod
    def from_stream(cls, stream, request=True):
        ver, code, rsv, atype = struct.unpack('!4B', stream.read(4))
        if rsv != cls.RSV:
            raise SocksError(
                REP.GENERAL_SOCKS_SERVER_FAILURE,
                'invalid RSV {}'.format(rsv))
        try:
            ver = VER(ver)
            code = CMD(code) if request else REP(code)
            atype = ATYPE(atype)
        except ValueError as e:
            raise SocksError(
                REP.GENERAL_SOCKS_SERVER_FAILURE,
                str(e))
        if atype is ATYPE.DOMAINNAME:
            alen = struct.unpack('!B', stream.read(1))[0]
            host = stream.read(alen).decode()
        elif atype is ATYPE.IPV4:
            host = ipaddress.IPv4Address(stream.read(4)).compressed
        elif atype is ATYPE.IPV6:
            host = ipaddress.IPv6Address(stream.read(16)).compressed
        port = struct.unpack('!H', stream.read(2))[0]
        return cls(ver, code, atype, (host, port))

    def to_bytes(self):
        data = struct.pack('!4B', self.ver.value, self.code.value,
                           self.RSV, self.atype.value)
        if self.atype is ATYPE.DOMAINNAME:
            alen = len(self.addr[0].encode())
            data += struct.pack('!B{}s'.format(alen),
                                alen, self.addr[0].encode())
        elif self.atype is ATYPE.IPV4:
            data += ipaddress.IPv4Address(self.addr[0]).packed
        elif self.atype is ATYPE.IPV6:
            data += ipaddress.IPv6Address(self.addr[0]).packed
        data += struct.pack('!H', self.addr[1])
        return data

    def __str__(self):
        return '<{} {} {} {}:{}>'.format(
            self.ver.name, self.code.name,
            self.atype.name,
            self.addr[0], self.addr[1])


class ClientGreeting:

    def __init__(self, ver, nmethods, methods):
        self.ver = ver
        self.nmethods = nmethods
        self.methods = methods

    @classmethod
    def from_stream(cls, stream):
        ver, nmethods = struct.unpack('!BB', stream.read(2))
        methods = struct.unpack('!{}B'.format(nmethods),
                                stream.read(nmethods))
        ver = VER(ver)
        methods = list(map(METHOD, methods))
        return cls(ver, nmethods, methods)

    def to_bytes(self):
        assert self.nmethods == len(self.methods)
        data = struct.pack('!BB', self.ver.value, self.nmethods)
        for method in self.methods:
            data += struct.pack('!B', method.value)
        return data

    def __str__(self):
        return '<{} {}:{}>'.format(self.ver.name, self.nmethods,
                                   [m.name for m in self.methods])


class ServerGreeting:

    def __init__(self, ver=VER.SOCKS5,
                 method=METHOD.NO_AUTHENTICATION_REQUIRED):
        self.ver = ver
        self.method = method

    @classmethod
    def from_stream(cls, stream):
        ver, method = struct.unpack('!BB', stream.read(2))
        ver = VER(ver)
        method = METHOD(method)
        return cls(ver, method)

    def to_bytes(self):
        return struct.pack('!BB', self.ver.value, self.method.value)

    def __str__(self):
        return '<{} {}>'.format(self.ver.name, self.method.name)
