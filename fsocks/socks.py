#!/usr/bin/env python3
import struct
import ipaddress
from enum import Enum, unique
from fsocks.net import recv_all, send_all


class ProxyError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@unique
class VERSION(Enum):
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


class Packet:
    """ Interface """

    @classmethod
    def from_sock(cls, sock, wrapper=lambda x: x, **kwargs):
        pass

    def to_bytes(self):
        pass

    def to_sock(self, sock, wrapper=lambda x: x):
        return send_all(sock, wrapper(self.to_bytes()))


class Message(Packet):
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
    rsv = 0x00

    def __init__(self, ver, msg, atype, addr):
        self.ver = ver
        self.msg = msg
        self.atype = atype
        self.addr = addr

    @property
    def is_request(self):
        return self.msg in CMD

    @classmethod
    def from_sock(cls, sock, wrapper=lambda x: x, request=True):
        data = wrapper(recv_all(sock, 4))
        ver, msg, rsv, atype = struct.unpack('!4B', data)
        if rsv != cls.rsv:
            raise ProxyError(
                    REP.GENERAL_SOCKS_SERVER_FAILURE,
                    'invalid RSV {}'.format(rsv))
        try:
            ver = VERSION(ver)
            msg = CMD(msg) if request else REP(msg)
            atype = ATYPE(atype)
        except ValueError as e:
            raise ProxyError(
                    REP.GENERAL_SOCKS_SERVER_FAILURE,
                    e.message)
        if atype is ATYPE.DOMAINNAME:
            alen = struct.unpack('!B', wrapper(recv_all(sock, 1)))[0]
            address = wrapper(recv_all(sock, alen)).decode()
        elif atype is ATYPE.IPV4:
            address = ipaddress.IPv4Address(
                    wrapper(recv_all(sock, 4))).compressed
        elif atype is ATYPE.IPV6:
            address = ipaddress.IPv6Address(
                    wrapper(recv_all(sock, 16))).compressed
        port = struct.unpack('!H', wrapper(recv_all(sock, 2)))[0]
        return cls(ver, msg, atype,
                   (address, port))

    def to_bytes(self):
        data = struct.pack('!4B', self.ver.value, self.msg.value,
                           self.rsv, self.atype.value)
        if self.atype is ATYPE.DOMAINNAME:
            addrlen = len(self.addr)
            data += struct.pack('!B{}s', addrlen, self.addr)
        elif self.atype is ATYPE.IPV4:
            data += ipaddress.IPv4Address(self.addr[0]).packed
        elif self.atype is ATYPE.IPV6:
            data += ipaddress.IPv6Address(self.addr[0]).packed
        data += struct.pack('!H', self.addr[1])
        return data

    def __str__(self):
        return '<{} {} {} {}:{}>'.format(
                self.ver.name, self.msg.name,
                self.atype.name,
                self.addr[0], self.addr[1])


class ClientGreeting(Packet):

    def __init__(self, ver, nmethods, methods):
        self.ver = ver
        self.nmethods = nmethods
        self.methods = methods

    @classmethod
    def from_sock(cls, sock, wrapper=lambda x: x):
        ver, nmethods = struct.unpack('!BB', wrapper(recv_all(sock, 2)))
        methods = struct.unpack('!{}B'.format(nmethods),
                                wrapper(recv_all(sock, nmethods)))
        ver = VERSION(ver)
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


class ServerGreeting(Packet):

    def __init__(self, ver=VERSION.SOCKS5,
                 method=METHOD.NO_AUTHENTICATION_REQUIRED):
        self.ver = ver
        self.method = method

    @classmethod
    def from_sock(cls, sock, wrapper=lambda x: x):
        ver, method = struct.unpack('!BB', wrapper(recv_all(sock, 2)))
        ver = VERSION(ver)
        method = METHOD(method)
        return cls(ver, method)

    def to_bytes(self):
        return struct.pack('!BB', self.ver.value, self.method.value)

    def __str__(self):
        return '<{} {}>'.format(self.ver.name, self.method)
