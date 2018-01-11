#!/usr/bin/env python3
import select
import struct
from .log import logger


class SocketError(Exception):
    pass


class Stream:
    """A thin wrapper for socket"""

    def __init__(self, sock):
        self.sock = sock

    def read(self, nbytes):
        return self.sock.recv(nbytes)

    def read_all(self, nbytes):
        read = b''
        left = nbytes
        while left > 0:
            data = self.read(left)
            n = len(data)
            if n == 0:
                raise SocketError('connection closed')
            elif n < 0:
                raise SocketError('interal error')
            read += data
            left -= n
        return read

    def write(self, data):
        return self.sock.send(data)

    def write_all(self, data):
        sent = 0
        while sent < len(data):
            n = self.write(data[sent:])
            if n == 0:
                print('sup?')
                continue
            if n < 0:
                raise SocketError('internal error')
            sent += n
        return sent

    def close(self):
        return self.sock.close()


def pipe(plain, fuzz, cipher):
    """
    :param plain: Stream of peer send/recv plain text
    :param fuzz: Stream of peer send/recv encrypted text destination
    :param cipher: cipher object provides encrypt/decrypt method
    Note that encrypt/decrypt itself is not stream based,
    so we add 2 bytes header indicating len(payload)
    before the encrypted payload
    """
    rdset = [plain.sock, fuzz.sock]
    while True:
        rlist, _, _ = select.select(rdset, [], [])
        if plain.sock in rlist:
            try:
                data = plain.sock.recv(4096)
            except ConnectionResetError as e:
                logger.warn(e)
                break
            if len(data) == 0:
                break
            edata = cipher.encrypt(data)
            fuzz.write_all(struct.pack('!H', len(edata)))
            fuzz.write_all(edata)
        if fuzz.sock in rlist:
            elen = struct.unpack('!H', fuzz.read_all(2))[0]
            edata = fuzz.read_all(elen)
            plain.write_all(cipher.decrypt(edata))
