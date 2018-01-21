#!/usr/bin/env python3
import select
import struct
import io
import asyncio
from .log import logger


class NetworkError(Exception):
    pass


class SockStream:
    """A thin wrapper for socket"""

    def __init__(self, sock, loop=None):
        self.sock = sock
        # self.loop = asyncio.get_event_loop() if loop is None else loop

    def connect(self, addr):
        try:
            return self.sock.connect(addr)
        except (ConnectionRefusedError,
                TimeoutError,
                OSError) as e:
            raise NetworkError(str(e))

    async def async_connect(self, addr):
        return await self.loop.sock_connect(addr)

    def read(self, nbytes, insist=True):
        if insist:
            return self.read_all(nbytes)
        # read some data
        try:
            read = self.sock.recv(nbytes)
        except (OSError,
                TimeoutError,
                ConnectionResetError) as e:
            raise NetworkError(str(e))
        if len(read) == 0:
            raise NetworkError('connection closed')
        return read

    def read_all(self, nbytes):
        read = b''
        left = nbytes
        while left > 0:
            data = self.sock.recv(left)
            n = len(data)
            if n == 0:
                raise NetworkError('connection closed')
            read += data
            left -= n
        return read

    async def async_read(self, nbytes, insist=True):
        if insist:
            return self.async_read_all(self, nbytes)
        data = await self.loop.sock_recv(self.sock, nbytes)
        return data

    async def async_read_all(self, nbytes):
        read = b''
        left = nbytes
        while left > 0:
            data = await self.loop.sock_recv(self.sock, left)
            n = len(data)
            if n == 0:
                raise NetworkError('connection closed')
            read += data
            left -= n
        return read

    def write(self, data, insist=True):
        if insist:
            return self.write_all(data)
        try:
            return self.sock.send(data)
        except (OSError,
                TimeoutError,
                ConnectionResetError) as e:
            raise NetworkError(str(e))

    def write_all(self, data):
        sent = 0
        while sent < len(data):
            n = self.write(data[sent:], insist=False)
            if n == 0:
                raise NetworkError('The buffer is full')
            if n < 0:
                raise NetworkError('internal error')
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
            elen = struct.unpack('!H', fuzz.read(2))[0]
            edata = fuzz.read(elen)
            plain.write_all(cipher.decrypt(edata))
