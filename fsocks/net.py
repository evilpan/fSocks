#!/usr/bin/env python3
import select
from .log import logger


class SocketError(Exception):
    pass


class Stream:
    """A thin wrapper for socket"""

    def __init__(self, sock):
        self.sock = sock

    def read(self, nbytes):
        return recv_all(self.sock, nbytes)

    def write(self, data):
        return send_all(self.sock, data)

    def close(self):
        return self.sock.close()


def pipe(plain, encrypted, cipher):
    """
    :param plain: Stream of peer send/recv plain text
    :param encrypted: Stream of peer send/recv encrypted text destination
    :param cipher: cipher object provides encrypt/decrypt method
    """
    pla, enc = plain.sock, encrypted.sock
    rdset = [pla, enc]
    while True:
        rlist, _, _ = select.select(rdset, [], [])
        if pla in rlist:
            try:
                data = pla.recv(4096)
            except ConnectionResetError as e:
                logger.warn(str(e))
                break
            if len(data) == 0:
                break
            send_all(enc, cipher.encrypt(data))
        if enc in rlist:
            data = enc.recv(4096)
            if len(data) == 0:
                break
            send_all(pla, cipher.decrypt(data))


def recv_all(fd, nbytes):
    read = b''
    left = nbytes
    while left > 0:
        data = fd.recv(left)
        n = len(data)
        if n == 0:
            raise SocketError('connection closed')
        elif n < 0:
            raise SocketError('interal error')
        read += data
        left -= n
    return read


def send_all(fd, data):
    sent = 0
    while sent < len(data):
        n = fd.send(data[sent:])
        if n == 0:
            print('sup?')
            continue
        if n < 0:
            raise SocketError('internal error')
        sent += n
    return sent
