#!/usr/bin/env python3


class SocketError(Exception):
    pass


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
