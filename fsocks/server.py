#!/usr/bin/env python3
import socket
from threading import Thread
from fsocks import logger, config
from fsocks.net import pipe, SocketError, Stream
from fsocks.socks import CMD, VERSION, ATYPE, REP,\
    Message, ProxyError
from fsocks.cipher import ALL_CIPHERS


def handle_conn(client):
    try:
        req = Message.from_stream(client)
    except (ProxyError, SocketError) as e:
        logger.warn('Invalid message: {}'.format(e))
        client.close()
        return
    logger.info(req)
    remotefd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote = Stream(remotefd)
    if req.msg is CMD.CONNECT:
        logger.info('connecting to {}:{}'.format(req.addr[0], req.addr[1]))
        try:
            remote.connect(req.addr)
        except SocketError as e:
            logger.warn('{}:{} {}'.format(req.addr[0], req.addr[1], e))
            remote.close()
            client.close()
            return
        bind_address = remote.sock.getsockname()
        reply = Message(
            ver=VERSION.SOCKS5,
            msg=REP.SUCCEEDED,
            atype=ATYPE.IPV4,
            addr=bind_address)
        try:
            reply.to_stream(client)
            # request done, piping stream data
            cipher = ALL_CIPHERS[0x01]()
            pipe(remote, client, cipher)
        except SocketError as e:
            logger.info(e)
    else:
        logger.error('not handled command')
    remote.close()
    client.close()


def main():
    config.load_args()
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind(config.server_address)
    serverfd.listen(5)
    logger.info('Server started on {}:{}'.format(
        config.server_host, config.server_port))
    while True:
        clientfd, addr = serverfd.accept()
        # no greetings, handle CONNECT command
        client = Stream(clientfd)
        t = Thread(target=handle_conn, args=(client,))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
