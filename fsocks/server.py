#!/usr/bin/env python3
import socket
from threading import Thread
from fsocks import logger, config
from fsocks.net import pipe, SocketError, Stream
from fsocks.socks import CMD, VERSION, ATYPE, REP,\
        Message, ProxyError
from fsocks.cipher import XOR, Plain, Base64


def handle_conn(client):
    try:
        req = Message.from_stream(client)
    except (ProxyError, SocketError) as e:
        logger.warn('Invalid message: {}'.format(e))
        client.close()
        return
    logger.info(req)
    if req.msg is CMD.CONNECT:
        remotefd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info('connecting to {}:{}'.format(req.addr[0], req.addr[1]))
        try:
            remotefd.connect(req.addr)
        except (ConnectionRefusedError, TimeoutError) as e:
            logger.warn('{}:{} {}'.format(req.addr[0], req.addr[1], e))
            return
        bind_address = remotefd.getsockname()
        reply = Message(
                ver=VERSION.SOCKS5,
                msg=REP.SUCCEEDED,
                atype=ATYPE.IPV4,
                addr=bind_address)
        remote = Stream(remotefd)
        reply.to_stream(client)

        # request done, piping stream data
        # cipher = XOR(0x26)
        cipher = Base64()
        pipe(remote, client, cipher)
        remote.close()
        client.close()
    else:
        logger.error('not handled')
    logger.info('handle done')


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
