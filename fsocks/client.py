#!/usr/bin/env python3
import socket
from threading import Thread
from fsocks import logger, config
from fsocks.socks import Message, ClientGreeting, ServerGreeting, ProxyError
from fsocks.net import Stream, pipe, SocketError
from fsocks.cipher import ALL_CIPHERS


def handle_conn(user):
    try:
        req = Message.from_stream(user)
    except (ProxyError, SocketError) as e:
        logger.warn('UA: {}'.format(e))
        user.close()
        return
    logger.info(req)
    remotefd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remotefd.connect(config.server_address)
    server = Stream(remotefd)
    req.to_stream(server)
    response = Message.from_stream(server, request=False)
    # forward this reply to user
    response.to_stream(user)

    # request done, piping stream data
    cipher = ALL_CIPHERS[0x01]()
    pipe(user, server, cipher)
    server.close()
    user.close()


def main():
    config.load_args()
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind(config.client_address)
    serverfd.listen(5)
    logger.info('Local SOCKS5 server started on {}:{}'.format(
        config.client_host, config.client_port))
    while True:
        clientfd, addr = serverfd.accept()
        user = Stream(clientfd)
        client_greeting = ClientGreeting.from_stream(user)
        logger.debug('C {}:{} {}'.format(
            addr[0], addr[1], client_greeting))
        server_greeting = ServerGreeting()
        logger.debug('S {}'.format(server_greeting))
        server_greeting.to_stream(user)
        # greeting done, receiving CONNECT request from client
        t = Thread(target=handle_conn, args=(user,))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
