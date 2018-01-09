#!/usr/bin/env python3
import socket
import select
from threading import Thread
from fsocks import logger, config
from fsocks.socks import Message, ClientGreeting, ServerGreeting, ProxyError
from fsocks.net import send_all
from fsocks.crypto import encrypt, decrypt


def handle_conn(clientfd):
    try:
        req = Message.from_sock(clientfd)
    except ProxyError as e:
        logger.warn(e)
        clientfd.close()
        return
    logger.info(req)
    remotefd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remotefd.connect(config.server_address)
    req.to_sock(remotefd, wrapper=encrypt)
    # piping clientfd and remotefd with crypto
    rdset = [clientfd, remotefd]
    while True:
        rlist, _, _ = select.select(rdset, [], [])
        if clientfd in rlist:
            try:
                data = clientfd.recv(4096)
            except ConnectionResetError as e:
                logger.warn(str(e))
                break
            if len(data) == 0:
                break
            send_all(remotefd, encrypt(data))
        if remotefd in rlist:
            data = remotefd.recv(4096)
            if len(data) == 0:
                break
            send_all(clientfd, decrypt(data))
    remotefd.close()
    clientfd.close()


def main():
    config.load_args()
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind(config.client_address)
    serverfd.listen(5)
    logger.info('Local SOCKS5 server started on {}:{}'.format(
        config.client_host, config.client_port))
    while True:
        clientfd, addr = serverfd.accept()
        client_greeting = ClientGreeting.from_sock(clientfd)
        logger.debug('C {}:{} {}'.format(
            addr[0], addr[1], client_greeting))
        server_greeting = ServerGreeting()
        logger.debug('S {}'.format(server_greeting))
        server_greeting.to_sock(clientfd)
        t = Thread(target=handle_conn, args=(clientfd,))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
