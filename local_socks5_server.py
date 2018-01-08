#!/usr/bin/env python3
import socket
import select
from threading import Thread
from fsocks import logger
from fsocks.socks import CMD, VERSION, ATYPE, REP,\
        Message, ClientGreeting, ServerGreeting
from fsocks.net import send_all


def handle_conn(clientfd):
    req = Message.from_sock(clientfd)
    logger.info(req)
    if req.msg is CMD.CONNECT:
        remotefd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remotefd.connect(req.addr)
        except (ConnectionRefusedError, TimeoutError) as e:
            logger.warn('{}:{} {}'.format(req.addr[0], req.addr[1], e))
            return
        logger.info('connected to {}:{}'.format(req.addr[0], req.addr[1]))
        bind_address = remotefd.getsockname()
        reply = Message(
                ver=VERSION.SOCKS5,
                msg=REP.SUCCEEDED,
                atype=ATYPE.IPV4,
                addr=bind_address)
        reply.to_sock(clientfd)
        # now forwarding data
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
                send_all(remotefd, data)
            if remotefd in rlist:
                data = remotefd.recv(4096)
                if len(data) == 0:
                    break
                send_all(clientfd, data)
        remotefd.close()
        clientfd.close()
    else:
        logger.error('not handled')
    logger.info('handle done')


def main():
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind(('127.0.0.1', 1080))
    serverfd.listen(5)
    logger.info('Server started')
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
