#!/usr/bin/env python3
import sys
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
    if len(sys.argv) != 2:
        print('Usage {} [host:]port'.format(sys.argv[0]))
        sys.exit(1)
    hp = sys.argv[1].rsplit(':', 1)
    if len(hp) == 2:
        host = hp[0]
        port = int(hp[1])
    else:
        host = '0.0.0.0'
        port = int(hp[0])
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind((host, port))
    serverfd.listen(5)
    logger.info('Server started on {}:{}'.format(host, port))
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
