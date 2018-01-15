#!/usr/bin/env python3
import socket
from threading import Thread
from fsocks import logger, config, fuzzing, protocol, socks
from fsocks.socks import Message, ClientGreeting, ServerGreeting, SocksError
from fsocks.net import SockStream, pipe, NetworkError



fd_maps = {} # user_fd <--> remote_fd
user_dict = {} # user_fd -> user_stream
def get_user_by_remote(remotefd):
    for userfd in fd_maps:
        if fd_maps[userfd] == remotefd:
            return userfd
    return None

def delete_userfd(userfd):
    logger.debug('deleting {} from {}'.format(userfd, fd_maps))
    try:
        del fd_maps[userfd]
    except KeyError:
        logger.error('Fail to delete {}'.format(userfd))


def user_connect(user, server):
    try:
        req = Message.from_stream(user)
    except (SocksError, NetworkError) as e:
        logger.warn('UA: {}'.format(e))
        user.close()
        return
    logger.info(req)
    if req.code is not socks.CMD.CONNECT:
        logger.info('Unhandled cmd from user')
        user.close()
        return
    userfd = user.sock.fileno()
    # > REQUEST(CONNECT)
    connect_reqeust = protocol.Request(
        userfd, 0, req)
    server.write(connect_reqeust.to_packet())
    user_dict[userfd] = user


def user_loop(user, server):
    logger.debug('enter user_loop')
    userfd = user.sock.fileno()
    while True:
        try:
            data = user.read(2048, insist=False)
        except NetworkError as e:
            logger.debug(
                '[{}] tell server that user[{}] is closed'.format(e, userfd))
            packet = protocol.Close(userfd)
            server.write(packet.to_packet())
            delete_userfd(userfd)
            user.close()
            break
        # relay to server
        packet = protocol.Relaying(
            userfd, fd_maps[userfd],
            payload=data).to_packet()
        server.write(packet)
    logger.debug('exit user_loop')


def server_loop(server):
    logger.debug('enter server_loop')
    while True:
        try:
            packet = protocol.read_packet(server)
        except NetworkError:
            break
        if packet.mtype is protocol.MTYPE.REPLY:
            # < REPLY(CONNECT)
            remotefd = packet.src
            userfd = packet.dst
            user = user_dict[userfd]
            if packet.msg.code is socks.REP.SUCCEEDED:
                fd_maps[userfd] = remotefd
                logger.debug('Accepted new request, fd_maps:{}'.format(fd_maps))
            user_thread = Thread(target=user_loop, args=(user,server))
            user_thread.setDaemon(True)
            user_thread.start()
            user.write(packet.msg.to_bytes())
        elif packet.mtype is protocol.MTYPE.RELAYING:
            remotefd = packet.src
            userfd = packet.dst
            user = user_dict[userfd]
            try:
                user.write(packet.payload)
            except NetworkError:
                logger.warn('server_loop: user is closed')
        elif packet.mtype is protocol.MTYPE.CLOSE:
            # remote closed, so we close user if existing
            remotefd = packet.src
            logger.info('Server said that {} is closed'.format(remotefd))
            userfd = get_user_by_remote(remotefd)
            if userfd:
                user = user_dict[userfd]
                user.close()
                delete_userfd(userfd)
        else:
            logger.info(packet)
    logger.debug('exit server_loop')


def auth():
    server_sock = socket.create_connection(config.server_address)
    server = SockStream(server_sock)
    logger.info('Negotiating to server {}:{}'.format(
        config.server_host, config.server_port))
    # > Hello
    hello_request = protocol.Hello()
    server.write(hello_request.to_packet())
    # < Hello
    hello_response = protocol.read_packet(server)
    # > HandShake
    shake_request = protocol.HandShake(timestamp=hello_response.timestamp)
    server.write(shake_request.to_packet())
    # < HandShake
    shake_response = protocol.read_packet(server)
    cipher = shake_response.cipher
    logger.info('Negotiate done, using cipher: {}'.format(cipher))
    return server, cipher


def main():
    config.load_args()
    server, cipher = auth()
    server_thread = Thread(target=server_loop, args=(server,))
    server_thread.setDaemon(True)
    server_thread.start()
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.bind(config.client_address)
    client_sock.listen(5)
    logger.info('Local SOCKS5 server started on {}:{}'.format(
        config.client_host, config.client_port))
    while True:
        user_sock, addr = client_sock.accept()
        logger.debug('New connection from {}:{}, fd={}'.format(
            addr[0], addr[1], user_sock.fileno()))
        user = SockStream(user_sock)
        client_greeting = ClientGreeting.from_stream(user)
        logger.debug('C {}:{} {}'.format(
            addr[0], addr[1], client_greeting))
        server_greeting = ServerGreeting()
        logger.debug('S {}'.format(server_greeting))
        user.write(server_greeting.to_bytes())
        # greeting done, ready to receive CMD from client
        t = Thread(target=user_connect, args=(user, server))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
