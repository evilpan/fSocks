#!/usr/bin/env python3
import socket
import struct
import asyncio
from threading import Thread
from fsocks import logger, config, protocol, fuzzing
from fsocks.net import pipe, NetworkError, SockStream
from fsocks.socks import CMD, VER, ATYPE, REP,\
    Message, SocksError


fd_maps = {} #  remote_fd <--> user_fd
remote_dict = {} #  remote_fd -> remote_stream
def get_remote_by_user(userfd):
    for remotefd in fd_maps:
        if fd_maps[remotefd] == userfd:
            return remotefd
    return None
def delete_remotefd(remotefd):
    logger.debug('deleting {} from {}'.format(
        remotefd, fd_maps))
    try:
        del fd_maps[remotefd]
    except KeyError:
        logger.error('fail to delete {}'.format(remotefd))


def remote_loop(remote, client):
    logger.debug('enter remote_loop')
    remotefd = remote.sock.fileno()
    while True:
        userfd = fd_maps.get(remotefd, None)
        if userfd is None:
            logger.warn('remote_loop: remotefd is cleared')
            break
        try:
            data = remote.read(2048, insist=False)
        except NetworkError as e:
            # close user
            logger.debug(
                '[{}] tell client that remote[{}] is closed'.format(e, remotefd))
            packet = protocol.Close(remotefd)
            client.write(packet.to_packet())
            delete_remotefd(remotefd)
            remote.close()
            break
        relaying_packet = protocol.Relaying(
            remotefd, userfd, data)
        client.write(relaying_packet.to_packet())
    logger.debug('exit remote_loop')


def client_loop(client):
    logger.debug('enter client_loop')
    while True:
        try:
            packet = protocol.read_packet(client)
        except NetworkError:
            break
        if packet.mtype is protocol.MTYPE.REQUEST:
            handle_request(client, packet)
        elif packet.mtype is protocol.MTYPE.RELAYING:
            userfd = packet.src
            remotefd = packet.dst
            try:
                remote = remote_dict[remotefd]
            except KeyError:
                logger.warn('RELAY request:{}, remote_dict:{}'.format(remotefd, remote_dict))
            try:
                remote.write(packet.payload)
            except NetworkError as e:
                logger.warn('[{}]: ignore relaying request'.format(e))
        elif packet.mtype is protocol.MTYPE.CLOSE:
            # user closed, so we close remote if existing
            userfd = packet.src
            logger.info('Client said that {} is closed'.format(userfd))
            remotefd = get_remote_by_user(userfd)
            if remotefd:
                remote = remote_dict[remotefd]
                delete_remotefd(remotefd)
                remote.close()
        elif packet.mtype is protocol.MTYPE.HANDSHAKE:
            logger.info('Client HandShake again')
        else:
            logger.warn('Unhandled packet', packet)
    logger.debug('exit client_loop')


def handle_request(client, packet):
    logger.info(packet.msg)
    if packet.msg.code is not CMD.CONNECT:
        logger.warn('not handled SOCKS5 CMD')
        return
    userfd = packet.src
    remote_sock = socket.create_connection(packet.msg.addr)
    remotefd = remote_sock.fileno()
    remote = SockStream(remote_sock)
    bind_address = remote.sock.getsockname()
    rep = Message(
        ver=VER.SOCKS5,
        code=REP.SUCCEEDED,
        atype=ATYPE.IPV4,
        addr=bind_address)
    reply = protocol.Reply(remotefd, userfd, rep)
    # update mapping
    fd_maps[remotefd] = userfd
    remote_dict[remotefd] = remote
    logger.debug('Accept new connect request, fd_maps:{}'.format(fd_maps))
    client.write(reply.to_packet())
    t = Thread(target=remote_loop, args=(remote, client))
    t.setDaemon(False)
    t.start()


def main():
    config.load_args()
    serverfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverfd.bind(config.server_address)
    serverfd.listen(5)
    logger.info('Server started on {}:{}'.format(
        config.server_host, config.server_port))
    while True:
        client_sock, addr = serverfd.accept()
        logger.info('New connection from {}:{}'.format(
            addr[0], addr[1]))
        client = SockStream(client_sock)
        try:
            # TLV
            # > Hello
            hello_request = protocol.read_packet(client)
            logger.info(hello_request)
            # < Hello
            hello_response = protocol.Hello()
            client.write(hello_response.to_packet())
            # > Handshake
            shake_request = protocol.read_packet(client)
            delay = shake_request.timestamp - hello_response.timestamp
            if delay > 100 or delay < 0:
                raise protocol.ProtocolError('HandShake timestamp error')
            logger.info(shake_request)
            shake_response = protocol.HandShake(
                cipher=fuzzing.CipherChain([fuzzing.XOR(0x11), fuzzing.Base64()]))
            client.write(shake_response.to_packet())
            logger.info('HandShake done, using cipher: {}'.format(
                shake_response.cipher))
        except protocol.ProtocolError as e:
            logger.warn(e)
            client_sock.close()
            continue
        # no greetings, handle CONNECT command
        t = Thread(target=client_loop, args=(client,))
        t.setDaemon(True)
        t.start()


if __name__ == '__main__':
    main()
