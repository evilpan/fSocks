#!/usr/bin/env python3
import io
import struct
import asyncio
import socket
from enum import Enum, unique
from fsocks import logger, config, protocol, socks
from fsocks import fuzzing, cryption


concurrent = 0  # for debug purpose
# Each TunnelServer can accept many tunnel(connection)s,
# And every tunnel(connection) is multiplexed for handling
# many SOCKS5 request. Thus, every tunnel is keeping track of
# the peer to peer states.


class Client(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self.channel = None
        global concurrent
        concurrent += 1

    def data_received(self, data):
        self.channel.forward(data, False)

    def connection_lost(self, exc):
        global concurrent
        concurrent -= 1
        if exc is not None:
            logger.warn('remote closed: {}'.format(exc))
        self.channel.close()


class Channel:
    """ A channel is a peer to peer association """
    IDLE, CMD, DATA = 0, 1, 2

    def __init__(self, transport, fuzz, user, remote=0):
        self.tunnel_transport = transport
        self.remote_transport = None
        self.fuzz = fuzz
        self.user = user
        self.remote = remote
        self.state = self.IDLE

    async def connect(self, host, port):
        self.state = self.CMD
        loop = asyncio.get_event_loop()
        bind_addr = ('255.255.255.255', 0)
        try:
            logger.info('connecting {}:{}'.format(host, port))
            fut = loop.create_connection(Client, host, port)
            transport, client = await \
                asyncio.wait_for(fut, timeout=config.timeout)
        except (asyncio.TimeoutError,
                ConnectionRefusedError,
                socket.gaierror) as e:
            logger.warn('connect {}'.format(e))
            socks_err = socks.Message(socks.VER.SOCKS5,
                                      socks.REP.NETWORK_UNREACHABLE,
                                      socks.ATYPE.IPV4, bind_addr)
            rep = protocol.Reply(self.remote, self.user, socks_err)
            self.tunnel_transport.write(rep.to_packet(self.fuzz))
            self.state = self.IDLE
            return
        client.channel = self
        self.remote_transport = transport
        self.remote = transport._sock_fd
        bind_addr = transport.get_extra_info('sockname')
        socks_ok = socks.Message(socks.VER.SOCKS5, socks.REP.SUCCEEDED,
                                 socks.ATYPE.IPV4, bind_addr)
        rep = protocol.Reply(self.remote, self.user, socks_ok)
        self.tunnel_transport.write(rep.to_packet(self.fuzz))
        self.state = self.DATA
        logger.debug('channel {} opened'.format(self))

    def forward(self, payload, upstream=True):
        if self.state != self.DATA:
            logger.warn('channel is not ready')
            return
        if upstream:
            return self.remote_transport.write(payload)
        packet = protocol.Relaying(self.remote, self.user, payload)
        return self.tunnel_transport.write(packet.to_packet(self.fuzz))

    def close(self):
        if self.state == self.IDLE:
            return
        self.state = self.IDLE
        if self.remote_transport is not None:
            self.remote_transport.abort()
        packet = protocol.Close(self.user)
        self.tunnel_transport.write(packet.to_packet(self.fuzz))
        logger.debug('channel {} closed'.format(self))

    def __str__(self):
        return '{}->{}'.format(self.user, self.remote)


class Tunnel:
    def __init__(self, transport, fuzz):
        self.transport = transport
        self.fuzz = fuzz
        self.channels = {}  # user_id -> Channel

    def handle_request(self, packet):
        if packet.mtype is protocol.MTYPE.REQUEST:
            msg = packet.msg
            if msg.code is not socks.CMD.CONNECT:
                logger.warn('unsupported msg: {}'.format(msg))
                return
            user = packet.src
            chan = Channel(self.transport, self.fuzz, user)
            asyncio.ensure_future(chan.connect(msg.addr[0], msg.addr[1]))
            self.channels[user] = chan
        elif packet.mtype is protocol.MTYPE.RELAYING:
            user = packet.src
            self.channels[user].forward(packet.payload)
        elif packet.mtype is protocol.MTYPE.CLOSE:
            user = packet.src
            self.channels[user].close()
        else:
            logger.warn('unkown packet {}'.format(packet))

    def close(self):
        logger.info('closing channels in tunnel')
        for user in self.channels:
            self.channels[user].close()


class TunnelServer(asyncio.Protocol):
    GREETING, NEGOTIATING, OPEN, CLOSING = 0, 1, 2, 3

    def connection_made(self, transport):
        logger.debug('client {}:{} connected'.format(
            *transport.get_extra_info('peername')))
        self.transport = transport
        self.tunnel = None
        self.state = self.GREETING
        self.buf = bytearray()
        self.remains = 0
        self.cipher = cryption.AES256CBC(config.password)
        self.fuzz = None

    def connection_lost(self, exc):
        self.state = self.CLOSING
        logger.debug('client {}:{} disconnected'.format(
            *self.transport.get_extra_info('peername')))
        if self.tunnel is not None:
            self.tunnel.close()

    def data_received(self, data):
        length = len(data)
        if self.remains > 0:
            # remaining part of previous packet
            if length == self.remains:
                self.buf.extend(data)
                self.packet_received(self.buf)
                self.remains = 0
                self.buf.clear()
            elif length < self.remains:
                self.buf.extend(data)
                self.remains -= length
            elif length > self.remains:
                self.buf.extend(data[:self.remains])
                self.packet_received(self.buf)
                self.remains = 0
                self.buf.clear()
                self.data_received(data[self.remains:])
            return
        # start of packet
        assert length >= 6, 'packet length too small'
        need_len, = struct.unpack('!I', data[2:6])
        real_len = length - 6
        self.remains = need_len - real_len
        if self.remains == 0:
            self.packet_received(data)
        elif self.remains > 0:
            self.buf.extend(data)
        elif self.remains < 0:
            logger.debug('more than one packet recevied at once')
            self.packet_received(data[:6 + need_len])
            remaining = data[6 + need_len:]
            self.remains = 0
            self.data_received(remaining)

    def packet_received(self, packet_data):
        if self.state == self.GREETING:
            packet = protocol.read_packet(
                io.BytesIO(packet_data), self.cipher)
            if packet.mtype is not protocol.MTYPE.HELLO:
                self.transport.abort()
                self.state = self.CLOSING
                return
            self.transport.write(
                protocol.Hello().to_packet(self.cipher))
            self.tunnel = Tunnel(self.transport, self.fuzz)
            self.state = self.NEGOTIATING
        elif self.state == self.NEGOTIATING:
            packet = protocol.read_packet(
                io.BytesIO(packet_data), self.cipher)
            if packet.mtype is not protocol.MTYPE.HANDSHAKE:
                self.transport.abort()
                self.state = self.CLOSING
            nfuzzs = len(packet.fuzz.fuzz_list)
            logger.info('client HandShake with {} fuzzing methods:\n{}'.format(
                nfuzzs, packet.fuzz))
            fuzz = fuzzing.FuzzChain(packet.fuzz.fuzz_list[:2])
            logger.info('choose {}'.format(fuzz))
            response = protocol.HandShake(fuzz=fuzz)
            self.transport.write(response.to_packet(self.cipher))
            self.fuzz = fuzz
            self.tunnel.fuzz = fuzz
            self.state = self.OPEN
        elif self.state == self.OPEN:
            packet = protocol.read_packet(
                io.BytesIO(packet_data), self.fuzz)
            self.tunnel.handle_request(packet)
        else:
            logger.warn('tunel is closing')


def main():
    config.load_args()
    loop = asyncio.get_event_loop()
    host, port = config.server_address
    logger.info('tunnel server listen on {}:{}'.format(host, port))
    server = loop.create_server(TunnelServer, host, port)
    loop.run_until_complete(server)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info('shuting down tunnel server')


if __name__ == '__main__':
    main()
