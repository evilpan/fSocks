#!/usr/bin/env python3
import sys
import asyncio
from fsocks import logger, config, fuzzing, protocol, socks


concurrent = 0
# Each TunnelClient can allocate one or many tunnel(connection)s,
# And every tunnel(connection) is multiplexed for handling 
# many SOCKS5 request.
# Tunnels are independent and could make up a connection pool. 


class Channel:
    """ A channel is a peer to peer association """
    IDLE, CMD, DATA = 0, 1, 2
    def __init__(self, transport, user, remote=0):
        self.tunnel_transport = transport
        self.user_transport = None
        self.user = user
        self.remote = remote
        self.state = self.IDLE

    def forward(self, payload, upstream=True):
        if self.state != self.DATA:
            logger.warn('channel is not ready')
            return
        if upstream:
            return self.user_transport.write(payload)
        packet = protocol.Relaying(self.remote, self.user, payload)
        return self.tunnel_transport.write(packet.to_packet())

    def close(self):
        if self.state == self.IDLE:
            return
        self.state = self.IDLE
        if self.user_transport is not None:
            self.user_transport.abort()
        logger.debug('channel {} closed'.format(self))

    def __str__(self):
        return '{}->{}'.format(self.user, self.remote)


class TunnelClient(asyncio.Protocol):
    NEGOTIATING, OPEN, CLOSING = 0, 1, 2

    def connection_made(self, transport):
        self.transport = transport
        self.state = NEGOTIATING
        # self.client = None  # client that owning this tunnel
        self.cipher = None
        self.channels = {}  # remote_id -> Channel
        # Start negotiating
        self.transport.write(protocol.Hello().to_packet())

    def connection_lost(self, exc):
        self.client.remove(self)
        self.state = self.CLOSING

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
            # more than one packet recevied
            self.packet_received(data[:6+need_len])
            remaining = data[6+need_len:]
            self.remains = 0
            self.data_received(remaining)

    def packet_received(self, packet_data):
        packet = protocol.read_packet(io.BytesIO(packet_data))
        if self.state == self.NEGOTIATING:
            if packet.mtype is protocol.MTYPE.HELLO:
                self.transport.write(protocol.HandShake(
                    timestamp=packet.timestamp))
            elif packet.mtype is protocol.MTYPE.HANDSHAKE:
                self.cipher = packet.cipher
                self.state = self.OPEN
            else:
                logger.warn('receive {} while negotiating'.format(packet))
            return
        elif self.state == self.OPEN:
            self.client.handle_packet(packet)

    def handle_packet(self, packet):
        if packet.mtype is protocol.MTYPE.REPLY:
            pass
        elif packet.mtype is protocol.MTYPE.RELAYING:
            pass
        elif packet.mtype is protocol.MTYPE.CLOSE:
            pass
        else:
            logger.warn('unhandled packet {}'.format(packet))


class SocksServer(asyncio.Protocol):
    IDLE, CMD, DATA, CLOSING = 0, 1, 2, 3

    def connection_made(self, transport):
        self.transport = transport
        self.state = IDLE
        self.user_id = transport._sock_fd
        # self.client = None
        self.tunnel = self.client.get_tunnel()

    def connection_lost(self, exc):
        pass

    def data_received(self, data):
        if self.state == self.IDLE:
            # greeting
            client_greeting = socks.ClientGreeting.from_stream(io.BytesIO(data))
            server_greeting = socks.ServerGreeting()
            self.transport.write(server_greeting.to_bytes())
            self.state = self.CMD
        if self.state == self.CMD:
            # command
            msg = socks.Message.from_stream(io.BytesIO(data))
            addr = ('255.255.255.255', 0)
            if msg.code is not socks.CMD.CONNECT:
                rep = socks.Message(socks.VER.SOCKS5,
                                    socks.REP.COMMAND_NOT_SUPPORTED,
                                    socks.ATYPE.IPV4,
                                    addr)
                self.transport.write(rep.to_bytes())
                return
            # choose a random tunnel to handle CONNECT command
            packet = protocol.Request(self.user_id, 0, msg)
            self.tunnel.transport.write(packet.to_packet())
        if self.state == self.DATA:
            pass


class Client:

    def __init__(self, loop):
        self.loop = loop
        self.tunnels = []
        self.socks_server = None

    async def start_tunnel(self, ntunnels=2):
        host, port = config.server_address
        for i in range(ntunnels):
            try:
                transport, tunnel = await asyncio.wait_for(
                    self.loop.create_connection(TunnelClient, host, port),
                    timeout=3.0)
            except asyncio.TimeoutError:
                logger.error('cannot connect to tunnel server')
                continue
            tunnel.client = self
            self.tunnels.append(tunnel)

    def start_server(self):
        host, port = config.client_address
        logger.info('local SOCKS5 server listen on {}:{}'.format(host, port))
        socks_server = self.loop.run_until_complete(
            self.loop.create_server(SocksServer, host, port))
        socks_server.client = self
        self.socks_server = socks_server

    def get_tunnel(self):
        return self.tunnels[0]

    def remove(self, tunnel):
        if tunnel in self.tunnels:
            self.tunnels.remove(tunnel)
