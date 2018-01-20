#!/usr/bin/env python3
import io
import asyncio
from fsocks import logger, socks

""" callback based SOCKS5 server
https://docs.python.org/3/library/asyncio-protocol.html#connection-callbacks
"""


concurrent = 0


class Server(asyncio.Protocol):
    INIT, CMD, DATA, CLOSED = 0, 1, 2, 3

    def connection_made(self, transport):
        global concurrent
        concurrent += 1
        logger.debug('{} connected'.format(
            transport.get_extra_info('peername')))
        self.transport = transport
        self.client_transport = None
        self.user = transport.get_extra_info('peername')
        self.state = self.INIT

    def connection_lost(self, exc):
        global concurrent
        concurrent -= 1
        logger.debug('connection to user lost')
        self.state = self.CLOSED
        if self.client_transport is not None:
            logger.debug('abort client')
            self.client_transport.abort()

    def data_received(self, data):
        # logger.debug('{}: {}'.format(self.user, data))
        if self.state == self.INIT:
            client_greeting = socks.ClientGreeting.from_stream(io.BytesIO(data))
            server_greeting = socks.ServerGreeting()
            self.transport.write(server_greeting.to_bytes())
            self.state = self.CMD
        elif self.state == self.CMD:
            msg = socks.Message.from_stream(io.BytesIO(data))
            global concurrent
            logger.info('connecting {}:{} ({})'.format(msg.addr[0], msg.addr[1], concurrent))
            bind_addr = ('127.0.0.1', 9999)
            if msg.code is not socks.CMD.CONNECT:
                rep = socks.Message(socks.VER.SOCKS5,
                                    socks.REP.COMMAND_NOT_SUPPORTED,
                                    socks.ATYPE.IPV4,
                                    bind_addr)
                self.transport.write(rep.to_bytes())
                return
            # connect
            asyncio.ensure_future(self.connect(msg.addr[0], msg.addr[1]))
        elif self.state == self.DATA:
            self.client_transport.write(data)
        else:
            logger.warn('receiving data from user in CLOSED state')

    async def connect(self, host, port):
        loop = asyncio.get_event_loop()
        bind_addr = ('127.0.0.1', 80)
        try:
            transport, client = \
                await loop.create_connection(Client, host, port)
        except asyncio.TimeoutError:
            rep = socks.Message(socks.VER.SOCKS5,
                                socks.REP.NETWORK_UNREACHABLE,
                                socks.ATYPE.IPV4,
                                bind_addr)
            self.transport.write(rep.to_bytes())
            self.state = self.CMD
            return
        client.server_transport = self.transport
        self.client_transport = transport
        bind_addr = transport.get_extra_info('sockname')
        rep = socks.Message(socks.VER.SOCKS5,
                            socks.REP.SUCCEEDED,
                            socks.ATYPE.IPV4,
                            bind_addr)
        self.transport.write(rep.to_bytes())
        self.state = self.DATA


class Client(asyncio.Protocol):
    OPEN, CLOSED = 0, 1
    def connection_made(self, transport):
        self.transport = transport
        self.state = self.OPEN

    def data_received(self, data):
        if self.state == self.OPEN:
            self.server_transport.write(data)
        else:
            logger.warn('receiving data from server in CLOSED state')

    def connection_lost(self, exc):
        logger.debug('connection to server lost')
        self.state = self.CLOSED
        if self.server_transport is not None:
            logger.debug('abort server')
            self.server_transport.abort()


def main():
    import logging
    logger.setLevel(logging.INFO)
    loop = asyncio.get_event_loop()
    host, port = '127.0.0.1', 1080
    logger.info('SOCKS5 server listen on {}:{}'.format(host, port))
    server = loop.create_server(Server, host, port)
    loop.run_until_complete(server)
    loop.run_forever()


if __name__ == '__main__':
    main()
