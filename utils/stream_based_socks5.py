#!/usr/bin/env python3
import asyncio
from fsocks import logger, socks


async def pipe(name, reader, writer):
    while True:
        try:
            data = await reader.read(2048)
        except ConnectionResetError as e:
            logger.warn('connection reset by ' + name)
            break
        except asyncio.CancelledError as e:
            logger.debug('pipe canceled.')
            break
        if len(data) == 0:
            logger.debug('{} connection closed'.format(name))
            break
        writer.write(data)
    return None


class Server:

    def __init__(self):
        self.server = None  # encapsulates the server sockets

        # this keeps track of all the clients that connected to our
        # server.  It can be useful in some cases, for instance to
        # kill client connections or to broadcast some data to all
        # clients...
        self.clients = {}  # task -> (reader, writer)

    def _accept_client(self, client_reader, client_writer):
        """
        This method accepts a new client connection and creates a Task
        to handle this client.  self.clients is updated to keep track
        of the new client.
        """

        logger.debug('=== begin ===')
        # start a new Task to handle this specific client connection
        task = asyncio.Task(self._handle_client(client_reader, client_writer))
        self.clients[task] = (client_reader, client_writer)

        def client_done(task):
            logger.debug('=== end ===')
            del self.clients[task]

        task.add_done_callback(client_done)

    async def _handle_client(self, client_reader, client_writer):
        # ignore client greeting
        data = await client_reader.read(32)
        logger.debug('Ignore client greeting ({} bytes)'.format(len(data)))
        server_greeting = socks.ServerGreeting()
        client_writer.write(server_greeting.to_bytes())
        # recv CMD
        msg = await socks.Message.from_reader(client_reader)
        if msg.code is not socks.CMD.CONNECT:
            logger.warn('unhandle msg {}'.format(msg))
            return
        fut = asyncio.open_connection(msg.addr[0], msg.addr[1])
        try:
            remote_reader, remote_writer = await asyncio.wait_for(fut, 3)
        except (asyncio.TimeoutError, ConnectionRefusedError):
            logger.warn('connet {}:{} failed'.format(
                msg.addr[0], msg.addr[1]))
            err_reply = socks.Message(
                ver=socks.VER.SOCKS5,
                code=socks.REP.CONNECTION_REFUSED,
                atype=socks.ATYPE.IPV4,
                addr=('127.0.0.1', 9999))
            client_writer.write(err_reply.to_bytes())
            return

        logger.info('connected to {}:{}'.format(msg.addr[0], msg.addr[1]))
        # send REP
        bind_address = remote_writer.transport._extra['sockname']
        reply = socks.Message(
            ver=socks.VER.SOCKS5,
            code=socks.REP.SUCCEEDED,
            atype=socks.ATYPE.IPV4,
            addr=bind_address)
        client_writer.write(reply.to_bytes())
        # piping
        await asyncio.gather(
            pipe('remote', remote_reader, client_writer),
            pipe('user', client_reader, remote_writer))

    def start(self, loop):
        """
        Starts the TCP server, so that it listens on port 12345.

        For each client that connects, the accept_client method gets
        called.  This method runs the loop until the server sockets
        are ready to accept connections.
        """
        host, port = '127.0.0.1', 1080
        self.server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_client,
                                         host, port,
                                         loop=loop))
        logger.info('Server start on {}:{}'.format(host, port))

    def stop(self, loop):
        """
        Stops the TCP server, i.e. closes the listening socket(s).

        This method runs the loop until the server sockets are closed.
        """
        if self.server is not None:
            logger.debug('canceling tasks')
            for task in self.clients:
                task.cancel()
            loop.run_until_complete(asyncio.wait([t for t in self.clients]))
            self.server.close()
            loop.run_until_complete(self.server.wait_closed())
            self.server = None


def main():
    loop = asyncio.get_event_loop()
    server = Server()
    server.start(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        server.stop(loop)
        loop.close()


if __name__ == '__main__':
    main()
