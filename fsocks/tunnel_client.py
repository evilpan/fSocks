#!/usr/bin/env python3
import sys
import asyncio
from fsocks import logger, config, fuzzing, protocol, socks


class TunnelClient:
    """
    fSocks tunnel client, and SOCK5 server for user
    """

    def __init__(self):
        self.socks_server = None
        self.tunnel = None
        self.users = {}  # task -> (reader, writer)
        # Tunnel client
        self.tunnel_task = None
        self.tunnel_reader = None
        self.tunnel_writer = None
        self.cipher = None
        self.established = {}  # user_id -> remote_id
        self.user_dict = {}  # user_id -> (reader, writer)

    def _accept_user(self, user_reader, user_writer):
        logger.debug('user accepted')
        task = asyncio.Task(self._handle_user(user_reader, user_writer))
        self.users[task] = (user_reader, user_writer)

        def user_done(task):
            logger.debug('user task done')
            del self.users[task]

        task.add_done_callback(user_done)

    def _user_closed(self, user_id):
        logger.debug('user[{}] closed'.format(user_id))
        if user_id in self.established:
            remote_id = self.established[user_id]
            self.tunnel_writer.write(
                protocol.Close(user_id).to_packet())
            del self.established[user_id]
        if user_id in self.user_dict:
            del self.user_dict[user_id]


    async def _pipe_user(self, user_id):
        # may start before connection to remote is established
        user_reader = self.user_dict[user_id][0]
        while True:
            data = await user_reader.read(2048)
            if len(data) == 0:
                self._user_closed(user_id)
                break
            remote_id = self.established[user_id]
            packet = protocol.Relaying(
                user_id, remote_id, data)
            self.tunnel_writer.write(packet.to_packet())

    async def _handle_user(self, user_reader, user_writer):
        # ignore client SOCKS5 greeting
        data = await user_reader.read(256)
        logger.debug('ignore SOCK5 greeting ({} bytes)'.format(len(data)))
        # response greeting without auth
        server_greeting = socks.ServerGreeting()
        user_writer.write(server_greeting.to_bytes())
        # recv CMD
        msg = await socks.Message.from_reader(user_reader)
        if msg.code is not socks.CMD.CONNECT:
            logger.warn('unhandle msg {}'.format(msg))
            user_writer.write(socks.Message(
                socks.VER.SOCKS5,
                socks.REP.COMMAND_NOT_SUPPORTED,
                socks.ATYPE.IPV4,
                ('0', 0)).to_bytes())
            return
        logger.info('connecting {}:{}'.format(msg.addr[0], msg.addr[1]))
        # send to tunnel
        user_id = user_writer.transport._sock_fd
        connect_reqeust = protocol.Request(
            user_id, 0, msg)
        self.tunnel_writer.write(connect_reqeust.to_packet())
        self.user_dict[user_id] = user_reader, user_writer
        await self._pipe_user(user_id)

    async def _handle_tunnel(self, reader, writer):
        logger.debug('_handle_tunnel started')
        while True:
            packet = await protocol.async_read_packet(reader)
            if packet.mtype is protocol.MTYPE.REPLY:
                # received a SOCKS reply, update mapping
                # and forward to corresponding user
                remote_id = packet.src
                user_id = packet.dst
                if user_id not in self.user_dict:
                    # Tell server to close
                    continue
                user_writer = self.user_dict[user_id][1]
                user_writer.write(packet.msg.to_bytes())
                self.established[user_id] = remote_id
            elif packet.mtype is protocol.MTYPE.RELAYING:
                # received raw data, forwarding
                remote_id = packet.src
                user_id = packet.dst
                if user_id not in self.user_dict:
                    # Tell server to close
                    continue
                user_writer = self.user_dict[user_id][1]
                user_writer.write(packet.payload)
            elif packet.mtype is protocol.MTYPE.CLOSE:
                # remote closed, so we close every related user
                remote_id = packet.src
                logger.info('Close remote[{}]'.format(remote_id))
            else:
                logger.warn('unknown packet {}'.format(packet))
        logger.debug('_handle_tunnel exited')

    async def start_tunnel(self, loop, host, port):
        logger.info('negotiate with server {}:{}'.format(
            config.server_host, config.server_port))
        reader, writer = await asyncio.open_connection(host, port)
        # > Hello
        hello_request = protocol.Hello()
        writer.write(hello_request.to_packet())
        # < Hello
        hello_response = await protocol.async_read_packet(reader)
        # > HandShake
        shake_request = protocol.HandShake(timestamp=hello_response.timestamp)
        writer.write(shake_request.to_packet())
        # < HandShake
        shake_response = await protocol.async_read_packet(reader)
        self.cipher = shake_response.cipher
        logger.info('negotiate done, using cipher: {}'.format(self.cipher))
        self.tunnel_reader = reader
        self.tunnel_writer = writer
        self.tunnel_task = asyncio.Task(
            self._handle_tunnel(reader, writer))

        def tunnel_done(task):
            # clean up here or there?
            logger.warn('tunnel is closed')
        self.tunnel_task.add_done_callback(tunnel_done)
        return True

    def start(self, loop):
        try:
            loop.run_until_complete(
                self.start_tunnel(loop,
                                  config.server_host,
                                  config.server_port))
        except Exception as e:
            logger.error('Negotiate failed: {}'.format(e))
            sys.exit(1)
        self.socks_server = loop.run_until_complete(
            asyncio.streams.start_server(self._accept_user,
                                         config.client_host,
                                         config.client_port,
                                         loop=loop))
        logger.info('SOCKS5 server listen on {}:{}'.format(
            config.client_host, config.client_port))

    def stop(self, loop):
        if self.socks_server is not None:
            self.socks_server.close()
            loop.run_until_complete(self.socks_server.wait_closed())
            self.socks_server = None
        if self.tunnel_task is not None:
            self.tunnel_task.cancel()
        loop.run_until_complete(asyncio.wait(
            list(self.users.keys()) + [self.tunnel_task]))


def main():
    config.load_args()
    loop = asyncio.get_event_loop()
    tunnel = TunnelClient()
    tunnel.start(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        tunnel.stop(loop)
        loop.close()


if __name__ == '__main__':
    main()
