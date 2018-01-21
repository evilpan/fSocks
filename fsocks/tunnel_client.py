#!/usr/bin/env python3
import sys
import asyncio
from fsocks import logger, config, fuzzing, protocol, socks


class User:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.user_id = writer.transport._sock_fd
        self.remote_id = None
        self.task = None

    @property
    def actived(self):
        return self.task is not None

    @property
    def established(self):
        return self.remote_id is not None

    def close(self):
        self.remote_id = None
        self.writer.close()
        self.task.cancel()
        self.task = None

    def __str__(self):
        return 'User(%d)' % self.user_id


class TunnelClient:
    """
    fSocks tunnel client, and SOCK5 server for user
    """

    def __init__(self):
        self.socks_server = None
        self.users = {}  # user_id -> User
        # Tunnel client
        # TODO: one tunnel client may have many tunnels
        self.tunnel_task = None
        self.tunnel_reader = None
        self.tunnel_writer = None
        self.cipher = None

    def _accept_user(self, user_reader, user_writer):
        logger.debug('user accepted')
        user = User(user_reader, user_writer)
        task = asyncio.Task(self._handle_user(user))
        user.task = task
        self.users[user.user_id] = user

        def user_done(task):
            logger.debug('user task done')
        task.add_done_callback(user_done)

    def _user_closed(self, user):
        logger.debug('{} closed'.format(user))
        if user.established:
            self.tunnel_writer.write(
                protocol.Close(user.user_id).to_packet())
        user.writer.transport.abort()

    def _delete_user(self, user):
        user.close()
        del self.users[user.user_id]

    def _get_user(self, user_id):
        if user_id in self.users:
            user = self.users[user_id]
            return user
        return None

    async def _pipe_user(self, user):
        # may start before connection to remote is established
        while True:
            try:
                data = await user.reader.read(2048)
            except ConnectionResetError:
                logger.warn('user connection reset')
                data = b''
            if len(data) == 0:
                self._user_closed(user)
                break
            assert user.established
            packet = protocol.Relaying(
                user.user_id, user.remote_id, data)
            self.tunnel_writer.write(packet.to_packet())

    async def _handle_user(self, user):
        # ignore client SOCKS5 greeting
        data = await user.reader.read(256)
        logger.debug('ignore SOCK5 greeting ({} bytes)'.format(len(data)))
        # response greeting without auth
        server_greeting = socks.ServerGreeting()
        user.writer.write(server_greeting.to_bytes())
        # recv CMD
        msg = await socks.Message.from_reader(user.reader)
        if msg.code is not socks.CMD.CONNECT:
            logger.warn('unhandle msg {}'.format(msg))
            user.writer.write(socks.Message(
                socks.VER.SOCKS5,
                socks.REP.COMMAND_NOT_SUPPORTED,
                socks.ATYPE.IPV4,
                ('0', 0)).to_bytes())
            return
        logger.info('connecting {}:{}'.format(msg.addr[0], msg.addr[1]))
        # send to tunnel
        connect_reqeust = protocol.Request(
            user.user_id, 0, msg)
        self.tunnel_writer.write(connect_reqeust.to_packet())
        await self._pipe_user(user)

    async def _handle_tunnel(self, reader, writer):
        logger.debug('_handle_tunnel started')
        while True:
            packet = await protocol.async_read_packet(reader)
            if packet.mtype is protocol.MTYPE.REPLY:
                # received a SOCKS reply, update mapping
                # and forward to corresponding user
                remote_id = packet.src
                user_id = packet.dst
                user = self._get_user(user_id)
                if user is None:
                    # Tell server to close
                    continue
                user.writer.write(packet.msg.to_bytes())
                user.remote_id = remote_id
            elif packet.mtype is protocol.MTYPE.RELAYING:
                # received raw data, forwarding
                remote_id = packet.src
                user_id = packet.dst
                user = self._get_user(user_id)
                if user is None:
                    # Tell server to close
                    continue
                user.writer.write(packet.payload)
            elif packet.mtype is protocol.MTYPE.CLOSE:
                # remote closed, so we close related user
                user_id = packet.src
                logger.debug(
                    'remote disconnected, close user {}'.format(user_id))
                user = self._get_user(user_id)
                if user is None:
                    # ignore
                    continue
                self._delete_user(user)
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
        logger.debug(hello_response)
        # > HandShake
        shake_request = protocol.HandShake(timestamp=hello_response.timestamp)
        writer.write(shake_request.to_packet())
        # < HandShake
        shake_response = await protocol.async_read_packet(reader)
        logger.debug(shake_response)
        logger.info('negotiate done, using cipher: {}'.format(shake_response.cipher))
        self.cipher = shake_response.cipher
        self.tunnel_reader = reader
        self.tunnel_writer = writer
        self.tunnel_task = asyncio.Task(
            self._handle_tunnel(reader, writer))

        def tunnel_done(task):
            logger.warn('tunnel is closed')
            sys.exit(2)
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
            [u.task for u in self.users.values() if u.actived] +
            [self.tunnel_task]))


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
