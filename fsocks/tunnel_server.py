#!/usr/bin/env python3
import asyncio
from fsocks import logger, config, fuzzing, protocol, socks


class Remote:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.remote_id = writer.transport._sock_fd
        self.user_id = None
        self.task = None

    @property
    def actived(self):
        return self.task is not None

    @property
    def established(self):
        return self.user_id is not None

    def close(self):
        # self.reader = None
        # self.writer = None
        self.user_id = None
        self.task.cancel()

    def __str__(self):
        return 'Remote(%d)' % self.remote_id


class Tunnel:
    """ each tunnel """
    def __init__(self, reader, writer):
        self.tunnel_id = writer.transport._sock_fd
        self.reader = reader
        self.writer = writer
        self.remotes = {}  # remote_id -> Remote


class TunnelServer:
    """
    fSocks tunnel server
    A server can accept many tunnels at the same time
    """

    def __init__(self):
        self.tunnel_server = None
        self.tunnel_clients = {}  # task -> Tunnel

    def _get_remote(self, tunnel, remote_id, established=True):
        if remote_id in tunnel.remotes:
            remote = tunnel.remotes[remote_id]
            if (not established) or remote.established:
                return remote
        return None

    def _accept_tunnel(self, tunnel_reader, tunnel_writer):
        logger.debug('tunnel connected')
        t = Tunnel(tunnel_reader, tunnel_writer)
        task = asyncio.Task(self._handle_tunnel(t))
        self.tunnel_clients[task] = t

        def tunnel_done(task):
            logger.debug('tunnel closed')
            del self.tunnel_clients[task]
        task.add_done_callback(tunnel_done)

    async def _handle_tunnel(self, tunnel):
        logger.debug('tunnel negotiating')
        # > Hello
        hello_request = await protocol.async_read_packet(tunnel.reader)
        # < Hello
        hello_response = protocol.Hello()
        tunnel.writer.write(hello_response.to_packet())
        # > Handshake
        shake_request = await protocol.async_read_packet(tunnel.reader)
        delay = shake_request.timestamp - hello_response.timestamp
        if delay > 100 or delay < 0:
            return
        # < Handshake
        cipher = fuzzing.CipherChain([fuzzing.XOR(0x91), fuzzing.Base64()])
        shake_response = protocol.HandShake(cipher=cipher)
        tunnel.writer.write(shake_response.to_packet())
        logger.info(
            'tunnel handshake done, using cipher {} for tunnel {}'.format(
                cipher, tunnel.tunnel_id))
        await self._handle_request(tunnel)

    async def _handle_request(self, tunnel):
        logger.debug('tunnel start handling')
        while True:
            try:
                packet = await protocol.async_read_packet(tunnel.reader)
            except asyncio.IncompleteReadError as e:
                logger.info('tunnel broken')
                break
            if packet.mtype is protocol.MTYPE.REQUEST:
                await self._handle_remote_connect(tunnel, packet)
            elif packet.mtype is protocol.MTYPE.RELAYING:
                remote_id = packet.dst
                remote = self._get_remote(tunnel, remote_id, True)
                if remote is None:
                    # ignore relaying
                    continue
                remote.writer.write(packet.payload)
            elif packet.mtype is protocol.MTYPE.CLOSE:
                remote_id = packet.src
                remote = self._get_remote(tunnel, remote_id, True)
                if remote is None:
                    # already closed
                    continue
                self._delete_remote(tunnel, remote_id)
            else:
                logger.warn('unknown packet: {}'.format(packet))
        logger.debug('tunnel stop handling')

    def _remote_closed(self, tunnel, remote_id):
        if remote_id in tunnel.remotes:
            remote = tunnel.remotes[remote_id]
            logger.debug('{} closed'.format(remote))
            if remote.established:
                tunnel.writer.write(
                    protocol.Close(remote.user_id).to_packet())
        self._delete_remote(tunnel, remote_id)

    def _delete_remote(self, tunnel, remote_id):
        # TODO: cancel task?
        if remote_id in tunnel.remotes:
            del tunnel.remotes[remote_id]

    async def _handle_remote_connect(self, tunnel, packet):
        socks_msg = packet.msg
        if socks_msg.code is not socks.CMD.CONNECT:
            logger.warn('unsupported msg: {}'.format(socks_msg))
            return
        user_id = packet.src
        # connect to remote
        logger.info('connecting {}:{}'.format(
            socks_msg.addr[0], socks_msg.addr[1]))
        fut = asyncio.open_connection(
            socks_msg.addr[0], socks_msg.addr[1])
        try:
            remote_reader, remote_writer = await asyncio.wait_for(fut, config.timeout)
        except asyncio.TimeoutError:
            logger.warn('connect {}:{} timeout'.format(
                socks_msg.addr[0], socks_msg.addr[1]))
            socks_err = socks.Message(
                socks.VER.SOCKS5,
                socks.REP.NETWORK_UNREACHABLE,
                socks.ATYPE.IPV4,
                ('127.0.0.1', 4444))
            tunnel.writer.write(protocol.Reply(
                0, user_id, socks_err).to_packet())
            return
        bind_address = remote_writer.transport._extra['sockname']
        remote = Remote(remote_reader, remote_writer)
        # send REP
        socks_rep = socks.Message(
            socks.VER.SOCKS5,
            socks.REP.SUCCEEDED,
            socks.ATYPE.IPV4,
            bind_address)
        reply = protocol.Reply(
            remote.remote_id, user_id, socks_rep)
        tunnel.writer.write(reply.to_packet())
        remote.user_id = user_id
        # connect success. start forwarding data
        task = asyncio.Task(self._reading_remote(tunnel, remote))
        remote.task = task
        tunnel.remotes[remote.remote_id] = remote

        def remote_done(task):
            logger.debug('remote server closed')
        task.add_done_callback(remote_done)

    async def _reading_remote(self, tunnel, remote):
        while True:
            try:
                data = await remote.reader.read(2048)
            except ConnectionResetError as e:
                logger.warn('remote connection reset')
                data = b''
            if len(data) == 0:
                self._remote_closed(tunnel, remote.remote_id)
                break
            r = protocol.Relaying(
                remote.remote_id, remote.user_id, data)
            tunnel.writer.write(r.to_packet())

    def start(self, loop):
        self.tunnel_server = loop.run_until_complete(
            asyncio.start_server(self._accept_tunnel,
                                 config.server_host,
                                 config.server_port,
                                 loop=loop))
        logger.info('tunnel server listen on {}:{}'.format(
            config.server_host, config.server_port))

    def stop(self, loop):
        if self.tunnel_server is not None:
            self.tunnel_server.close()
            loop.run_until_complete(self.tunnel_server.wait_closed())
            self.tunnel_server = None
        tasks = []
        for tsk in self.tunnel_clients:
            tasks.append(tsk)
            tasks += [ r.task for r in self.tunnel_clients[tsk].remotes if r.actived ]
        if len(tasks) > 0:
            logger.info('stopping pending tasks')
            loop.run_until_complete(asyncio.wait(tasks))


def main():
    config.load_args()
    loop = asyncio.get_event_loop()
    ts = TunnelServer()
    ts.start(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        ts.stop(loop)
        loop.close()


if __name__ == '__main__':
    main()
