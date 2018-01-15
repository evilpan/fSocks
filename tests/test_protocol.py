#!/usr/bin/env python3
import io
import struct
from unittest import TestCase
from fsocks import protocol, socks, fuzzing
from fsocks.protocol import ProtocolError, Hello, HandShake,\
    Request, Reply, Relaying, Close


class TestHello(TestCase):
    def test_basic(self):
        msg = Hello()
        self.assertIsInstance(str(msg), str)
        s = io.BytesIO(msg.to_bytes())
        msg1 = Hello.from_stream(s)
        self.assertEqual(msg.magic, msg1.magic)
        self.assertEqual(msg.mtype, msg1.mtype)
        self.assertEqual(msg.nonce, msg1.nonce)
        self.assertEqual(msg.timestamp, msg1.timestamp)
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())

    def test_corner(self):
        msg = Hello()
        msg.mtype = protocol.MTYPE.HANDSHAKE
        self.assertRaises(ProtocolError, Hello.from_stream,
                          io.BytesIO(msg.to_bytes()))
        self.assertRaises(ProtocolError, Hello.from_stream,
                          io.BytesIO(struct.pack('!HBI', msg.magic, 0, 0)))
        self.assertRaises(ProtocolError, Hello.from_stream,
                          io.BytesIO(b'\x00\x11'))
        msg.magic = 0x3389
        self.assertRaises(ProtocolError, Hello.from_stream,
                          io.BytesIO(msg.to_bytes()))


class TestHandShake(TestCase):
    def test_init(self):
        msg = HandShake()
        self.assertIsInstance(str(msg), str)
        self.assertLessEqual(99, len(msg.to_bytes()))
        self.assertEqual(0, msg.to_bytes()[-1]) # end of ciphers
        msg1 = HandShake.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())

    def test_corner(self):
        msg = HandShake()
        b = msg.to_bytes()
        b1 = b.replace(b'\x06Base64', b'\x16NonExistingCpher')
        self.assertNotEqual(b1, b)
        self.assertRaises(ProtocolError, HandShake.from_stream, io.BytesIO(b1))
        msg.mtype = protocol.MTYPE.HELLO
        self.assertRaises(ProtocolError, HandShake.from_stream,
                          io.BytesIO(msg.to_bytes()))
        msg.magic = 0x3389
        self.assertRaises(ProtocolError, HandShake.from_stream,
                          io.BytesIO(msg.to_bytes()))
        self.assertRaises(ProtocolError, HandShake.from_stream,
                          io.BytesIO(b'123456'))
        self.assertRaises(ProtocolError, HandShake, cipher=[])
        self.assertRaises(ProtocolError, HandShake, cipher=fuzzing.XOR(0x11))
        msg = HandShake(cipher=fuzzing.CipherChain([]))
        b = msg.to_bytes()
        self.assertRaises(ProtocolError, HandShake.from_stream, io.BytesIO(b))

    def test_custom(self):
        cipher=fuzzing.CipherChain([fuzzing.XOR(0x11)])
        msg = HandShake(cipher=cipher)
        msg1 = HandShake.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())


class TestRequest(TestCase):
    def test_basic(self):
        socks_msg = socks.Message(socks.VER.SOCKS5, socks.CMD.CONNECT,
                                  socks.ATYPE.IPV4, ('127.0.0.1', 1234))
        m = Request(3, 4, socks_msg)
        m1 = Request.from_stream(io.BytesIO(m.to_bytes()))
        self.assertEqual(m.to_bytes(), m1.to_bytes())


class TestReply(TestCase):
    def test_basic(self):
        socks_msg = socks.Message(socks.VER.SOCKS5, socks.REP.ADDRESS_TYPE_NOT_SUPPORTED,
                                  socks.ATYPE.IPV4, ('127.0.0.1', 1234))
        m = Reply(3, 4, socks_msg)
        m1 = Reply.from_stream(io.BytesIO(m.to_bytes()))
        self.assertEqual(m.to_bytes(), m1.to_bytes())

    def test_corner(self):
        socks_msg = socks.Message(socks.VER.SOCKS5, socks.CMD.CONNECT,
                                  socks.ATYPE.IPV4, ('127.0.0.1', 1234))
        m = Request(3, 4, socks_msg)
        self.assertRaises(ProtocolError, Reply.from_stream,
                          io.BytesIO(m.to_bytes()))


class TestRelaying(TestCase):
    def test_basic(self):
        payload = b'GET / HTTP/1.1\r\n\r\n'
        msg = Relaying(3, 5, payload)
        msg1 = Relaying.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())


class TestClose(TestCase):
    def test_basic(self):
        msg = Close(3)
        msg1 = Close.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())
