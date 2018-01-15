#!/usr/bin/env python3
import io
import struct
from unittest import TestCase
from fsocks import socks
from fsocks.socks import Message, ClientGreeting, ServerGreeting, SocksError


class TestMessage(TestCase):
    def test_basic(self):
        msg = Message(socks.VER.SOCKS5, socks.CMD.CONNECT,
                      socks.ATYPE.IPV4, ('127.0.0.1', 1234))
        self.assertTrue(msg.is_request)
        self.assertEqual('<SOCKS5 CONNECT IPV4 127.0.0.1:1234>', str(msg))
        self.assertEqual(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2',
                         msg.to_bytes())
        msg1 = Message.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.ver, msg1.ver)
        self.assertEqual(msg.code, msg1.code)
        self.assertEqual(msg.atype, msg1.atype)
        self.assertEqual(msg.addr, msg1.addr)
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())
        msg = Message(socks.VER.SOCKS5, socks.CMD.CONNECT,
                      socks.ATYPE.IPV6, ('::1', 1234))
        msg1 = Message.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())
        msg = Message(socks.VER.SOCKS5, socks.CMD.CONNECT,
                      socks.ATYPE.DOMAINNAME, ('baidu.com', 1234))
        msg1 = Message.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())

    def test_corner(self):
        msg = Message(socks.VER.SOCKS5, socks.REP.ADDRESS_TYPE_NOT_SUPPORTED,
                      socks.ATYPE.IPV4, ('127.0.0.1', 1234))
        self.assertFalse(msg.is_request)
        Message.from_stream(io.BytesIO(msg.to_bytes()), request=False)
        self.assertRaises(SocksError, Message.from_stream,
                          io.BytesIO(msg.to_bytes()))
        msg.RSV = 1
        self.assertRaises(SocksError, Message.from_stream,
                          io.BytesIO(msg.to_bytes()), request=False)

class TestGreeting(TestCase):
    def test_client(self):
        cg = ClientGreeting(socks.VER.SOCKS5, 2,
                            [socks.METHOD.NO_AUTHENTICATION_REQUIRED,
                             socks.METHOD.USERNAME_PASSWORD])
        cg1 = ClientGreeting.from_stream(io.BytesIO(cg.to_bytes()))
        for m in cg, cg1:
            self.assertEqual("<SOCKS5 2:['NO_AUTHENTICATION_REQUIRED',"
                             " 'USERNAME_PASSWORD']>", str(m))
            self.assertEqual(b'\x05\x02\x00\x02', m.to_bytes())

    def test_server(self):
        sg = ServerGreeting(socks.VER.SOCKS5, socks.METHOD.USERNAME_PASSWORD)
        sg1 = ServerGreeting.from_stream(io.BytesIO(sg.to_bytes()))
        for m in sg, sg1:
            self.assertEqual('<SOCKS5 USERNAME_PASSWORD>', str(m))
            self.assertEqual(b'\x05\x02', m.to_bytes())
