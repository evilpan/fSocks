#!/usr/bin/env python3
import io
from unittest import TestCase
from fsocks import protocol
from fsocks import fuzzing
from fsocks.protocol import ProtocolError, Hello, HandShake


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
        self.assertRaises(ProtocolError,
                          Hello.from_stream, io.BytesIO(msg.to_bytes()))
        msg.magic = 0x3389
        self.assertRaises(ProtocolError,
                          Hello.from_stream, io.BytesIO(msg.to_bytes()))
        self.assertRaises(ProtocolError,
                          Hello.from_stream, io.BytesIO(b'\x00\x11'))


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
        self.assertRaises(ProtocolError, HandShake, **{'cipher':[]})
        self.assertRaises(ProtocolError, HandShake, **{'cipher':fuzzing.XOR(0x11)})
        msg = HandShake(cipher=fuzzing.CipherChain([]))
        b = msg.to_bytes()
        self.assertRaises(ProtocolError, HandShake.from_stream, io.BytesIO(b))

    def test_custom(self):
        cipher=fuzzing.CipherChain([fuzzing.XOR(0x11)])
        msg = HandShake(cipher=cipher)
        msg1 = HandShake.from_stream(io.BytesIO(msg.to_bytes()))
        self.assertEqual(msg.to_bytes(), msg1.to_bytes())
