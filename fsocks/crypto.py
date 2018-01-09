#!/usr/bin/env python3


def xor_codec(data, key=0x26):
    source = bytearray(data)
    result = bytearray()
    for b in source:
        b = b ^ key
        result.append(b)
    result = bytes(result)
    assert len(data) == len(result)
    return result


def encrypt(data):
    return xor_codec(data)


def decrypt(data):
    return xor_codec(data)
