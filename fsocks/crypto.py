#!/usr/bin/env python3


def xor_codec(data, key=0x26):
    result = b''
    for b in data:
        b = b ^ key
        result += chr(b).encode()
    assert len(data) == len(result)
    return result


def encrypt(data):
    #return xor_codec(data)
    return data


def decrypt(data):
    #return xor_codec(data)
    return data
