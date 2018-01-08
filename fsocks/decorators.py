#!/usr/bin/env python3
from functools import wraps
from fsocks.net import SocketError
from fsocks.socks import ProxyError


def silent_close(func, fd):
    @wraps(func)
    def func_wrapper(*args, **kwargs):
        result = None
        try:
            result = func(*args, **kwargs)
        except (SocketError, ProxyError) as e:
            logger.warn(e)
            fd.close()
        return result
    return func_wrapper
