import sys
import inspect
from .base import CipherChain
from .codec import Plain, Base16, Base32, Base64,\
    Base85, XXencode, UUencode, AtBash
from .integer_key import XOR, RailFence


def cipher_list():
    clist = []
    this_module = sys.modules[__name__]
    for name, obj in inspect.getmembers(this_module):
        if name != 'CipherChain' and inspect.isclass(obj):
            clist.append(obj())
    return clist
