import sys
import inspect
from .base import FuzzChain
from .codec import Plain, Base16, Base32, Base64,\
    Base85, XXencode, UUencode, AtBash
from .symmetric import XOR, RailFence


def available_fuzz():
    flist = []
    this_module = sys.modules[__name__]
    for name, obj in inspect.getmembers(this_module):
        if name != 'FuzzChain' and inspect.isclass(obj):
            flist.append(obj())
    return flist
