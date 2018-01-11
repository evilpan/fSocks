from .codec import Plain, Base16, Base32, Base64,\
    Base85, XXencode, UUencode
from .xor import XOR


__all__ = ['Plain', 'Base16', 'Base32', 'Base64',
           'Base85', 'XXencode', 'UUencode', 'XOR']


ALL_CIPHERS = {
    # codec
    0x00: Plain,
    0x01: Base64,
    0x02: Base32,
    0x03: Base16,
    0x04: Base85,
    0x05: XXencode,
    0x06: UUencode,
    # symmetric
    0x70: XOR,
}
