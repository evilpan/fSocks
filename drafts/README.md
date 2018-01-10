# fSocks

# How it works?

For every CONNECT request from SOCKS, we do:

1) negotiate with server using username/password
2) when succeeded, get a random cipher from server
3) use this cipher to fuzzy the following TCP streams

## encryption

In step(1), we MUST encrypt the username/password, in a way that
even some evil man in the middle capture the packet, they **CAN NOT**:

- restore the plain text infomation from the packet
- replay the negotiation using the packet

## fuzzy

We assume that most of the websites supported HTTPS at precent,
therefor strong encryption for streams is unnecessary and we just
do some simple fuzzy such as xor mapping to avoid keyword detection.
However, it's hackable, and you can roll your own quite easily.


## considerations

- [ ] Do we need SSL for step(1)?
- [x] Prevent idle TCP connection(using timeout)
- [x] Prevent brute force attack(blacklist ip manually/automaticly)


## available ciphers

### codec

- [x] base64/32/16/85
- [x] XXEncode
- [x] UUEncode

### symmetric

- [x] XOR
- [ ] Rail-Fence Cipher
- [ ] Curve Cipher
- [ ] Columnar Transposition Cipher
- [ ] Atbash Cipher
- [ ] Caesar Cipher
- [ ] Vigenère Cipher
- [ ] Autokey Cipher
- [ ] Beaufort Cipher
- [ ] Running Key Cipher
- [ ] ROT5/13/18/47
- [ ] Simple Substitution Cipher
- [ ] Hill Cipher
- [ ] Pigpen Cipher
- [ ] Polybius Square Cipher
- [ ] ADFGX Cipher
- [ ] Playfair Cipher
- [ ] Porta Cipher
- [ ] Homophonic Substitution Cipher
- [ ] Affine Cipher
- [ ] Baconian Cipher
- [ ] Bifid Cipher
- [ ] Trifid Cipher
- [ ] Four-Square Cipher
- [ ] Checkerboard Cipher
- [ ] Straddle Checkerboard Cipher
- [ ] Fractionated Morse Cipher
- [ ] Bazeries Cipher
- [ ] Digrafid Cipher
- [ ] Beale Cipher

- to be more ...
