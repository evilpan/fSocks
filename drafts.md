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

[ ] Do we need SSL for step(1)?
[x] Prevent idle TCP connection(using timeout)
[x] Prevent brute force attack(blacklist ip manually/automaticly)
