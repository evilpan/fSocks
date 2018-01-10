fSocks
===

fSocks is a new version of fuzzy SOCKS proxy to bypass middlewares
like firewall. It's intented to be highly customisable.

**CURRENTLY WORKING IN PROGRESS**

# RUN

## on your local machine

```
python3 fclient.py -c config.json
```

## beyond the wall

```
python3 fserver.py -c config.json
```

# TODO

- [ ] Handshake for the first CONNECT request
- [ ] Using event loop instead of one connection per thread
- [ ] Complete unit tests with coverage

# drafts

For more infomation, please refer to [the drafts](drafts)

