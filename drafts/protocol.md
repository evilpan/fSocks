# participants

- user: user agent(such as browser or application) that using fclient as SOCKS5 proxy
- client: fclient running on local machine
- server: fserver running beyond the fiewall
- remote: remote server that user want to communicate with

here is the dataflow:

```
+------+       +------+                +------+       +------+
|      | <---> |      |                |      | <---> |      |
| user | <---> |client| <<--TUNNEL-->> |server| <---> |remote|
|      | <---> |      |                |      | <---> |      |
+------+       +------+                +------+       +------+
```

# workflow

## starup
0. server start
1. client start
2. client send HELLO request to server
3. server respond HELLO to client (with server nonce)
4. client send encrypt(nonce|ciphers) to server (HANDSHAKE).
5. server respond with encrypt(nonce|cipher), (HANDSHAKE).

> step 4/5 may happen in variable interval.

## user connection
0. user greeting with client.
1. user send SOCKS5-CONNECT reuqest to client.
2. client send CONNECT to server
3. server connect to remote.
4. server response to client.
5. client begin forward data between user and server using. (RELAYING)
6. disconnect from any peer.


# protocol detail

Basicly, all messages format are as follow:
```
+-----+-------+---------+-----------+
|MTYPE|  RSV  | ENC.LEN | ENC.DATA  |
+-----+-------+---------+-----------+
|  1  | X'00' |    4    | Variable  |
+-----+-------+---------+-----------+
```

- MTYPE: message type
- RSV: reserved
- ENC.LEN: encrypted/encoded data length
- ENC.DATA: encrypted/encoded data content, vary from MTYPE

choices of MTYPE:

- 0x00 HELLO: validating
- 0x01 HANDSHAKE: negociate for ciphers
- 0x02 CONNECT: new connection from user to remote
- 0x03 RELAYING: relaying data between user and remote


before connection is established, `ENC.DATA` is encrypted
using pre shared password and method, such as HELLO, HANDSHAKE.
after connection is established, `ENC.DATA` is encoded
using negotiated cipher(s), such as CONNECT, RELAYING.


## HELLO

the `ENC.DATA` part of HELLO message is as follow:
```
+-------+-------+-----------+
| MAGIC | NONCE | TIMESTAMP |
+-------+-------+-----------+
|   4   |   4   |     8     |
+-------+-------+-----------+
```

- MAGIC: const value: 0x2110242
- NONCE: random number
- TIMESTAMP: client/server timestamp in seconds

## HANDSHAKE

The HANDSHAKE message is responsible for negotiating cipher.
The `ENC.DATA` part of HANDSHAKE message is as follow:
```
+-------+-------+-----------+----------+
| MAGIC | NONCE | TIMESTAMP | CIPHERS  |
+-------+-------+-----------+----------+
|   4   |   4   |     8     | variable |
+-------+-------+-----------+----------+
```

CIPHER can be chained to perform diverse fuzzing,
format of each CIPHER:
```
+----+-----+
| ID | KEY |
+----+-----+
| 2  |  4  |
+----+-----+
```

- ID: cipher id, from 0x0000 - 0xFFFE, 0xFFFF meams end of ciphers.
- KEY: cipher key, may be zero.

All ciphers are designed to accept a 4-byte integer as initial key.

## CONNECT
The `ENC.DATA` part of CONNECT message is as follow:
```
+-------+-------+-------+------+----------+----------+
| MAGIC | NONCE | FROM  | ATYP | DST.ADDR | DST.PORT |
+-------+-------+-------+------+----------+----------+
|   4   |   4   |   4   | 1    | Variable |    2     |
+-------+-------+-------+------+----------+----------+
```

FROM is user identifier, such as socket.fileno.
The ATYPE, DST.ADDR and DST.PORT the same as SOCKS5 CONNECT message.

## RELAYING
The `ENC.DATA` part of RELAYING message is as follow:
```
+-------+-------+------+-----+---------------+
| MAGIC | NONCE | FROM | TO  |     DATA      |
+-------+-------+------+-----+---------------+
|   4   |   4   |  4   |  4  |  varialble    |
+-------+-------+------+-----+---------------+
```

FROM and TO are remote or user identifier respectively.
