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

> step 2/3 only happen once at connection setup.
> step 4/5 may happen from time to time in one tunnel connection.

## user connection
0. user greeting with client.
1. user send SOCKS5 reuqest to client.
2. client send REQUEST to server
3. server connect to remote.
4. server response to client.
5. client begin forward data between user and server using. (RELAYING)
6. disconnect from any peer.


# protocol detail

Basicly, all messages format are as follow:
```
+----------+---------+----------+
| ENC.TYPE | ENC.LEN | ENC.DATA |
+----------+---------+----------+
|    2     |    4    | variable |
+----------+---------+----------+
```

- ENC.TYPE: encrypt type can be encrypt or fuzzing, see below
- ENC.LEN: encrypted/encoded data length
- ENC.DATA: encrypted/encoded data content, vary from MTYPE

before connection is established, `ENC.DATA` is encrypted
using pre shared password and method, such as HELLO, HANDSHAKE.
after connection is established, `ENC.DATA` is encoded
using negotiated cipher(s), such as REQUEST, REPLY and RELAYING.

choices of MTYPE:

- 0x01 HELLO: validating
- 0x02 HANDSHAKE: negociate for ciphers
- 0x03 REQUEST: new SOCKS5 request from client
- 0x04 REPLY: reply from server
- 0x05 RELAYING: relaying data between user and remote
- 0x06 CLOSE: connection closed by peer


## HELLO

the `ENC.DATA` part of HELLO message is as follow:
```
+---------+-------+-------+-----------+
|  MAGIC  | MTYPE | NONCE | TIMESTAMP |
+---------+-------+-------+-----------+
| X'1986' | X'01' |   4   |     8     |
+---------+-------+-------+-----------+
```
Request and response share the same format.

## HANDSHAKE

The HANDSHAKE message is responsible for negotiating cipher.
The `ENC.DATA` part of HANDSHAKE message is as follow:
```
+---------+-------+-------+-----------+----------+
|  MAGIC  | MTYPE | NONCE | TIMESTAMP | CIPHERS  |
+---------+-------+-------+-----------+----------+
| X'1986' | X'02' |   4   |     8     | variable |
+---------+-------+-------+-----------+----------+
```
Request and response share the same format.

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

## REQUEST
The `ENC.DATA` part of REQUEST message is as follow:
```
+---------+-------+-------+-------+---------------+
|  MAGIC  | MTYPE | NONCE | FROM  | SOCKS REQUEST |
+---------+-------+-------+-------+---------------+
| X'1986' | X'03' |   4   |   4   |    Variable   |
+---------+-------+-------+-------+---------------+
```

FROM is user identifier, such as socket.fileno.
SOCKS REQUEST is the same as RFC1928

## REPLY
The `ENC.DATA` part of REPLY message is as follow:
```
+---------+-------+-------+-------+--------------+
|  MAGIC  | MTYPE | NONCE | FROM  | SOCKS REPLY  |
+---------+-------+-------+-------+--------------+
| X'1986' | X'04' |   4   |   4   |   Variable   |
+---------+-------+-------+-------+--------------+
```

FROM is remote identifier, such as socket.fileno.
SOCKS REQUEST is the same as RFC1928

## RELAYING
The `ENC.DATA` part of RELAYING message is as follow:
```
+---------+-------+-------+------+-----+---------------+
|  MAGIC  | MTYPE | NONCE | FROM | TO  |     DATA      |
+---------+-------+-------+------+-----+---------------+
| X'1986' | X'05' |   4   |  4   |  4  |  varialble    |
+---------+-------+-------+------+-----+---------------+
```
FROM and TO are remote or user identifier respectively.

## CLOSE
The `ENC.DATA` part of CLOSE message is as follow:
```
+---------+-------+-------+-------+
|  MAGIC  | MTYPE | NONCE | FROM  |
+---------+-------+-------+-------+
| X'1986' | X'06' |   4   |   4   |
+---------+-------+-------+-------+
```
When client/server receive CLOSE message, he should known the associated peer
and inform it.

