# This is a random thought about shadowsocks

Currently, user always making many connections to client(mainly HTTP(S)),
and client makes many connections to server, and then server makes many connections to remote.
Connection itself is not expensive for performance, and modern CPU can handle 100K
concurrent connections easily, However, it introduced additional delay, especially when
server is usually located far away from client.
What if `client <--> server` only maintain one single TCP connection and use it
for all the stream data?

```
+------+       +------+                +------+       +------+
|      | <---> |      |                |      | <---> |      |
| user | <---> |client| <<--TUNNEL-->> |server| <---> |remote|
|      | <---> |      |                |      | <---> |      |
+------+       +------+                +------+       +------+
```

This may save considerable time, however it increase the code complexity since
the client and server have to associate corresponding user with remote server,
and current protocol need to changed too.

pro:

- less connection delay
- TUNNEL can be protocol independent

con:

- client and server have to handle peer connection in application layer
- trafiic of single connection may be limited by domain controller
