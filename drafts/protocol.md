# flow of connection

1. UA send CONNECT to client.
2. client send handshake to server
3. server respond handshake to client
4. [x] clinet send CONNECT to server
5. [x] client forward data between UA and server

# format of handshake message

the handshake message is responsible for:

1) authorization
2) chosing a cipher
