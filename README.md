## socks5
implement the socks5 server by SSL protocol.
cmd: `./bin/socks5 -p 8000`
socks5 server bind port 8000 to listen ssl connection.

## test
implement ssl tunnel.
cmd:`./vpn_client -l 8090 -h 127.0.0.1 -p 8000`
in the client point listen port 8090. receive data from connection to 8090, transfer all data to server.

## hijack client socket connect by tsocks

## treat local 8090 as socks server.