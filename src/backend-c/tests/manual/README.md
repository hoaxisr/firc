# Manual checks

Checks that need a real kernel and are not part of `make test`. Run them by
hand when the code they cover changes.

## The capture's read path

`e2e_run.sh` runs the capture's read path (the NFLOG socket, the message
walk, the packet parse and the ClientHello parser) against a live kernel,
without root, inside a private network namespace. It needs `unshare`,
`openssl` and `socat`. From `src/backend-c/`:

```sh
gcc -std=c11 -D_POSIX_C_SOURCE=200809L -Iinclude -o tests/manual/e2e_nflog \
    tests/manual/e2e_nflog.c \
    src/tap/nflog.c src/tap/nflog_sock.c src/tap/packet.c src/tap/clienthello.c \
    src/netlink/nlattr_iter.c src/logging/log.c src/util/err.c
unshare -Urn sh tests/manual/e2e_run.sh
```

A passing run prints both ClientHellos with their SNI, lower-cased:

```
bound group 42, range 300
packet 1: 300 bytes delivered
  203.0.113.1 -> 203.0.113.1:443, 248 bytes after TCP
  SNI=bypass.example.com
packet 2: 300 bytes delivered
  SNI=upper.example.com
```

## The capture on a router

With `fircd` running on the router, drive the capture over the API socket
(`socat` ships as a package dependency):

```sh
req() {
    printf '%s /api/v1/%s HTTP/1.1\r\nHost: firc\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
        "$1" "$2" "${#3}" "$3" | socat - UNIX-CONNECT:/tmp/firc/firc.sock
}

req POST 'system/capture' ''            # the answer carries the token
req GET  'system/events?since=0' ''     # kind=bypass events land here
req DELETE 'system/capture?token=<token>' ''
```

The socket needs no login; over the WebUI's HTTP port the same routes need
a bearer token.
