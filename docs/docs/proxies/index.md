---
title: Proxies
sidebar_position: 1
---

# Proxies

httpcloak speaks HTTP CONNECT, SOCKS5, SOCKS5 with UDP, and MASQUE. Pick the one that fits your upstream and your protocol mix.

## In this section

- [Overview](./overview): when to use what, the proxy types we support, what each one solves
- [HTTP CONNECT](./http-connect): classic CONNECT proxy, plain HTTPS tunneling
- [SOCKS5](./socks5): SOCKS5 with auth, the residential-provider workhorse
- [SOCKS5 UDP](./socks5-udp): SOCKS5 UDP ASSOCIATE for HTTP/3 over QUIC
- [MASQUE](./masque): HTTP/3 CONNECT-UDP, tunneling QUIC inside QUIC
- [Source Address Binding](./source-address-binding): pick which local IP every dial uses
