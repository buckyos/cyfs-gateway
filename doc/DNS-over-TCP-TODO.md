# TODO: support DNS-over-TCP through the normal `server` route

## Goal

Make the following stack configuration work without a DNS-specific command or an
extra upstream process:

```yaml
dns_tcp:
  protocol: tcp
  bind: 0.0.0.0:53
  hook_point:
    main:
      blocks:
        default:
          block: |
            return "server main_dns";
```

`main_dns` must remain one logical DNS server. The stack protocol determines
whether it is invoked through its datagram or stream interface, so the matching
UDP configuration continues to use exactly the same `return "server main_dns"`
syntax.

## Required changes

- Add a `StreamServer` adapter for `ProcessChainDnsServer` and register both
  `Server::Datagram` and `Server::Stream` under the same server ID.
- Implement DNS-over-TCP framing as specified by RFC 1035: read a two-byte
  unsigned big-endian message length, read exactly that many DNS message bytes,
  resolve them through the existing DNS process chain, then write a two-byte
  response length followed by the response bytes.
- Process multiple framed requests on one TCP connection until clean EOF. Reject
  zero-length, incomplete, or oversized frames without interpreting arbitrary
  TCP read chunks as DNS packets.
- Pass the actual transport into the shared DNS request handler. TCP responses
  must not be limited to the UDP/EDNS payload size or incorrectly set `TC`
  merely because the response is larger than a UDP packet; enforce the DNS-over-
  TCP 65,535-byte message limit instead.
- Preserve the TCP connection's source and destination addresses when populating
  DNS request/process-chain context.
- Make `return "server <id>"` dispatch deterministic when one logical server ID
  exposes multiple traits. A TCP stack must select a compatible `StreamServer`
  (while retaining existing HTTP behavior), and a UDP stack must select the
  corresponding `DatagramServer`; do not use the arbitrary first match returned
  by `ServerManager::get_server()`.
- Define clean connection behavior for malformed frames, handler errors, client
  half-close, write failure, and idle timeout, with useful debug/warning logs and
  no busy loop.

## Acceptance criteria

- TCP and UDP stacks can bind `0.0.0.0:53` simultaneously and both route to
  `main_dns` using `return "server main_dns"`.
- A, AAAA, TXT, NXDOMAIN, NODATA, and SERVFAIL queries return equivalent DNS
  results over UDP and TCP, except for transport-appropriate truncation.
- A response too large for the client's UDP payload is truncated over UDP and
  succeeds in full when the client retries over TCP.
- Two sequential DNS queries on one TCP connection both receive correctly
  framed responses, including when frame bytes arrive across multiple TCP
  reads.
- Co-registering the stream and datagram implementations under `main_dns` never
  causes nondeterministic `unsupported server type` errors.
- Integration tests exercise the YAML configuration shown above rather than
  calling the DNS handler directly.

## Relevant code

- `src/components/cyfs-dns/src/dns_server.rs`: DNS request handling and server
  factory; currently exposes only `DatagramServer` and always constructs requests
  with `Protocol::Udp`.
- `src/components/cyfs-gateway-lib/src/stack/tcp_stack.rs`: TCP `server` route;
  currently accepts only HTTP/stream server variants selected through the generic
  server lookup.
- `src/components/cyfs-gateway-lib/src/stack/udp_stack.rs`: UDP `server` route and
  datagram dispatch.
- `src/components/cyfs-gateway-lib/src/server/server.rs`: typed server registry;
  `get_server(id)` currently returns an arbitrary matching trait when an ID has
  more than one implementation.
