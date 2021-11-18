# Member protocol notes

## Protocols and their negotiation

Hazelcast uses
* either the **default networking**, where the member accepts all protocol types (member, client, http, memcache) on one port
(see [UnifiedProtocolDecoder](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/server/tcp/UnifiedProtocolDecoder.java)
and [UnifiedProtocolEncoder](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/server/tcp/UnifiedProtocolEncoder.java));
* or the **advanced networking*** where only a single protocol is expected/allowed on the configured port number
(see [SingleProtocolDecoder](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/server/tcp/SingleProtocolDecoder.java)
and [SingleProtocolEncoder](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/server/tcp/SingleProtocolEncoder.java))

The decision which protocol should be used on the connection-acceptor side is based on the first 3 bytes sent from the connection-initiator side.
Let's call these bytes the **Protocol header**.

### Handling Unexpected protocol header

When the first 3 bytes received are not recogized as a valid protocol header by the acceptor, the behavior depends on networking type used:

#### Default networking

Connection is closed by the acceptor immediately.

See [UnifiedProtocolDecoder](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/server/tcp/UnifiedProtocolDecoder.java#L129-L130)

// TODO Consider creating issue to change the behavior and align it with the advanced's *unexpected protocol reply*

#### Advanced networking
If an unexpected protocol header is received by the acceptor, then the acceptor replies with the **unexpected protocol reply** (3-bytes: `"HZX"`).
This behavior was introduced in Hazelcast 5.

See [Protocols#UNEXPECTED_PROTOCOL](https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/nio/Protocols.java#L52)


## Member protocol negotiation

```
Initiator            Acceptor

HZC          -->                   (3-bytes protocol header)
             <--     HZC           (member-protocol reply accepting the protocol)
```



* https://github.com/hazelcast/hazelcast/blob/v5.0/hazelcast/src/main/java/com/hazelcast/internal/nio/Packet.java#L41-L104