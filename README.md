# netflow_parser

A Netflow Parser library for Cisco V5, V7, V9, IPFIX written in Rust.
Supports chaining of multple versions in the same stream.  ({v5 packet}, {v7packet}, {v5packet}, {v9packet}, etc.)

# References
See: <https://en.wikipedia.org/wiki/NetFlow>

# Description

## Example

### V5

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
match NetflowParser::default().parse_bytes(&v5_packet).first() {
    Some(NetflowPacket::V5(v5)) => assert_eq!(v5.header.version, 5),
    Some(NetflowPacket::Error(e)) => println!("{:?}", e),
    _ => (),
}
```

## Want Serialization such as JSON?
Structures fully support serialization.  Below is an example using the serde_json macro:
```rust
use serde_json::json;
use netflow_parser::NetflowParser;

let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
println!("{}", json!(NetflowParser::default().parse_bytes(&v5_packet)).to_string());
```

```json
[{"V5":{"header":{"count":1,"engine_id":7,"engine_type":6,"flow_sequence":33752069,"sampling_interval":2057,"sys_up_time":{"nanos":672000000,"secs":50332},"unix_nsecs":134807553,"unix_secs":83887623,"version":5},"sets":[{"d_octets":66051,"d_pkts":101124105,"dst_addr":"4.5.6.7","dst_as":515,"dst_mask":5,"dst_port":1029,"first":{"nanos":87000000,"secs":67438},"input":515,"last":{"nanos":553000000,"secs":134807},"next_hop":"8.9.0.1","output":1029,"pad1":6,"pad2":1543,"protocol_number":8,"protocol_type":"Egp","src_addr":"0.1.2.3","src_as":1,"src_mask":4,"src_port":515,"tcp_flags":7,"tos":9}]}}]
```

## Filtering for a specific version

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

let v5_packet = [0, 5, 2, 0, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,];
let parsed = NetflowParser::default().parse_bytes(&v5_packet);

let v5_parsed: Vec<NetflowPacket> = parsed.into_iter().filter(|p| p.is_v5()).collect();
```

## Netflow Common

For convenience we have included a `NetflowCommon` structure.  This will allow you to use common
Netflow fields without unpacking specific versions (fields like `src_port`, `dst_port`, etc.).  If the
packet flow does not have the matching field it will simply be left as `None`.

### Netflow Common fields:
```
src_addr: Option<IpAddr>,
dst_addr: Option<IpAddr>,
src_port: Option<u16>,
dst_port: Option<u16>,
protocol_number: Option<u8>,
protocol_type: Option<ProtocolTypes>,
first_seen: Option<u32>,
last_seen: Option<u32>,
```

```rust
use netflow_parser::{NetflowParser, NetflowPacket};

let v5_packet = [0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7];
let netflow_common = NetflowParser::default()
                     .parse_bytes(&v5_packet)
                     .first()
                     .unwrap()
                     .as_netflow_common()
                     .unwrap();

for common_flow in netflow_common.flowsets.iter() {
    println!("Src Addr: {} Dst Addr: {}", common_flow.src_addr.unwrap(), common_flow.dst_addr.unwrap());
}
```

## Re-Exporting flows

Netflow Parser now supports parsed V5, V7, V9, IPFix can be re-exported back into bytes.
```rust
let packet = [
    0, 5, 0, 1, 3, 0, 4, 0, 5, 0, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3,
    4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
    2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7,
];
if let NetflowPacket::V5(v5) = NetflowParser::default()
    .parse_bytes(&packet)
    .first()
    .unwrap()
{
    assert_eq!(v5.to_be_bytes(), packet);
}
```

## V9/IPFix notes:

Parse the data ('&[u8]' as any other versions.  The parser (NetflowParser) holds onto already parsed templates, so you can just send a header/data flowset combo and it will use the cached templates.)   To see cached templates simply use the parser for the correct version (v9_parser for v9, ipfix_parser for IPFix.)

```rust
use netflow_parser::NetflowParser;
let parser = NetflowParser::default();
dbg!(parser.v9_parser.templates);
dbg!(parser.v9_parser.options_templates);
```

To access templates flowset of a processed V9/IPFix flowset you can find the `flowsets` attribute on the Parsed Record.  In there you can find `Templates`, `Option Templates`, and `Data` Flowsets.

## Features

* `parse_unknown_fields` - When enabled fields not listed in this library will attempt to be parsed as a Vec of bytes and the field_number listed.  When disabled an error is thrown when attempting to parse those fields.  Enabled by default.

## Included Examples

Some examples has been included mainly for those who want to use this parser to read from a Socket and parse netflow.  In those cases with V9/IPFix it is best to create a new parser for each router.  There are both single threaded and multi-threaded examples in the examples directory.

To run:

```cargo run --example netflow_udp_listener_multi_threaded```

or 

```cargo run --example netflow_udp_listener_single_threaded```

or

```cargo run --example netflow_udp_listener_tokio```
