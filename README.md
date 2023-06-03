# netflow_parser
A netflow_parser library for V5, V7, V9, V10, IPFIX written in Rust.

# Example:

## V5:

```rust
use netflow_parser::NetflowParser;

let v5_packet = [5, 1, 2...];
match NetflowParser::try_from_bytes(&v5_packet) {
    Ok(NetflowParser::V5(v5)) => {
        assert_eq!(v5.header.version, 5);
    }
    ...
}


```
