# netflow_parser
A netflow_parser for V5, V7, V9, V10, IPFIX.

# Example:

## V5:

```
use netflow_parser::NetflowParser;

let v5_packet = [5, 1, 2...];
match NetflowParser::try_from_bytes(&v5_packet) {
    Ok(NetflowParser::V5(v5)) => {
        assert_eq!(v5.header.version, 5);
    }
    ...
}


```
