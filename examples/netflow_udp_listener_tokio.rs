use std::collections::HashMap;
use std::io;
use tokio::net::UdpSocket;

use netflow_parser::NetflowParser;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut parsers: HashMap<String, NetflowParser> = HashMap::new();

    let sock = UdpSocket::bind("0.0.0.0:9995").await?;

    let mut buf = [0; 65535];

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        let data = buf[..len].to_vec();
        let data = data.as_slice();

        let result = match parsers.get_mut(&addr.to_string()) {
            Some(parser) => parser.parse_bytes(data),
            None => {
                let mut new_parser = NetflowParser::default();
                let result = new_parser.parse_bytes(data);
                parsers.insert(addr.to_string(), new_parser);
                result
            }
        };
        println!("{:?}", result);
    }
}
