use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

use netflow_parser::NetflowParser;

fn main() {
    // Map for Parsers
    let mut parsers: HashMap<SocketAddr, NetflowParser> = HashMap::new();

    loop {
        // Read from Socket
        let socket = UdpSocket::bind("127.0.0.1:9995").expect("couldn't bind to address");
        let mut buf = [0; 65_535];
        let (number_of_bytes, src_addr) =
            socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = &mut buf[..number_of_bytes];

        // Fetch Parser by src_addr or insert new parser for src_addr and process bytes
        let parser = parsers.entry(src_addr).or_insert_with(NetflowParser::default);

        for packet in parser.iter_packets(filled_buf) {
            println!("{:?}", packet);
        }
    }
}
