use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use netflow_parser::NetflowParser;

// Create a channel, spawn thread, loop and listen for data, function returns sender
fn create_thread() -> Sender<Vec<u8>> {
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();

    // Using default configuration. For custom configuration, use the builder pattern:
    //
    // use netflow_parser::variable_versions::ttl::TtlConfig;
    // let mut parser = NetflowParser::builder()
    //     .with_cache_size(2000)
    //     .with_ttl(TtlConfig::packet_based(100))
    //     .build()
    //     .expect("Failed to build parser");
    let mut parser = NetflowParser::default();

    thread::spawn(move || {
        loop {
            if let Ok(data) = rx.recv() {
                for packet in parser.iter_packets(data.as_slice()) {
                    println!("{:?}", packet);
                }
            }
        }
    });
    tx
}

fn main() {
    let mut senders = HashMap::new();

    loop {
        // Read from Socket
        let socket = UdpSocket::bind("127.0.0.1:9995").expect("couldn't bind to address");
        let mut buf = [0; 65_535];
        let (number_of_bytes, src_addr) =
            socket.recv_from(&mut buf).expect("Didn't receive data");
        let filled_buf = &mut buf[..number_of_bytes];

        // Get or insert new sender based on src_addr (Router) key
        senders.entry(src_addr).or_insert_with(create_thread);

        let _ = senders.get(&src_addr).unwrap().send(filled_buf.to_vec());
    }
}
