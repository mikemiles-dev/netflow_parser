use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::time::{Duration, interval};

use netflow_parser::NetflowParser;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut parsers: HashMap<String, NetflowParser> = HashMap::new();

    let sock = UdpSocket::bind("0.0.0.0:9995").await?;

    let mut buf = [0; 65535];

    // Counters for metrics
    let successful_packets = Arc::new(AtomicU64::new(0));
    let failed_packets = Arc::new(AtomicU64::new(0));

    // Spawn metrics reporter task
    let successful_clone = successful_packets.clone();
    let failed_clone = failed_packets.clone();
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let success = successful_clone.load(Ordering::Relaxed);
            let failed = failed_clone.load(Ordering::Relaxed);
            println!(
                "[Metrics] Successful packets: {}, Failed packets: {}",
                success, failed
            );
        }
    });

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        let data = buf[..len].to_vec();
        let data = data.as_slice();

        let parser = parsers
            .entry(addr.to_string())
            .or_insert_with(NetflowParser::default);

        // Count packets using iter API
        let mut count = 0;
        for _packet in parser.iter_packets(data) {
            count += 1;
        }

        if count > 0 {
            successful_packets.fetch_add(count, Ordering::Relaxed);
        } else {
            // If no packets were parsed from the data, count it as a failure
            failed_packets.fetch_add(1, Ordering::Relaxed);
        }
    }
}
