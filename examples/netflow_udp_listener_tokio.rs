use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};

use netflow_parser::NetflowParser;

// Create a processing task for a source address
fn create_processor_task(
    successful_packets: Arc<AtomicU64>,
    failed_packets: Arc<AtomicU64>,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

    tokio::spawn(async move {
        let mut parser = NetflowParser::default();

        while let Some(data) = rx.recv().await {
            // Count packets using iter API
            let count = parser.iter_packets(&data).count() as u64;

            if count > 0 {
                successful_packets.fetch_add(count, Ordering::Relaxed);
            } else {
                // If no packets were parsed from the data, count it as a failure
                failed_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    tx
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut senders: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();

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

        // Get or create sender for this source address
        let sender = senders.entry(addr).or_insert_with(|| {
            create_processor_task(successful_packets.clone(), failed_packets.clone())
        });

        // Send data to the processor task (only copy when sending to task)
        // If send fails, the task has been dropped, so we can ignore the error
        let _ = sender.send(buf[..len].to_vec()).await;
    }
}
