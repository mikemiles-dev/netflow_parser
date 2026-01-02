use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use netflow_parser::variable_versions::ttl::TtlConfig;
use netflow_parser::{NetflowParser, RouterScopedParser};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Create a RouterScopedParser with custom configuration
    // This automatically manages separate template caches per source address
    let builder = NetflowParser::builder()
        .with_cache_size(2000)
        .with_ttl(TtlConfig::new(Duration::from_secs(3600)));

    let parser = Arc::new(Mutex::new(RouterScopedParser::<SocketAddr>::with_builder(
        builder,
    )));

    let sock = UdpSocket::bind("0.0.0.0:9995").await?;
    let mut buf = [0; 65535];

    // Counters for metrics
    let successful_packets = Arc::new(AtomicU64::new(0));
    let failed_packets = Arc::new(AtomicU64::new(0));

    // Spawn metrics reporter task with enhanced template cache metrics
    let parser_clone = parser.clone();
    let successful_clone = successful_packets.clone();
    let failed_clone = failed_packets.clone();
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let success = successful_clone.load(Ordering::Relaxed);
            let failed = failed_clone.load(Ordering::Relaxed);

            println!("\n=== Metrics Report ===");
            println!("Packets - Success: {}, Failed: {}", success, failed);

            // Get template cache statistics per source
            let parser_lock = parser_clone.lock().await;
            let source_count = parser_lock.source_count();
            println!("Active sources: {}", source_count);

            if source_count > 0 {
                println!("\nPer-Source Template Cache Stats:");
                for (source, v9_stats, ipfix_stats) in parser_lock.all_stats() {
                    println!("\n  Source: {}", source);

                    // V9 stats
                    println!(
                        "    V9 Cache: {}/{} templates",
                        v9_stats.current_size, v9_stats.max_size
                    );
                    let v9_metrics = &v9_stats.metrics;
                    if let Some(hit_rate) = v9_metrics.hit_rate() {
                        println!(
                            "      Hit rate: {:.1}%, Hits: {}, Misses: {}",
                            hit_rate * 100.0,
                            v9_metrics.hits,
                            v9_metrics.misses
                        );
                    }
                    if v9_metrics.collisions > 0 {
                        println!("      ⚠️  Collisions: {}", v9_metrics.collisions);
                    }

                    // IPFIX stats
                    println!(
                        "    IPFIX Cache: {}/{} templates",
                        ipfix_stats.current_size, ipfix_stats.max_size
                    );
                    let ipfix_metrics = &ipfix_stats.metrics;
                    if let Some(hit_rate) = ipfix_metrics.hit_rate() {
                        println!(
                            "      Hit rate: {:.1}%, Hits: {}, Misses: {}",
                            hit_rate * 100.0,
                            ipfix_metrics.hits,
                            ipfix_metrics.misses
                        );
                    }
                    if ipfix_metrics.collisions > 0 {
                        println!("      ⚠️  Collisions: {}", ipfix_metrics.collisions);
                    }
                }
            }
            println!("======================\n");
        }
    });

    println!("NetFlow UDP listener started on 0.0.0.0:9995");
    println!("Using RouterScopedParser for automatic per-source template isolation\n");

    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;

        // Parse using RouterScopedParser - automatically handles per-source template caching
        let parser_clone = parser.clone();
        let data = buf[..len].to_vec();
        let successful = successful_packets.clone();
        let failed = failed_packets.clone();

        // Spawn task to parse without blocking the receive loop
        tokio::spawn(async move {
            let mut parser_lock = parser_clone.lock().await;

            // Parse packets from this source
            let count = parser_lock.iter_packets_from_source(addr, &data).count() as u64;

            if count > 0 {
                successful.fetch_add(count, Ordering::Relaxed);
            } else {
                failed.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}
