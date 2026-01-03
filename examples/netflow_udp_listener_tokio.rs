use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use netflow_parser::variable_versions::ttl::TtlConfig;
use netflow_parser::{AutoScopedParser, NetflowParser};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Create an AutoScopedParser with custom configuration
    // This automatically implements RFC-compliant template scoping:
    // - NetFlow v9: Uses (source_addr, source_id) per RFC 3954
    // - IPFIX: Uses (source_addr, observation_domain_id) per RFC 7011
    let builder = NetflowParser::builder()
        .with_cache_size(2000)
        .with_ttl(TtlConfig::new(Duration::from_secs(3600)));

    let parser = Arc::new(Mutex::new(AutoScopedParser::with_builder(builder)));

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
            println!("Total sources: {}", parser_lock.source_count());
            println!("  IPFIX sources: {}", parser_lock.ipfix_source_count());
            println!("  NetFlow v9 sources: {}", parser_lock.v9_source_count());
            println!("  Legacy sources: {}", parser_lock.legacy_source_count());

            // Show IPFIX sources with RFC-compliant scoping
            let ipfix_sources = parser_lock.ipfix_stats();
            if !ipfix_sources.is_empty() {
                println!("\nIPFIX Sources (RFC 7011 scoping):");
                for (key, _v9_stats, ipfix_stats) in ipfix_sources {
                    println!(
                        "\n  {}  [Domain ID: {}]",
                        key.addr, key.observation_domain_id
                    );
                    println!(
                        "    Templates: {}/{} | Evictions: {}",
                        ipfix_stats.current_size,
                        ipfix_stats.max_size,
                        ipfix_stats.metrics.evictions
                    );
                    if let Some(hit_rate) = ipfix_stats.metrics.hit_rate() {
                        println!(
                            "    Hit rate: {:.1}% (Hits: {}, Misses: {})",
                            hit_rate * 100.0,
                            ipfix_stats.metrics.hits,
                            ipfix_stats.metrics.misses
                        );
                    }
                    if ipfix_stats.metrics.collisions > 0 {
                        println!("    ⚠️  Collisions: {}", ipfix_stats.metrics.collisions);
                    }
                }
            }

            // Show NetFlow v9 sources with RFC-compliant scoping
            let v9_sources = parser_lock.v9_stats();
            if !v9_sources.is_empty() {
                println!("\nNetFlow v9 Sources (RFC 3954 scoping):");
                for (key, v9_stats, _ipfix_stats) in v9_sources {
                    println!("\n  {}  [Source ID: {}]", key.addr, key.source_id);
                    println!(
                        "    Templates: {}/{} | Evictions: {}",
                        v9_stats.current_size, v9_stats.max_size, v9_stats.metrics.evictions
                    );
                    if let Some(hit_rate) = v9_stats.metrics.hit_rate() {
                        println!(
                            "    Hit rate: {:.1}% (Hits: {}, Misses: {})",
                            hit_rate * 100.0,
                            v9_stats.metrics.hits,
                            v9_stats.metrics.misses
                        );
                    }
                    if v9_stats.metrics.collisions > 0 {
                        println!("    ⚠️  Collisions: {}", v9_stats.metrics.collisions);
                    }
                }
            }

            // Show legacy sources (v5/v7)
            let legacy_sources = parser_lock.legacy_stats();
            if !legacy_sources.is_empty() {
                println!("\nLegacy Sources (NetFlow v5/v7):");
                for (addr, v9_stats, _ipfix_stats) in legacy_sources {
                    println!("\n  {}", addr);
                    println!(
                        "    Templates: {}/{}",
                        v9_stats.current_size, v9_stats.max_size
                    );
                }
            }
            println!("======================\n");
        }
    });

    println!("NetFlow UDP listener started on 0.0.0.0:9995");
    println!("Using AutoScopedParser for RFC-compliant template scoping");
    println!("- IPFIX: (source_addr, observation_domain_id) per RFC 7011");
    println!("- NetFlow v9: (source_addr, source_id) per RFC 3954\n");

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
