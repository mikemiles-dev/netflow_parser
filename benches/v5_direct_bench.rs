use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use netflow_parser::NetflowParser;
use netflow_parser::static_versions::v5::V5;
use std::hint::black_box;

/// Helper to create V5 packet with N flow records (includes version header)
fn create_v5_packet(flow_count: u16) -> Vec<u8> {
    let mut packet = vec![
        0x00,
        0x05, // Version 5
        (flow_count >> 8) as u8,
        (flow_count & 0xFF) as u8, // Count
        0x03,
        0x00,
        0x04,
        0x00, // SysUptime
        0x05,
        0x00,
        0x06,
        0x07, // Unix seconds
        0x08,
        0x09,
        0x00,
        0x01, // Unix nsecs
        0x02,
        0x03,
        0x04,
        0x05, // Sequence
        0x06,
        0x07,
        0x08,
        0x09, // Engine type/id + sampling
    ];

    // Each V5 flow record is 48 bytes
    let flow_record = [
        0x0A, 0x00, 0x00, 0x01, // src_addr
        0x0A, 0x00, 0x00, 0x02, // dst_addr
        0x00, 0x00, 0x00, 0x00, // next_hop
        0x00, 0x01, 0x00, 0x02, // input/output
        0x00, 0x00, 0x00, 0x0A, // d_pkts
        0x00, 0x00, 0x05, 0x00, // d_octets
        0x00, 0x00, 0x00, 0x01, // first
        0x00, 0x00, 0x00, 0x02, // last
        0x00, 0x50, 0x00, 0x51, // src_port/dst_port
        0x00, 0x06, 0x06, 0x00, // pad1/tcp_flags/protocol/tos
        0x00, 0x01, 0x00, 0x02, // src_as/dst_as
        0x18, 0x18, 0x00, 0x00, // src_mask/dst_mask/pad2
    ];

    for _ in 0..flow_count {
        packet.extend_from_slice(&flow_record);
    }

    packet
}

fn bench_v5_direct(c: &mut Criterion) {
    let mut group = c.benchmark_group("V5 direct parse");

    for flow_count in [1u16, 10, 30, 100] {
        let packet = create_v5_packet(flow_count);
        // Skip the 2-byte version header (simulating GenericNetflowHeader already consumed it)
        let after_version = &packet[2..];
        let size = packet.len();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("parse_direct", format!("{} flows", flow_count)),
            after_version,
            |b, data| {
                b.iter(|| {
                    let _ = V5::parse_direct(black_box(data));
                });
            },
        );
    }

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("V5 full pipeline (with version dispatch)");

    for flow_count in [1u16, 10, 30, 100] {
        let packet = create_v5_packet(flow_count);
        let size = packet.len();

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("current", format!("{} flows", flow_count)),
            &packet,
            |b, data| {
                let mut parser = NetflowParser::default();
                b.iter(|| {
                    let _ = parser.parse_bytes(black_box(data));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_v5_direct, bench_full_pipeline);
criterion_main!(benches);
