use netflow_parser::NetflowParser;
use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

fn v9_template_packet() -> Vec<u8> {
    vec![
        0x00,
        0x09,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x20,
        0x01,
        0x00,
        0x00,
        0x06,
        0x00,
        0x08,
        0x00,
        0x04,
        0x00,
        0x0C,
        0x00,
        0x04,
        0x00,
        0x07,
        0x00,
        0x02,
        0x00,
        0x0B,
        0x00,
        0x02,
        0x00,
        0x01,
        0x00,
        0x04,
        0x00,
        0x02,
        0x00,
        0x04,
    ]
}

fn v9_data_packet(flow_count: u16) -> Vec<u8> {
    let record_size = 20u16;
    let data_length = 4 + flow_count * record_size;
    let mut packet = vec![
        0x00,
        0x09,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0x00,
        (data_length >> 8) as u8,
        (data_length & 0xFF) as u8,
    ];

    for i in 0..flow_count {
        let i_lo = (i & 0xFF) as u8;
        let i_hi = ((i >> 8) & 0xFF) as u8;
        packet.extend_from_slice(
            &[
                0x0A,
                0x00,
                i_hi,
                i_lo,
                0x0A,
                0x00,
                0x01,
                i_lo,
                0x00,
                0x50,
                0x01,
                0xBB,
                0x00,
                0x00,
                0x05,
                0x00,
                0x00,
                0x00,
                0x00,
                0x0A,
            ],
        );
    }

    packet
}

fn ipfix_template_packet() -> Vec<u8> {
    let set_length = 4 + 4 + 24;
    let total_length = 16 + set_length;
    vec![
        0x00,
        0x0A,
        (total_length >> 8) as u8,
        (total_length & 0xFF) as u8,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x02,
        (set_length >> 8) as u8,
        (set_length & 0xFF) as u8,
        0x01,
        0x00,
        0x00,
        0x06,
        0x00,
        0x08,
        0x00,
        0x04,
        0x00,
        0x0C,
        0x00,
        0x04,
        0x00,
        0x07,
        0x00,
        0x02,
        0x00,
        0x0B,
        0x00,
        0x02,
        0x00,
        0x01,
        0x00,
        0x04,
        0x00,
        0x02,
        0x00,
        0x04,
    ]
}

fn ipfix_data_packet(flow_count: u16) -> Vec<u8> {
    let record_size = 20u16;
    let data_set_length = 4 + flow_count * record_size;
    let total_length = 16u16 + data_set_length;
    let mut packet = vec![
        0x00,
        0x0A,
        (total_length >> 8) as u8,
        (total_length & 0xFF) as u8,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0x00,
        (data_set_length >> 8) as u8,
        (data_set_length & 0xFF) as u8,
    ];

    for i in 0..flow_count {
        let i_lo = (i & 0xFF) as u8;
        let i_hi = ((i >> 8) & 0xFF) as u8;
        packet.extend_from_slice(
            &[
                0x0A,
                0x00,
                i_hi,
                i_lo,
                0x0A,
                0x00,
                0x01,
                i_lo,
                0x00,
                0x50,
                0x01,
                0xBB,
                0x00,
                0x00,
                0x05,
                0x00,
                0x00,
                0x00,
                0x00,
                0x0A,
            ],
        );
    }

    packet
}

fn usage(binary: &str) -> String {
    format!("usage: {binary} <v9|ipfix> [iterations] [flows]")
}

fn main() -> ExitCode {
    let mut args = env::args();
    let binary = args.next().unwrap_or_else(|| "perf_hot_path".to_string());
    let protocol = match args.next() {
        Some(protocol) => protocol,
        None => {
            eprintln!("{}", usage(&binary));
            return ExitCode::FAILURE;
        }
    };

    let iterations = args.next()
        .as_deref()
        .map(str::parse::<usize>)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("invalid iterations: {e}");
            std::process::exit(2);
        })
        .unwrap_or(500_000);
    let flows = args.next()
        .as_deref()
        .map(str::parse::<u16>)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("invalid flows: {e}");
            std::process::exit(2);
        })
        .unwrap_or(1000);

    let (template, data) = match protocol.as_str() {
        "v9" => (v9_template_packet(), v9_data_packet(flows)),
        "ipfix" => (ipfix_template_packet(), ipfix_data_packet(flows)),
        _ => {
            eprintln!("{}", usage(&binary));
            return ExitCode::FAILURE;
        }
    };

    let mut parser = NetflowParser::default();
    let template_result = parser.parse_bytes(&template);
    if template_result.error.is_some() || template_result.packets.len() != 1 {
        eprintln!("failed to warm parser with template packet");
        return ExitCode::FAILURE;
    }

    let start = Instant::now();
    let mut packet_count = 0usize;
    let mut flow_count_total = 0usize;

    for _ in 0..iterations {
        let result = parser.parse_bytes(black_box(&data));
        if let Some(error) = result.error {
            eprintln!("parse error during run: {error}");
            return ExitCode::FAILURE;
        }
        packet_count += result.packets.len();
        flow_count_total += usize::from(flows);
        black_box(&result);
    }

    let elapsed = start.elapsed();
    println!(
        "protocol={protocol} iterations={iterations} flows_per_packet={flows} packets={packet_count} flows={flow_count_total} elapsed_ms={}",
        elapsed.as_millis()
    );

    ExitCode::SUCCESS
}
