use criterion::{criterion_group, criterion_main, Criterion};
use netflow_parser::NetflowParser;
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("netflow_ipfix bench", |b| {
        b.iter(|| {
            let ipfix_packet = [
                0, 10, 0, 64, 1, 2, 3, 4, 0, 0, 0, 0, 1, 2, 3, 4, 0, 2, 0, 20, 1, 0, 0, 3, 0,
                8, 0, 4, 0, 12, 0, 4, 0, 2, 0, 4, 1, 0, 0, 28, 1, 2, 3, 4, 1, 2, 3, 3, 1, 2, 3,
                2, 0, 2, 0, 2, 0, 1, 2, 3, 4, 5, 6, 7,
            ];
            NetflowParser::default().parse_bytes(black_box(&ipfix_packet));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
