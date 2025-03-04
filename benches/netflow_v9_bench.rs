use criterion::{Criterion, criterion_group, criterion_main};
use netflow_parser::NetflowParser;
use std::hint::black_box;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("netflow_v9 bench", |b| {
        b.iter(|| {
            let v9_packet = [
                0, 9, 0, 2, 0, 0, 9, 9, 0, 1, 2, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 1, 2,
                0, 2, 0, 1, 0, 4, 0, 8, 0, 4, 1, 2, 0, 12, 9, 2, 3, 4, 9, 9, 9, 8,
            ];
            NetflowParser::default().parse_bytes(black_box(&v9_packet));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
