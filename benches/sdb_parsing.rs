use criterion::{black_box, criterion_group, criterion_main, Criterion};
use leybold_opc_rs::sdb;

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("read_sdb_file", |b| {
        b.iter(|| black_box(sdb::read_sdb_file()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
