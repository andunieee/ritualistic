use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const EVENT_JSON: &str = r#"{"kind":1,"pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c","id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"}"#;

fn get_id(c: &mut Criterion) {
    c.bench_function("get_id_serde", |b| {
        b.iter(|| {
            serde_json::from_str::<ritualistic::Event>(black_box(EVENT_JSON))
                .map(|evt| evt.id)
                .ok()
        })
    });

    c.bench_function("get_id_manual", |b| {
        b.iter(|| ritualistic::helpers::extract_event_id(black_box(EVENT_JSON)))
    });
}

criterion_group!(benches, get_id);
criterion_main!(benches);
