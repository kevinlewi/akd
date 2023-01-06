// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

#[macro_use]
extern crate criterion;

use akd::storage::manager::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::{ecvrf::HardCodedAkdVRF, AkdLabel, AkdValue, Directory, EpochHash};
use criterion::{BatchSize, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn generate_audit(c: &mut Criterion) {
    let num_initial_leaves = 10000;
    let num_inserted_leaves = 10000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = runtime
        .block_on(Directory::<_, _>::new(storage, vrf, false))
        .unwrap();

    let mut set1 = vec![];
    for _ in 0..num_initial_leaves {
        set1.push((AkdLabel::random(&mut rng), AkdValue::random(&mut rng)));
    }
    let EpochHash(epoch1, _) = runtime.block_on(akd.publish(set1)).unwrap();

    let mut set2 = vec![];
    for _ in 0..num_inserted_leaves {
        set2.push((AkdLabel::random(&mut rng), AkdValue::random(&mut rng)));
    }
    let EpochHash(epoch2, _) = runtime.block_on(akd.publish(set2)).unwrap();

    // benchmark batch insertion
    let id = format!(
        "Testing audit proof generation ({} initial leaves, {} inserted leaves)",
        num_initial_leaves, num_inserted_leaves
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {},
            |()| {
                runtime.block_on(akd.audit(epoch1, epoch2)).unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

fn audit_verify(c: &mut Criterion) {
    let num_initial_leaves = 1000;
    let num_inserted_leaves = 1000;

    let mut rng = StdRng::seed_from_u64(42);
    let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();

    let db = AsyncInMemoryDatabase::new();
    let storage = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    let akd = runtime
        .block_on(Directory::<_, _>::new(storage, vrf, false))
        .unwrap();

    let mut set1 = vec![];
    for _ in 0..num_initial_leaves {
        set1.push((AkdLabel::random(&mut rng), AkdValue::random(&mut rng)));
    }
    let EpochHash(epoch1, hash1) = runtime.block_on(akd.publish(set1)).unwrap();

    let mut set2 = vec![];
    for _ in 0..num_inserted_leaves {
        set2.push((AkdLabel::random(&mut rng), AkdValue::random(&mut rng)));
    }
    let EpochHash(epoch2, hash2) = runtime.block_on(akd.publish(set2)).unwrap();

    let audit_proof = runtime.block_on(akd.audit(epoch1, epoch2)).unwrap();

    // benchmark batch insertion
    let id = format!(
        "Testing audit proof verification ({} initial leaves, {} inserted leaves)",
        num_initial_leaves, num_inserted_leaves
    );
    c.bench_function(&id, move |b| {
        b.iter_batched(
            || {},
            |()| {
                runtime
                    .block_on(akd::auditor::audit_verify(
                        vec![hash1, hash2],
                        audit_proof.clone(),
                    ))
                    .unwrap();
            },
            BatchSize::PerIteration,
        );
    });
}

criterion_group!(audit_benches, generate_audit, audit_verify);
criterion_main!(audit_benches);
