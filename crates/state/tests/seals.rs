// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Seals are private reuse hints: ordered state semantics always remain authoritative.

use state::{InMemoryState, StateDatabase, StateDiff, StateSnapshot};
use types::{Hash256, StateKey};

fn fixture() -> (InMemoryState, Vec<Vec<StateKey>>, Vec<StateDiff>) {
    let mut state = InMemoryState::new();
    let mut seed = StateDiff::new();
    let keys: Vec<_> = (0..1025u64)
        .map(|i| StateKey(i.to_be_bytes().to_vec()))
        .collect();
    for key in &keys {
        seed.put(key.clone(), vec![0; 16]);
    }
    state.commit(state.root(), &[seed]).unwrap();
    let writes = keys.iter().map(|key| vec![key.clone()]).collect();
    let diffs = keys
        .iter()
        .map(|key| {
            let mut diff = StateDiff::new();
            diff.put(key.clone(), vec![1; 16]);
            diff
        })
        .collect();
    (state, writes, diffs)
}

#[test]
fn reverse_completion_seals_match_reference_roots_proofs_and_old_snapshots() {
    let (state, writes, diffs) = fixture();
    let old = state.snapshot().unwrap();
    let old_bytes = state.export_snapshot();
    let root = Hash256([1; 32]);
    let seals = state.plan_seals(root, &writes).unwrap();
    assert_eq!(seals.transaction_root(), root);
    for (index, diff) in diffs.iter().enumerate().rev() {
        seals.record(index, diff).unwrap();
    }
    assert!(seals.ready_partitions() > 0);
    let expected = state.prepare(state.root(), &diffs).unwrap();
    let actual = state
        .prepare_sealed(state.root(), &diffs, Some(&seals))
        .unwrap();
    assert_eq!(seals.reused_partitions(), seals.ready_partitions());
    assert_eq!(expected.export_snapshot(), actual.export_snapshot());
    for key in writes.iter().flatten() {
        assert_eq!(expected.prove(key), actual.prove(key));
    }
    assert_eq!(old.root(), state.root());
    assert_eq!(state.export_snapshot(), old_bytes);
}

#[test]
fn concurrent_final_writers_publish_each_subtree_once() {
    let (state, writes, diffs) = fixture();
    let seals = state.plan_seals(Hash256([7; 32]), &writes).unwrap();
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let seals = &seals;
            let diffs = &diffs;
            scope.spawn(move || {
                for index in (worker..diffs.len()).step_by(8).rev() {
                    seals.record(index, &diffs[index]).unwrap();
                }
            });
        }
    });
    let actual = state
        .prepare_sealed(state.root(), &diffs, Some(&seals))
        .unwrap();
    assert_eq!(
        actual.export_snapshot(),
        state
            .prepare(state.root(), &diffs)
            .unwrap()
            .export_snapshot()
    );
    assert_eq!(seals.reused_partitions(), seals.ready_partitions());
}

#[test]
fn missing_changed_and_stale_seals_cannot_override_actual_effects() {
    let (state, writes, diffs) = fixture();
    let seals = state.plan_seals(Hash256([1; 32]), &writes).unwrap();
    for (index, diff) in diffs.iter().enumerate().skip(1) {
        seals.record(index, diff).unwrap();
    }
    let mut changed = diffs.clone();
    changed[513].changes.clear();
    changed[513].put(writes[513][0].clone(), vec![7; 20]);
    for actual_diffs in [&diffs, &changed] {
        assert_eq!(
            state
                .prepare_sealed(state.root(), actual_diffs, Some(&seals))
                .unwrap()
                .export_snapshot(),
            state
                .prepare(state.root(), actual_diffs)
                .unwrap()
                .export_snapshot()
        );
    }
    let next = state.prepare(state.root(), &diffs).unwrap();
    assert_eq!(
        next.prepare_sealed(next.root(), &changed, Some(&seals))
            .unwrap()
            .export_snapshot(),
        next.prepare(next.root(), &changed)
            .unwrap()
            .export_snapshot()
    );
    let mut topology = diffs.clone();
    topology[0].delete(writes[0][0].clone());
    assert_eq!(
        state
            .prepare_sealed(state.root(), &topology, Some(&seals))
            .unwrap()
            .export_snapshot(),
        state
            .prepare(state.root(), &topology)
            .unwrap()
            .export_snapshot()
    );
}

#[test]
fn later_final_writer_and_transient_bounds_cannot_be_hidden() {
    let (state, mut writes, mut diffs) = fixture();
    writes.push(writes[0].clone());
    let mut last = StateDiff::new();
    last.put(writes[0][0].clone(), vec![9; 16]);
    diffs.push(last);
    let seals = state.plan_seals(Hash256([1; 32]), &writes).unwrap();
    for (index, diff) in diffs.iter().enumerate().take(diffs.len() - 1) {
        seals.record(index, diff).unwrap();
    }
    assert_eq!(
        state
            .prepare_sealed(state.root(), &diffs, Some(&seals))
            .unwrap()
            .export_snapshot(),
        state
            .prepare(state.root(), &diffs)
            .unwrap()
            .export_snapshot()
    );
    seals
        .record(diffs.len() - 1, diffs.last().unwrap())
        .unwrap();
    diffs[0].changes.clear();
    diffs[0].put(
        writes[0][0].clone(),
        vec![0; state::MAX_STATE_VALUE_BYTES + 1],
    );
    assert!(
        state
            .prepare_sealed(state.root(), &diffs, Some(&seals))
            .is_err()
    );
    assert!(seals.record(diffs.len(), diffs.last().unwrap()).is_err());
}
