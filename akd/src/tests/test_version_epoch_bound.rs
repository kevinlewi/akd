// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Tests that key history and lookup verification reject proofs whose version
//! exceeds the epoch in which that version was inserted.
//!
//! An honest directory starts each label at version 1 and increments it by
//! exactly one per publish, so `version <= insertion epoch` always holds. A
//! malicious directory holds the VRF secret key and can insert leaves for
//! arbitrary versions directly into the tree. These tests build such a tree
//! using only public APIs.

use akd_core::{
    configuration::Configuration,
    ecvrf::{Proof, VRFKeyStorage, VRFPublicKey},
    hash::Digest,
    verify::{
        verify_membership_for_tests_only, verify_nonmembership_for_tests_only, VerificationError,
    },
    AzksElement, HistoryProof, VersionFreshness,
};

use crate::{
    append_only_zks::{AzksParallelismConfig, InsertMode, DEFAULT_AZKS_KEY},
    client::{key_history_verify, lookup_verify},
    directory::Directory,
    ecvrf::HardCodedAkdVRF,
    errors::AkdError,
    storage::{
        manager::StorageManager,
        memory::AsyncInMemoryDatabase,
        types::{DbRecord, ValueState},
    },
    test_config, AkdLabel, AkdValue, Azks, HistoryParams, HistoryVerificationParams,
};

type TestDirectory<TC> = Directory<TC, AsyncInMemoryDatabase, HardCodedAkdVRF>;

const TARGET: &str = "target";
const OTHER: &str = "other";

/// Number of honest updates for the target label (versions 1..=N at epochs 1..=N)
const HONEST_UPDATES: u64 = 20;
/// Epoch at which the malicious leaves are inserted
const MALICIOUS_EPOCH: u64 = HONEST_UPDATES + 1;
/// Version claimed by the malicious fresh leaf, far exceeding `MALICIOUS_EPOCH`
const MALICIOUS_VERSION: u64 = 130;
/// Fresh marker version required as a past marker for `MALICIOUS_VERSION`.
/// The past markers for 130 are [16, 128], and 16 already exists honestly.
const MALICIOUS_MARKER_VERSION: u64 = 128;
/// Epoch at which the directory still serves the honest view (version 20).
/// This must be below `MALICIOUS_MARKER_VERSION`, since otherwise the history
/// for version 20 would require non-membership of the inserted marker.
const HONEST_VIEW_EPOCH: u64 = 100;
const _: () = assert!(HONEST_VIEW_EPOCH < MALICIOUS_MARKER_VERSION);

/// Substring of the errors returned by the version-to-update-epoch bound
const VERSION_EPOCH_BOUND_ERROR: &str = "exceeds its epoch";

fn most_recent_one() -> HistoryVerificationParams {
    HistoryVerificationParams::Default {
        history_params: HistoryParams::MostRecent(1),
    }
}

fn is_version_epoch_bound_error(err: &VerificationError) -> bool {
    matches!(
        err,
        VerificationError::HistoryProof(msg) | VerificationError::LookupProof(msg)
            if msg.contains(VERSION_EPOCH_BOUND_ERROR)
    )
}

async fn publish_other_until<TC: Configuration>(
    akd: &TestDirectory<TC>,
    target_epoch: u64,
) -> Result<(), AkdError> {
    loop {
        let epoch = akd.get_epoch_hash().await?.epoch();
        if epoch >= target_epoch {
            assert_eq!(epoch, target_epoch);
            return Ok(());
        }
        akd.publish(vec![(
            AkdLabel::from(OTHER),
            AkdValue(format!("other_{}", epoch + 1).into_bytes()),
        )])
        .await?;
    }
}

/// Publishes versions 1..=HONEST_UPDATES of the target label, one per epoch.
async fn publish_honest_target_history<TC: Configuration>(
    akd: &TestDirectory<TC>,
) -> Result<(), AkdError> {
    for version in 1..=HONEST_UPDATES {
        akd.publish(vec![(
            AkdLabel::from(TARGET),
            AkdValue(format!("target_{version}").into_bytes()),
        )])
        .await?;
    }
    Ok(())
}

/// Acting as a malicious directory, directly inserts (in a single new epoch):
/// - a fresh leaf for `fresh_version` of `label`
/// - a stale leaf for `fresh_version - 1` of `label`
/// - a fresh leaf for `marker_version` of `label`
///
/// The leaves carry valid VRF labels and commitments, since the directory
/// holds the VRF secret key. Returns the [ValueState] describing the fresh
/// version, which the caller may write to storage whenever it chooses to start
/// serving that version.
async fn malicious_insert<TC: Configuration>(
    storage: &StorageManager<AsyncInMemoryDatabase>,
    vrf: &HardCodedAkdVRF,
    label: &AkdLabel,
    value: &AkdValue,
    fresh_version: u64,
    marker_version: u64,
) -> Result<ValueState, AkdError> {
    let mut azks = match storage.get::<Azks>(&DEFAULT_AZKS_KEY).await? {
        DbRecord::Azks(azks) => azks,
        _ => panic!("Expected an Azks record"),
    };
    let commitment_key = TC::hash(&vrf.retrieve().await?);

    let fresh_label = vrf
        .get_node_label::<TC>(label, VersionFreshness::Fresh, fresh_version)
        .await?;
    let stale_label = vrf
        .get_node_label::<TC>(label, VersionFreshness::Stale, fresh_version - 1)
        .await?;
    let marker_label = vrf
        .get_node_label::<TC>(label, VersionFreshness::Fresh, marker_version)
        .await?;
    let marker_value = AkdValue::from("marker");

    let elements = vec![
        AzksElement {
            label: fresh_label,
            value: TC::compute_fresh_azks_value(
                &commitment_key,
                &fresh_label,
                fresh_version,
                value,
            ),
        },
        AzksElement {
            label: stale_label,
            value: TC::stale_azks_value(),
        },
        AzksElement {
            label: marker_label,
            value: TC::compute_fresh_azks_value(
                &commitment_key,
                &marker_label,
                marker_version,
                &marker_value,
            ),
        },
    ];

    azks.batch_insert_nodes::<TC, _>(
        storage,
        elements,
        InsertMode::Directory,
        AzksParallelismConfig::default(),
    )
    .await?;
    let epoch = azks.get_latest_epoch();
    storage.batch_set(vec![DbRecord::Azks(azks)]).await?;

    Ok(ValueState {
        value: value.clone(),
        version: fresh_version,
        label: fresh_label,
        epoch,
        username: label.clone(),
    })
}

/// For a single-update `MostRecent(1)` history, independently performs the
/// checks that `key_history_verify` performs other than the
/// version-to-update-epoch bound: version range against the current epoch,
/// VRF proofs, leaf commitments, and membership / non-membership proofs for the
/// update and its markers. (The ordering and `HistoryParams` checks are
/// trivially satisfied by a single update.) Used to show that the malicious
/// proof in these tests is otherwise valid.
///
/// Unlike the verifier, which derives each node label from the VRF proof output,
/// this compares against the label computed with the VRF secret key, because
/// the output-to-label conversion is crate-private in akd_core. The two are
/// equivalent because the VRF is deterministic.
async fn assert_single_update_history_otherwise_valid<TC: Configuration>(
    vrf: &HardCodedAkdVRF,
    vrf_pk: &VRFPublicKey,
    root_hash: Digest,
    current_epoch: u64,
    label: &AkdLabel,
    proof: &HistoryProof,
) -> Result<(), AkdError> {
    async fn check_vrf<TC: Configuration>(
        vrf: &HardCodedAkdVRF,
        vrf_pk: &VRFPublicKey,
        label: &AkdLabel,
        freshness: VersionFreshness,
        version: u64,
        vrf_proof: &[u8],
        node_label: akd_core::NodeLabel,
    ) -> Result<(), AkdError> {
        let parsed = Proof::try_from(vrf_proof)?;
        vrf_pk.verify(
            &parsed,
            &TC::get_hash_from_label_input(label, freshness, version),
        )?;
        // The VRF is deterministic, so the verified proof's output is the node label
        // that the key holder computes for the same input.
        assert_eq!(
            node_label,
            vrf.get_node_label::<TC>(label, freshness, version).await?
        );
        Ok(())
    }

    assert_eq!(1, proof.update_proofs.len());
    let start_version = proof.update_proofs[0].version;
    let end_version = start_version;
    assert!(start_version >= 1);
    assert!(end_version <= current_epoch);

    for update in &proof.update_proofs {
        check_vrf::<TC>(
            vrf,
            vrf_pk,
            label,
            VersionFreshness::Fresh,
            update.version,
            &update.existence_vrf_proof,
            update.existence_proof.label,
        )
        .await?;
        assert_eq!(
            TC::hash_leaf_with_value(&update.value, update.epoch, &update.commitment_nonce).0,
            update.existence_proof.hash_val.0
        );
        verify_membership_for_tests_only::<TC>(root_hash, &update.existence_proof)?;

        if update.version > 1 {
            let stale_proof = update.previous_version_proof.as_ref().unwrap();
            check_vrf::<TC>(
                vrf,
                vrf_pk,
                label,
                VersionFreshness::Stale,
                update.version - 1,
                update.previous_version_vrf_proof.as_ref().unwrap(),
                stale_proof.label,
            )
            .await?;
            assert_eq!(
                TC::hash_leaf_with_commitment(TC::stale_azks_value(), update.epoch).0,
                stale_proof.hash_val.0
            );
            verify_membership_for_tests_only::<TC>(root_hash, stale_proof)?;
        }
    }

    let (past_markers, future_markers) =
        akd_core::utils::get_marker_versions(start_version, end_version, current_epoch);
    assert_eq!(past_markers.len(), proof.past_marker_vrf_proofs.len());
    assert_eq!(
        past_markers.len(),
        proof.existence_of_past_marker_proofs.len()
    );
    assert_eq!(future_markers.len(), proof.future_marker_vrf_proofs.len());
    assert_eq!(
        future_markers.len(),
        proof.non_existence_of_future_marker_proofs.len()
    );
    for (i, version) in past_markers.iter().enumerate() {
        let membership = &proof.existence_of_past_marker_proofs[i];
        check_vrf::<TC>(
            vrf,
            vrf_pk,
            label,
            VersionFreshness::Fresh,
            *version,
            &proof.past_marker_vrf_proofs[i],
            membership.label,
        )
        .await?;
        verify_membership_for_tests_only::<TC>(root_hash, membership)?;
    }
    for (i, version) in future_markers.iter().enumerate() {
        let non_membership = &proof.non_existence_of_future_marker_proofs[i];
        check_vrf::<TC>(
            vrf,
            vrf_pk,
            label,
            VersionFreshness::Fresh,
            *version,
            &proof.future_marker_vrf_proofs[i],
            non_membership.label,
        )
        .await?;
        verify_nonmembership_for_tests_only::<TC>(root_hash, non_membership)?;
    }

    Ok(())
}

// A malicious directory publishes versions 1..=20 of a label at epochs 1..=20,
// then at epoch 21 directly inserts a fresh version 130 (with a stale leaf for
// version 129 and a fresh marker for version 128), and afterwards only updates
// another label. Without a version-to-update-epoch bound:
// - a MostRecent(1) history at epoch 100 reports version 20, and
// - a MostRecent(1) history at epoch 130 reports version 130 with update epoch 21,
// with no intervening insertions for the label. Both have valid VRF and
// membership proofs and satisfy version <= current epoch. The second must be
// rejected because its version exceeds its update epoch. The same applies to
// lookup proofs served at those epochs.
test_config!(test_rejects_version_exceeding_update_epoch);
async fn test_rejects_version_exceeding_update_epoch<TC: Configuration>() -> Result<(), AkdError> {
    let storage = StorageManager::new_no_cache(AsyncInMemoryDatabase::new());
    let vrf = HardCodedAkdVRF {};
    let akd = TestDirectory::<TC>::new(
        storage.clone(),
        vrf.clone(),
        AzksParallelismConfig::default(),
    )
    .await?;
    let vrf_pk = akd.get_public_key().await?;
    let target = AkdLabel::from(TARGET);

    publish_honest_target_history(&akd).await?;
    let pending_state = malicious_insert::<TC>(
        &storage,
        &vrf,
        &target,
        &AkdValue::from("malicious"),
        MALICIOUS_VERSION,
        MALICIOUS_MARKER_VERSION,
    )
    .await?;
    assert_eq!(MALICIOUS_EPOCH, pending_state.epoch);

    // At an earlier epoch, the directory serves the honest view: latest version is 20.
    publish_other_until(&akd, HONEST_VIEW_EPOCH).await?;
    let (history_100, epoch_hash_100) = akd
        .key_history(&target, HistoryParams::MostRecent(1))
        .await?;
    assert_eq!(HONEST_VIEW_EPOCH, epoch_hash_100.epoch());
    assert_eq!(HONEST_UPDATES, history_100.update_proofs[0].version);
    assert_eq!(HONEST_UPDATES, history_100.update_proofs[0].epoch);
    key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        epoch_hash_100.hash(),
        epoch_hash_100.epoch(),
        target.clone(),
        history_100,
        most_recent_one(),
    )?;
    let (lookup_100, lookup_epoch_hash_100) = akd.lookup(target.clone()).await?;
    assert_eq!(HONEST_UPDATES, lookup_100.version);
    lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        lookup_epoch_hash_100.hash(),
        lookup_epoch_hash_100.epoch(),
        target.clone(),
        lookup_100,
    )?;

    // Start serving the malicious version and advance to epoch 130 by only
    // updating another label.
    storage
        .batch_set(vec![DbRecord::ValueState(pending_state)])
        .await?;
    publish_other_until(&akd, MALICIOUS_VERSION).await?;
    let (history_130, epoch_hash_130) = akd
        .key_history(&target, HistoryParams::MostRecent(1))
        .await?;
    assert_eq!(MALICIOUS_VERSION, epoch_hash_130.epoch());
    assert_eq!(1, history_130.update_proofs.len());
    assert_eq!(MALICIOUS_VERSION, history_130.update_proofs[0].version);
    assert_eq!(MALICIOUS_EPOCH, history_130.update_proofs[0].epoch);

    // Every other check performed by the verifier passes on this proof...
    assert_single_update_history_otherwise_valid::<TC>(
        &vrf,
        &vrf_pk,
        epoch_hash_130.hash(),
        epoch_hash_130.epoch(),
        &target,
        &history_130,
    )
    .await?;

    // ...but the verifier rejects it because version 130 exceeds update epoch 21,
    // with and without tolerance for missing values, including when the value is
    // presented as tombstoned.
    let allow_missing = HistoryVerificationParams::AllowMissingValues {
        history_params: HistoryParams::MostRecent(1),
    };
    let mut tombstoned = history_130.clone();
    tombstoned.update_proofs[0].value = AkdValue(akd_core::TOMBSTONE.to_vec());
    for (proof, params) in [
        (history_130.clone(), most_recent_one()),
        (history_130.clone(), allow_missing),
        (tombstoned, allow_missing),
    ] {
        let err = key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            epoch_hash_130.hash(),
            epoch_hash_130.epoch(),
            target.clone(),
            proof,
            params,
        )
        .expect_err("History with version exceeding its update epoch should not verify");
        assert!(
            is_version_epoch_bound_error(&err),
            "Unexpected error: {err}"
        );
    }

    // Raising the claimed update epoch to satisfy the bound breaks the leaf
    // commitment, so the membership check fails instead.
    let mut raised = history_130;
    raised.update_proofs[0].epoch = MALICIOUS_VERSION;
    let err = key_history_verify::<TC>(
        vrf_pk.as_bytes(),
        epoch_hash_130.hash(),
        epoch_hash_130.epoch(),
        target.clone(),
        raised,
        most_recent_one(),
    )
    .expect_err("Raising the update epoch should break membership verification");
    assert!(
        matches!(err, VerificationError::MembershipProof(_)),
        "Unexpected error: {err}"
    );

    // A lookup at epoch 130 likewise reports version 130 with update epoch 21,
    // and is rejected by the same bound.
    let (lookup_130, lookup_epoch_hash_130) = akd.lookup(target.clone()).await?;
    assert_eq!(MALICIOUS_VERSION, lookup_epoch_hash_130.epoch());
    assert_eq!(MALICIOUS_VERSION, lookup_130.version);
    assert_eq!(MALICIOUS_EPOCH, lookup_130.epoch);
    let err = lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        lookup_epoch_hash_130.hash(),
        lookup_epoch_hash_130.epoch(),
        target.clone(),
        lookup_130.clone(),
    )
    .expect_err("Lookup with version exceeding its update epoch should not verify");
    assert!(
        is_version_epoch_bound_error(&err),
        "Unexpected error: {err}"
    );

    // Raising the lookup's claimed epoch breaks the leaf commitment.
    let mut raised_lookup = lookup_130;
    raised_lookup.epoch = MALICIOUS_VERSION;
    let err = lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        lookup_epoch_hash_130.hash(),
        lookup_epoch_hash_130.epoch(),
        target,
        raised_lookup,
    )
    .expect_err("Raising the lookup epoch should break membership verification");
    assert!(
        matches!(err, VerificationError::MembershipProof(_)),
        "Unexpected error: {err}"
    );

    Ok(())
}

// An honest label updated in every epoch from epoch 1 has version == update
// epoch for each update. Such histories and lookups must continue to verify,
// raising the claimed update epoch must break membership verification, and
// lowering it below the version must be rejected by the bound.
test_config!(test_accepts_version_equal_to_update_epoch);
async fn test_accepts_version_equal_to_update_epoch<TC: Configuration>() -> Result<(), AkdError> {
    let storage = StorageManager::new_no_cache(AsyncInMemoryDatabase::new());
    let akd = TestDirectory::<TC>::new(
        storage,
        HardCodedAkdVRF {},
        AzksParallelismConfig::default(),
    )
    .await?;
    let vrf_pk = akd.get_public_key().await?;
    let target = AkdLabel::from(TARGET);

    publish_honest_target_history(&akd).await?;

    for history_params in [
        HistoryParams::Complete,
        HistoryParams::MostRecent(1),
        HistoryParams::MostRecent(5),
    ] {
        let (history, epoch_hash) = akd.key_history(&target, history_params).await?;
        assert_eq!(HONEST_UPDATES, epoch_hash.epoch());
        assert_eq!(HONEST_UPDATES, history.update_proofs[0].version);
        for update in &history.update_proofs {
            assert_eq!(update.version, update.epoch);
        }
        key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            epoch_hash.hash(),
            epoch_hash.epoch(),
            target.clone(),
            history.clone(),
            HistoryVerificationParams::Default { history_params },
        )?;

        // Raising any update's epoch by one (which keeps version <= epoch, and
        // keeps update epochs non-increasing since updates are in consecutive
        // epochs) breaks membership verification.
        for i in 0..history.update_proofs.len() {
            let mut raised = history.clone();
            raised.update_proofs[i].epoch += 1;
            let err = key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                target.clone(),
                raised,
                HistoryVerificationParams::Default { history_params },
            )
            .expect_err("Raising the update epoch should break membership verification");
            assert!(
                matches!(err, VerificationError::MembershipProof(_)),
                "Unexpected error: {err}"
            );
        }

        // Lowering the latest update's epoch below its version is rejected by
        // the version-to-update-epoch bound.
        let mut lowered = history;
        lowered.update_proofs[0].epoch -= 1;
        let err = key_history_verify::<TC>(
            vrf_pk.as_bytes(),
            epoch_hash.hash(),
            epoch_hash.epoch(),
            target.clone(),
            lowered,
            HistoryVerificationParams::Default { history_params },
        )
        .expect_err("Update epoch below its version should not verify");
        assert!(
            is_version_epoch_bound_error(&err),
            "Unexpected error: {err}"
        );
    }

    let (lookup, epoch_hash) = akd.lookup(target.clone()).await?;
    assert_eq!(HONEST_UPDATES, lookup.version);
    assert_eq!(HONEST_UPDATES, lookup.epoch);
    lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        target.clone(),
        lookup.clone(),
    )?;

    let mut raised = lookup.clone();
    raised.epoch += 1;
    let err = lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        target.clone(),
        raised,
    )
    .expect_err("Raising the lookup epoch should break membership verification");
    assert!(
        matches!(err, VerificationError::MembershipProof(_)),
        "Unexpected error: {err}"
    );

    let mut lowered = lookup;
    lowered.epoch -= 1;
    let err = lookup_verify::<TC>(
        vrf_pk.as_bytes(),
        epoch_hash.hash(),
        epoch_hash.epoch(),
        target,
        lowered,
    )
    .expect_err("Lookup epoch below its version should not verify");
    assert!(
        is_version_epoch_bound_error(&err),
        "Unexpected error: {err}"
    );

    Ok(())
}
