// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Abstract trait for a verifiable key directory.
//!
//! This trait defines both server-side operations (publish, lookup, key_history,
//! audit) and client-side verification functions. Implementations provide their
//! own proof types, public key types, and verification logic.

use async_trait::async_trait;
use core::fmt::Debug;

use akd_core::hash::Digest;
use akd_core::types::{AkdLabel, AkdValue, EpochHash, VerifyResult};

use crate::errors::VkdError;

/// Abstract Verifiable Key Directory interface.
///
/// This trait abstracts over both server-side operations and client-side
/// verification. Implementations provide their own proof types, public key
/// types, and verification logic through associated types.
///
/// Server-side methods are instance methods (`&self`). Client-side verification
/// methods are associated functions (no `self` parameter), called as
/// `D::lookup_verify(...)`.
#[async_trait]
pub trait VerifiableKeyDirectory: Send + Sync {
    /// The proof type returned by a single-key lookup.
    type LookupProof: Send + Sync + Debug;
    /// The proof type returned by a key history query.
    type HistoryProof: Send + Sync + Debug;
    /// The proof type returned by an audit between two epochs.
    type AuditProof: Send + Sync + Debug;
    /// The public key type for this directory.
    type PublicKey: Send + Sync + Debug;
    /// Parameters controlling how much key history to retrieve.
    type HistoryParams: Send + Sync + Debug + Default;
    /// Parameters controlling how key history verification proceeds.
    type HistoryVerificationParams: Send + Sync + Debug + Default;
    /// Implementation-specific error type.
    type Error: std::error::Error + Send + Sync + Into<VkdError>;

    // ========================
    // Server-side operations
    // ========================

    /// Publish a batch of label-value updates to the directory.
    /// Returns the new epoch hash (epoch number + root hash).
    async fn publish(
        &self,
        updates: Vec<(AkdLabel, AkdValue)>,
    ) -> Result<EpochHash, Self::Error>;

    /// Generate a lookup proof for a single label at the latest epoch.
    async fn lookup(
        &self,
        label: AkdLabel,
    ) -> Result<(Self::LookupProof, EpochHash), Self::Error>;

    /// Generate lookup proofs for multiple labels at the latest epoch.
    ///
    /// The default implementation calls [`lookup`](Self::lookup) sequentially.
    /// Implementations may override for efficiency (e.g., batch preloading).
    async fn batch_lookup(
        &self,
        labels: &[AkdLabel],
    ) -> Result<(Vec<Self::LookupProof>, EpochHash), Self::Error> {
        if labels.is_empty() {
            let epoch_hash = self.get_epoch_hash().await?;
            return Ok((vec![], epoch_hash));
        }
        let mut proofs = Vec::with_capacity(labels.len());
        let mut last_epoch_hash = None;
        for label in labels {
            let (proof, eh) = self.lookup(label.clone()).await?;
            proofs.push(proof);
            last_epoch_hash = Some(eh);
        }
        Ok((proofs, last_epoch_hash.unwrap()))
    }

    /// Generate a key history proof for a label.
    async fn key_history(
        &self,
        label: &AkdLabel,
        params: Self::HistoryParams,
    ) -> Result<(Self::HistoryProof, EpochHash), Self::Error>;

    /// Generate an audit proof between two epochs.
    async fn audit(
        &self,
        start_epoch: u64,
        end_epoch: u64,
    ) -> Result<Self::AuditProof, Self::Error>;

    /// Retrieve the public key for this directory.
    async fn get_public_key(&self) -> Result<Self::PublicKey, Self::Error>;

    /// Retrieve the current epoch and root hash.
    async fn get_epoch_hash(&self) -> Result<EpochHash, Self::Error>;

    // ========================
    // Client-side verification
    // ========================

    /// Verify a lookup proof against a public key and root hash.
    fn lookup_verify(
        public_key: &Self::PublicKey,
        root_hash: Digest,
        current_epoch: u64,
        label: AkdLabel,
        proof: Self::LookupProof,
    ) -> Result<VerifyResult, VkdError>;

    /// Verify a key history proof against a public key and root hash.
    fn key_history_verify(
        public_key: &Self::PublicKey,
        root_hash: Digest,
        current_epoch: u64,
        label: AkdLabel,
        proof: Self::HistoryProof,
        params: Self::HistoryVerificationParams,
    ) -> Result<Vec<VerifyResult>, VkdError>;

    /// Verify an audit proof given a sequence of root hashes.
    async fn audit_verify(
        hashes: Vec<Digest>,
        proof: Self::AuditProof,
    ) -> Result<(), VkdError>;
}
