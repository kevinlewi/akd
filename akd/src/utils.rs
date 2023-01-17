// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::LookupProof;

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
#[cfg(any(test, feature = "public-tests"))]
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[allow(unused)]
#[cfg(any(test, feature = "public-tests"))]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::NodeLabel {
    crate::NodeLabel {
        label_val: rng.gen::<[u8; 32]>(),
        label_len: 256,
    }
}

pub fn lookup_proof_variants(original_proof: &LookupProof) -> Vec<(LookupProof, bool)> {
    let mut variants = vec![];

    variants.push((original_proof.clone(), true));

    let mut modified_epoch = original_proof.clone();
    modified_epoch.epoch += 1;
    variants.push((modified_epoch, false));

    let mut modified_version = original_proof.clone();
    modified_version.version += 1;
    variants.push((modified_version, false));

    let mut modified_value = original_proof.clone();
    modified_value.value.0[0] += 1;
    variants.push((modified_value, false));

    let mut modified_commitment_nonce = original_proof.clone();
    modified_commitment_nonce.commitment_nonce[0] += 1;
    variants.push((modified_commitment_nonce, false));

    let mut modified_membership_proof_label = original_proof.clone();
    modified_membership_proof_label
        .existence_proof
        .label
        .label_val[0] += 1;
    variants.push((modified_membership_proof_label, false));

    variants
}
