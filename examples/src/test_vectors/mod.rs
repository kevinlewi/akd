// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Produces test vectors for various structs that can be used to verify operations
//! in the client against what the server produces.

use crate::fixture_generator::writer::yaml::YamlWriter;
use crate::fixture_generator::writer::Writer;
use akd::directory::Directory;
use akd::ecvrf::HardCodedAkdVRF;
use akd::hash::DIGEST_BYTES;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::storage::StorageManager;
use akd::verify::{key_history_verify, lookup_verify};
use akd::{
    AkdLabel, AkdValue, DomainLabel, HistoryParams, HistoryVerificationParams, NamedConfiguration,
};
use anyhow::Result;
use clap::Parser;
use protobuf::Message;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;

// "@" has to be separated from "generated" or linters might ignore this file
const HEADER_COMMENT: &str = concat!(
    "@",
    "generated This file was automatically generated by \n\
    the test vectors tool with the following command:\n\n\
    cargo run -p examples -- test-vectors \\"
);
const METADATA_COMMENT: &str = "Metadata";

/// Metadata about the output, including arguments passed to this tool and
/// the tool version.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub args: Args,
    pub version: String,
    pub configuration: String,
    pub domain_label: String,
}

#[derive(Parser, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Args {
    /// Name of output path.
    /// If omitted, output will be printed to stdout.
    #[arg(long = "out", short = 'o')]
    out: Option<String>,
}

pub async fn run(args: Args) {
    // NOTE(new_config): Add new configurations here
    type L = akd::ExampleLabel;
    generate::<akd::WhatsAppV1Configuration, L>(&args)
        .await
        .unwrap();
    generate::<akd::ExperimentalConfiguration<L>, L>(&args)
        .await
        .unwrap();
}

pub(crate) async fn generate<TC: NamedConfiguration, L: DomainLabel>(args: &Args) -> Result<()> {
    // initialize writer
    let buffer: Box<dyn Write> = if let Some(ref file_path) = args.out {
        Box::new(File::create(format!("{}/{}.yaml", file_path, TC::name())).unwrap())
    } else {
        Box::new(std::io::stdout())
    };
    let mut writer = YamlWriter::new(buffer);

    // write raw args as comment
    let raw_args = format!(
        " {}",
        std::env::args().skip(1).collect::<Vec<String>>().join(" ")
    );
    writer.write_comment(HEADER_COMMENT);
    raw_args
        .split(" -")
        .skip(1)
        .map(|arg| format!("  -{arg} \\"))
        .for_each(|comment| writer.write_comment(&comment));

    // write fixture metadata
    let comment = METADATA_COMMENT.to_string();
    let metadata = Metadata {
        args: args.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        configuration: TC::name().to_string(),
        domain_label: String::from_utf8(L::domain_label().to_vec()).unwrap(),
    };
    writer.write_line();
    writer.write_comment(&comment);
    writer.write_object(metadata);

    let db = AsyncInMemoryDatabase::new();
    let storage_manager = StorageManager::new_no_cache(db);
    let vrf = HardCodedAkdVRF {};
    // epoch 0
    let akd = Directory::<TC, _, _>::new(storage_manager, vrf).await?;
    let vrf_pk = akd.get_public_key().await?;

    let num_labels = 5;
    let num_epochs = 50;

    let label_to_write = num_labels - 1;
    let epoch_to_write = num_epochs - 1;

    let mut previous_hash = [0u8; DIGEST_BYTES];
    for epoch in 1..num_epochs {
        let mut to_insert = vec![];
        for i in 0..num_labels {
            let index = 1 << i;
            let label = AkdLabel::from(format!("{index}").as_str());
            let value = AkdValue::from(format!("{index},{epoch}").as_str());
            if epoch % index == 0 {
                to_insert.push((label, value));
            }
        }
        let epoch_hash = akd.publish(to_insert).await?;

        if epoch > 1 {
            let audit_proof = akd
                .audit(epoch_hash.epoch() - 1, epoch_hash.epoch())
                .await?;
            akd::auditor::audit_verify::<TC>(vec![previous_hash, epoch_hash.hash()], audit_proof)
                .await?;
        }

        previous_hash = epoch_hash.hash();

        for i in 0..num_labels {
            let index = 1 << i;
            if epoch < index {
                // Cannot produce proofs if there are no versions added yet for that user
                continue;
            }
            let latest_added_epoch = epoch_hash.epoch() - (epoch_hash.epoch() % index);
            let label = AkdLabel::from(format!("{index}").as_str());
            let lookup_value = AkdValue::from(format!("{index},{latest_added_epoch}").as_str());

            let (lookup_proof, epoch_hash_from_lookup) = akd.lookup(label.clone()).await?;
            assert_eq!(epoch_hash, epoch_hash_from_lookup);
            let lookup_verify_result = lookup_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label.clone(),
                lookup_proof.clone(),
            )
            .unwrap();
            assert_eq!(lookup_verify_result.epoch, latest_added_epoch);
            assert_eq!(lookup_verify_result.value, lookup_value);
            assert_eq!(lookup_verify_result.version, epoch / index);

            let (history_proof_complete, epoch_hash_from_history_complete) =
                akd.key_history(&label, HistoryParams::Complete).await?;
            assert_eq!(epoch_hash, epoch_hash_from_history_complete);

            let history_results_complete = key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label.clone(),
                history_proof_complete.clone(),
                HistoryVerificationParams::default(),
            )
            .unwrap();
            for (j, res) in history_results_complete.iter().enumerate() {
                let added_in_epoch =
                    epoch_hash.epoch() - (epoch_hash.epoch() % index) - (j as u64) * index;
                let history_value = AkdValue::from(format!("{index},{added_in_epoch}").as_str());
                assert_eq!(res.epoch, added_in_epoch);
                assert_eq!(res.value, history_value);
                assert_eq!(res.version, epoch / index - j as u64);
            }

            let (history_proof_partial, epoch_hash_from_history_partial) = akd
                .key_history(&label, HistoryParams::MostRecent(1))
                .await?;
            assert_eq!(epoch_hash, epoch_hash_from_history_partial);

            let history_results_partial = key_history_verify::<TC>(
                vrf_pk.as_bytes(),
                epoch_hash.hash(),
                epoch_hash.epoch(),
                label.clone(),
                history_proof_partial.clone(),
                HistoryVerificationParams::Default {
                    history_params: HistoryParams::MostRecent(1),
                },
            )
            .unwrap();
            assert_eq!(history_results_partial.len(), 1);
            for (j, res) in history_results_partial.iter().enumerate() {
                let added_in_epoch =
                    epoch_hash.epoch() - (epoch_hash.epoch() % index) - (j as u64) * index;
                let history_value = AkdValue::from(format!("{index},{added_in_epoch}").as_str());
                assert_eq!(res.epoch, added_in_epoch);
                assert_eq!(res.value, history_value);
                assert_eq!(res.version, epoch / index - j as u64);
            }

            if (i, epoch) == (label_to_write, epoch_to_write) {
                writer.write_line();
                writer.write_comment("Public Key");
                writer.write_object(hex::encode(vrf_pk.as_bytes()));
                writer.write_line();
                writer.write_comment("Epoch Hash");
                writer.write_object(hex::encode(epoch_hash.hash()));
                writer.write_line();
                writer.write_comment("Epoch");
                writer.write_object(epoch_hash.epoch());
                writer.write_line();
                writer.write_comment("Label");
                writer.write_object(hex::encode(&label.clone().0));
                writer.write_line();
                writer.write_comment("Lookup Proof");
                writer.write_object(hex::encode(
                    akd_core::proto::specs::types::LookupProof::from(&lookup_proof)
                        .write_to_bytes()?,
                ));
                writer.write_line();
                writer.write_comment("History Proof (HistoryParams::MostRecent(1))");
                writer.write_object(hex::encode(
                    akd_core::proto::specs::types::HistoryProof::from(&history_proof_partial)
                        .write_to_bytes()?,
                ));
                writer.write_line();
                writer.write_comment(&format!(
                    "History Proof (HistoryParams::Complete with {} versions)",
                    history_results_complete.len()
                ));
                writer.write_object(hex::encode(
                    akd_core::proto::specs::types::HistoryProof::from(&history_proof_complete)
                        .write_to_bytes()?,
                ));
            }
        }
    }

    // flush writer and exit
    writer.flush();
    Ok(())
}