// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! # VKD: Verifiable Key Directory Framework
//!
//! This crate provides the abstract [`VerifiableKeyDirectory`] trait that
//! defines the interface for any verifiable key directory implementation.
//! Both server-side operations (publish, lookup, key history, audit) and
//! client-side verification are part of the trait.
//!
//! AKD (auditable key directory) is one implementation of this trait.
//! Other implementations (e.g., polynomial-commitment-based directories)
//! can implement the same trait to enable generic benchmarking and
//! interchangeable backends.

#![warn(missing_docs)]

pub mod bench;
pub mod errors;
pub mod traits;

pub use errors::VkdError;
pub use traits::VerifiableKeyDirectory;
