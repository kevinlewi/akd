// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

//! Error types for the VKD framework.

/// Generic error type for VKD operations.
#[derive(Debug)]
pub enum VkdError {
    /// Server-side directory operation error
    Directory(String),
    /// Storage layer error
    Storage(String),
    /// Verification error
    Verification(String),
    /// Audit error
    Audit(String),
    /// Other error
    Other(String),
}

impl std::fmt::Display for VkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VkdError::Directory(s) => write!(f, "VKD directory error: {s}"),
            VkdError::Storage(s) => write!(f, "VKD storage error: {s}"),
            VkdError::Verification(s) => write!(f, "VKD verification error: {s}"),
            VkdError::Audit(s) => write!(f, "VKD audit error: {s}"),
            VkdError::Other(s) => write!(f, "VKD error: {s}"),
        }
    }
}

impl std::error::Error for VkdError {}
