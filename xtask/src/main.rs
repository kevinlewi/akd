// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed licenses.

use std::fs::create_dir_all;

use xtaskops::ops::{clean_files, cmd, remove_dir};

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["coverage"] => coverage(false),
        ["coverage", "-d" | "--dev"] => coverage(true),
        _ => xtaskops::tasks::main(),
    }
}

/// Equivalent to `xtaskops::tasks::coverage`, except that grcov searches all of
/// `target/debug` for test binaries rather than only `target/debug/deps`, which
/// newer versions of Cargo no longer populate.
fn coverage(devmode: bool) -> Result<(), anyhow::Error> {
    remove_dir("coverage")?;
    create_dir_all("coverage")?;

    println!("=== running coverage ===");
    cmd!("cargo", "test")
        .env("CARGO_INCREMENTAL", "0")
        .env("RUSTFLAGS", "-Cinstrument-coverage")
        .env("LLVM_PROFILE_FILE", "cargo-test-%p-%m.profraw")
        .run()?;
    println!("ok.");

    println!("=== generating report ===");
    let (fmt, file) = if devmode {
        ("html", "coverage/html")
    } else {
        ("lcov", "coverage/tests.lcov")
    };
    cmd!(
        "grcov",
        ".",
        "--binary-path",
        "./target/debug",
        "-s",
        ".",
        "-t",
        fmt,
        "--branch",
        "--ignore-not-existing",
        "--ignore",
        "../*",
        "--ignore",
        "/*",
        "--ignore",
        "xtask/*",
        "--ignore",
        "*/src/tests/*",
        "-o",
        file,
    )
    .run()?;
    println!("ok.");

    println!("=== cleaning up ===");
    clean_files("**/*.profraw")?;
    println!("ok.");
    if devmode {
        println!("report location: {file}");
    }

    Ok(())
}
