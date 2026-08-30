#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is dual-licensed under either the MIT license found in the
# LICENSE-MIT file in the root directory of this source tree or the Apache
# License, Version 2.0 found in the LICENSE-APACHE file in the root directory
# of this source tree. You may select, at your option, one of the above-listed licenses.

"""Verify published WhatsApp Key Transparency audit proofs and emit a transcript.

This drives the real shipped auditor (`akd-examples whatsapp-kt-auditor`), so the
cryptographic verification performed here is exactly `akd::auditor::audit_verify`
-- no reimplementation of verification logic lives in this script.

Two independent checks are performed:

  1. Chain linkage (cheap, metadata only, covers every published epoch).
     Each published blob is named `<epoch>/<previous_root_hash>/<current_root_hash>`.
     For consecutive epochs N-1 and N, epoch N's previous_root_hash must equal
     epoch N-1's current_root_hash. This proves the published root hashes form an
     unbroken chain, and needs no blob downloads.

  2. Cryptographic proof verification (expensive, downloads each ~40MB blob).
     Each epoch's append-only proof is verified against its start/end root hash.

Outputs a self-contained, tamper-evident transcript directory:

    manifest.jsonl.gz  every published epoch discovered (epoch, hashes, size, etag)
    results.jsonl    one record per verified epoch (status, exit code, duration)
    TRANSCRIPT.md    human-readable report
    environment.txt  provenance: git commit, rustc, binary checksum, timestamps
    SHA256SUMS       checksums of all of the above

Exit status is non-zero if any epoch fails to verify or the chain is broken.

Examples
--------
    # Size the job first -- enumerate + chain-check only, no downloads.
    ./scripts/verify_published_proofs.py --log v2 --plan

    # Verify a bounded range with 8 workers.
    ./scripts/verify_published_proofs.py --log v2 --from 1000000 --to 1000999 --jobs 8

    # Spot-check 500 epochs spread evenly across the whole log.
    ./scripts/verify_published_proofs.py --log v2 --sample 500 --jobs 8

    # Resume an interrupted run (skips epochs already recorded as PASS).
    ./scripts/verify_published_proofs.py --log v2 --out audit-2026-08-05 --resume
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

LOGS = {
    "v1": "https://d1tfr3x7n136ak.cloudfront.net",
    "v2": "https://d4ttn6vhp3mg0.cloudfront.net",
}
S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
HTTP_TIMEOUT = 120


# --------------------------------------------------------------------------
# Bucket enumeration
# --------------------------------------------------------------------------


def progress(msg: str, *, final: bool = False) -> None:
    """Write a progress line: in-place on a TTY, throttled otherwise."""
    if sys.stderr.isatty():
        print(f"\r{msg}   ", end="" if not final else "\n", file=sys.stderr, flush=True)
    elif final:
        print(msg, file=sys.stderr, flush=True)


def http_get(url: str, retries: int = 5) -> bytes:
    """GET with bounded exponential backoff."""
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
                return resp.read()
        except Exception as exc:  # noqa: BLE001 - retry on any transport error
            last = exc
            if attempt < retries - 1:
                time.sleep(min(2**attempt, 30))
    raise RuntimeError(f"GET failed after {retries} attempts: {url}: {last}")


def list_bucket(base_url: str, progress=lambda n: None) -> list[dict]:
    """Enumerate every object in the bucket via the S3 ListObjectsV2 API."""
    entries: list[dict] = []
    token = None
    while True:
        params = {"list-type": "2", "max-keys": "1000"}
        if token:
            params["continuation-token"] = token
        body = http_get(f"{base_url}?{urllib.parse.urlencode(params)}")
        root = ET.fromstring(body)

        for contents in root.findall(f"{S3_NS}Contents"):
            key = contents.findtext(f"{S3_NS}Key", "")
            parts = key.split("/")
            if len(parts) != 3 or not parts[0].isdigit():
                # Not an audit blob (unexpected object); record so it is visible
                # in the transcript rather than silently ignored.
                entries.append({"epoch": None, "key": key, "unexpected": True})
                continue
            entries.append(
                {
                    "epoch": int(parts[0]),
                    "previous_hash": parts[1],
                    "current_hash": parts[2],
                    "key": key,
                    "size": int(contents.findtext(f"{S3_NS}Size", "0")),
                    "etag": contents.findtext(f"{S3_NS}ETag", "").strip('"'),
                    "last_modified": contents.findtext(f"{S3_NS}LastModified", ""),
                }
            )
        progress(len(entries))

        if root.findtext(f"{S3_NS}IsTruncated", "false") != "true":
            return entries
        token = root.findtext(f"{S3_NS}NextContinuationToken")
        if not token:
            return entries


# --------------------------------------------------------------------------
# Check 1: root-hash chain linkage (metadata only)
# --------------------------------------------------------------------------


def check_chain(epochs: list[dict]) -> dict:
    """Verify consecutive epochs' published root hashes link together.

    Only consecutive pairs (N-1, N) are checked; gaps are reported separately
    since a missing epoch means the chain cannot be followed across it.
    """
    breaks, gaps = [], []
    for prev, cur in zip(epochs, epochs[1:]):
        step = cur["epoch"] - prev["epoch"]
        if step != 1:
            gaps.append({"after": prev["epoch"], "before": cur["epoch"], "missing": step - 1})
            continue
        if cur["previous_hash"] != prev["current_hash"]:
            breaks.append(
                {
                    "epoch": cur["epoch"],
                    "expected_previous_hash": prev["current_hash"],
                    "published_previous_hash": cur["previous_hash"],
                }
            )
    return {
        "linked_pairs": max(len(epochs) - 1 - len(gaps), 0),
        "breaks": breaks,
        "gaps": gaps,
    }


# --------------------------------------------------------------------------
# Check 2: cryptographic proof verification (invokes the real auditor)
# --------------------------------------------------------------------------


VERIFICATION_FAILURE_MARKER = "failed to verify with error"


def verify_epoch(
    binary: str, log: str, entry: dict, timeout: int, retries: int = 3
) -> dict:
    """Run the shipped auditor against one epoch.

    Outcomes are deliberately distinguished:

      PASS   the append-only proof verified
      FAIL   the auditor rejected the proof -- a real, security-relevant result
      ERROR  the proof could not be fetched or run (network/infra); says nothing
             about the proof's validity, and is retried before being recorded

    Conflating ERROR with FAIL would make a transient download blip look like a
    broken proof, so they are reported separately.
    """
    cmd = [binary, "whatsapp-kt-auditor", "--log", log, "epoch", str(entry["epoch"])]
    started = time.time()
    attempts = 0
    code = out = err = None

    while attempts < max(retries, 1):
        attempts += 1
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            code, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            code, out, err = None, "", f"timed out after {timeout}s"

        text = ((out or "") + (err or "")).strip()
        # Stop immediately on a definitive answer; only retry infra errors.
        if code == 0 or VERIFICATION_FAILURE_MARKER in text:
            break
        if attempts < max(retries, 1):
            time.sleep(min(2**attempts, 15))

    output = ((out or "") + (err or "")).strip()
    if code == 0:
        status = "PASS"
    elif VERIFICATION_FAILURE_MARKER in output:
        status = "FAIL"
    else:
        status = "ERROR"

    return {
        "epoch": entry["epoch"],
        "status": status,
        "attempts": attempts,
        "exit_code": code,
        "seconds": round(time.time() - started, 2),
        "previous_hash": entry["previous_hash"],
        "current_hash": entry["current_hash"],
        "size": entry["size"],
        "etag": entry["etag"],
        "command": " ".join(cmd),
        # Kept short: the tool is silent on success (its progress bar only
        # renders to a TTY), so this carries failure detail when it matters.
        "output": output[-2000:],
    }


# --------------------------------------------------------------------------
# Provenance + transcript
# --------------------------------------------------------------------------


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str]) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, check=False
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return "(unavailable)"


def collect_environment(binary: str, base_url: str, args) -> dict:
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dirty = run(["git", "-C", repo, "status", "--porcelain"])
    return {
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "log_version": args.log,
        "bucket_url": base_url,
        "akd_git_commit": run(["git", "-C", repo, "rev-parse", "HEAD"]),
        "akd_git_describe": run(["git", "-C", repo, "describe", "--always", "--dirty"]),
        "akd_working_tree": "dirty" if dirty else "clean",
        "auditor_binary": os.path.abspath(binary),
        "auditor_binary_sha256": sha256_file(binary) if os.path.exists(binary) else None,
        "rustc": run(["rustc", "--version"]),
        "cargo": run(["cargo", "--version"]),
        "host": run(["uname", "-a"]),
        "invocation": " ".join(sys.argv),
    }


def human_bytes(n: int) -> str:
    step = 1024.0
    val = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if val < step:
            return f"{val:.1f} {unit}"
        val /= step
    return f"{val:.1f} EiB"


def human_time(seconds: float) -> str:
    seconds = int(seconds)
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def contiguous_ranges(numbers) -> list[tuple[int, int]]:
    """Collapse a set of integers into inclusive contiguous [start, end] ranges."""
    ranges: list[list[int]] = []
    for n in sorted(numbers):
        if ranges and n == ranges[-1][1] + 1:
            ranges[-1][1] = n
        elif not ranges or n != ranges[-1][1]:
            ranges.append([n, n])
    return [(a, b) for a, b in ranges]


def write_transcript(
    outdir: str,
    env: dict,
    all_epochs,
    chain,
    results,
    args,
    planned,
    interrupted=False,
    resumed_count=0,
):
    results = sorted(results, key=lambda r: r["epoch"])
    failures = [r for r in results if r["status"] == "FAIL"]
    errors = [r for r in results if r["status"] == "ERROR"]
    passed = len([r for r in results if r["status"] == "PASS"])
    verified_epochs = sorted(r["epoch"] for r in results if r["status"] == "PASS")
    bytes_verified = sum(r.get("size", 0) for r in results)
    total_seconds = sum(r.get("seconds", 0) for r in results)

    chain_ok = not chain["breaks"]
    if failures or not chain_ok:
        overall = "FAIL"
    elif args.plan:
        overall = "PASS (chain only)" if chain_ok else "FAIL"
    elif errors:
        overall = f"INCOMPLETE ({len(errors)} unreachable, no verification failures)"
    elif interrupted or len(results) != planned + resumed_count:
        overall = "INCOMPLETE (no verification failures so far)"
    elif results:
        overall = "PASS"
    else:
        overall = "PASS (chain only)"

    lines: list[str] = []
    a = lines.append
    a("# WhatsApp KT — Published Audit Proof Verification Transcript")
    a("")
    a(f"**Result: {overall}**")
    a("")
    a(f"- Log: `{args.log}` — `{env['bucket_url']}`")
    a(f"- Started: `{env['started_utc']}`")
    a(f"- Finished: `{datetime.datetime.now(datetime.timezone.utc).isoformat()}`")
    a("")

    a("## Provenance")
    a("")
    a("| Field | Value |")
    a("| --- | --- |")
    for k in (
        "akd_git_commit",
        "akd_git_describe",
        "akd_working_tree",
        "auditor_binary",
        "auditor_binary_sha256",
        "rustc",
        "cargo",
        "invocation",
    ):
        a(f"| `{k}` | `{env.get(k)}` |")
    a("")
    a(
        "The auditor binary above performs verification via "
        "`akd::auditor::audit_verify`. This script contains no verification "
        "logic of its own."
    )
    a("")

    a("## Check 1 — Root-hash chain linkage (all published epochs)")
    a("")
    a(
        "Each blob is named `<epoch>/<previous_root_hash>/<current_root_hash>`. "
        "For consecutive epochs, epoch N's `previous_root_hash` must equal epoch "
        "N-1's `current_root_hash`."
    )
    a("")
    a(f"- Epochs discovered: **{len(all_epochs):,}**")
    if all_epochs:
        a(f"- Epoch range: **{all_epochs[0]['epoch']:,} – {all_epochs[-1]['epoch']:,}**")
    a(f"- Consecutive pairs checked: **{chain['linked_pairs']:,}**")
    a(f"- Linkage breaks: **{len(chain['breaks'])}**")
    a(f"- Gaps (missing epochs): **{len(chain['gaps'])}**")
    a("")
    if chain["breaks"]:
        a("### Linkage breaks")
        a("")
        a("| Epoch | Expected previous_hash | Published previous_hash |")
        a("| --- | --- | --- |")
        for b in chain["breaks"][:200]:
            a(
                f"| {b['epoch']} | `{b['expected_previous_hash']}` "
                f"| `{b['published_previous_hash']}` |"
            )
        if len(chain["breaks"]) > 200:
            a(f"| … | _{len(chain['breaks']) - 200} more — see `chain.json`_ | |")
        a("")
    if chain["gaps"]:
        a("### Gaps")
        a("")
        a("| After epoch | Before epoch | Missing |")
        a("| --- | --- | --- |")
        for g in chain["gaps"][:200]:
            a(f"| {g['after']} | {g['before']} | {g['missing']} |")
        if len(chain["gaps"]) > 200:
            a(f"| … | _{len(chain['gaps']) - 200} more — see `chain.json`_ | |")
        a("")

    a("## Check 2 — Cryptographic proof verification")
    a("")
    if args.plan:
        a("_Skipped: `--plan` mode (enumeration and chain check only)._")
        a("")
    else:
        coverage = (len(results) / len(all_epochs) * 100) if all_epochs else 0.0
        if resumed_count:
            a(f"- Carried over from previous run(s): **{resumed_count:,}**")
        a(f"- Epochs selected for verification this run: **{planned:,}**")
        a(
            f"- Outcomes: PASS **{passed:,}** / FAIL **{len(failures):,}** "
            f"/ ERROR **{len(errors):,}**"
        )
        a(f"- Coverage of all published epochs: **{coverage:.2f}%**")
        a(f"- Proof data downloaded and verified: **{human_bytes(bytes_verified)}**")
        a(f"- Cumulative verification time: **{human_time(total_seconds)}**")
        if verified_epochs:
            a(f"- Verified epoch range: **{verified_epochs[0]:,} – {verified_epochs[-1]:,}**")
        a("")

        if verified_epochs:
            covered = contiguous_ranges(verified_epochs)
            published = {e["epoch"] for e in all_epochs}
            # Holes between the lowest and highest verified epoch that exist in
            # the log but have not been verified yet.
            span = range(verified_epochs[0], verified_epochs[-1] + 1)
            holes = contiguous_ranges(
                [e for e in span if e in published and e not in set(verified_epochs)]
            )
            a("### Verified coverage")
            a("")
            a("| Verified range | Epochs |")
            a("| --- | --- |")
            for lo, hi in covered[:200]:
                a(f"| {lo:,} – {hi:,} | {hi - lo + 1:,} |")
            if len(covered) > 200:
                a(f"| … | _{len(covered) - 200} more ranges_ |")
            a("")
            if holes:
                a(f"**Unverified gaps within the verified span: {len(holes)}**")
                a("")
                a("| Gap | Epochs |")
                a("| --- | --- |")
                for lo, hi in holes[:200]:
                    a(f"| {lo:,} – {hi:,} | {hi - lo + 1:,} |")
                if len(holes) > 200:
                    a(f"| … | _{len(holes) - 200} more gaps_ |")
            else:
                a("No gaps: every published epoch in the verified span was verified.")
            a("")
            remaining = len(published) - len(set(verified_epochs))
            a(f"Not yet verified elsewhere in the log: **{remaining:,}** epochs.")
            a("")
        if interrupted:
            a(
                "> **Run was interrupted.** The records below cover the epochs "
                "completed before interruption; re-run with `--resume` to continue."
            )
            a("")
        if failures:
            a("### ❌ Verification failures")
            a("")
            a("| Epoch | Exit | Detail |")
            a("| --- | --- | --- |")
            for f in failures[:200]:
                detail = (f.get("output") or "").replace("\n", " ").replace("|", "\\|")[:300]
                a(f"| {f['epoch']} | {f['exit_code']} | {detail} |")
            if len(failures) > 200:
                a(f"| … | | _{len(failures) - 200} more — see `results.jsonl`_ |")
            a("")
        else:
            a("No verification failures. Every epoch that was reached verified successfully.")
            a("")

        if errors:
            a("### ⚠️ Unreachable (not verified)")
            a("")
            a(
                "These epochs could not be fetched or executed (network or "
                "infrastructure). This says **nothing** about proof validity — "
                "re-run with `--resume` to retry them."
            )
            a("")
            a("| Epoch | Attempts | Detail |")
            a("| --- | --- | --- |")
            for e in errors[:200]:
                detail = (e.get("output") or "").replace("\n", " ").replace("|", "\\|")[:200]
                a(f"| {e['epoch']} | {e.get('attempts', 1)} | {detail} |")
            if len(errors) > 200:
                a(f"| … | | _{len(errors) - 200} more — see `results.jsonl`_ |")
            a("")

    a("## How to independently reproduce")
    a("")
    a("1. Check out the akd commit listed under Provenance and build the auditor:")
    a("   ```")
    a("   cargo build --release -p examples --bin akd-examples")
    a("   ```")
    a("2. Re-run this script with the same arguments (see `invocation` above).")
    a(
        "3. Compare `manifest.jsonl.gz` — the `etag` and `size` of each object pin the "
        "exact bytes verified, so a re-listing of the bucket can confirm nothing "
        "changed underneath this run."
    )
    a("4. Verify this transcript is intact:")
    a("   ```")
    a("   shasum -a 256 -c SHA256SUMS")
    a("   ```")
    a("")
    a("## Files")
    a("")
    a("| File | Contents |")
    a("| --- | --- |")
    a("| `manifest.jsonl.gz` | Every published epoch discovered, with hashes/size/etag |")
    a("| `chain.json` | Full chain-linkage result |")
    a("| `results.jsonl` | Per-epoch verification records |")
    a("| `environment.txt` | Provenance captured at run start |")
    a("| `SHA256SUMS` | Checksums of the files above |")
    a("")

    path = os.path.join(outdir, "TRANSCRIPT.md")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return overall, failures


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def parse_args():
    p = argparse.ArgumentParser(
        description="Verify published WhatsApp KT audit proofs and emit a transcript.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples\n--------\n")[-1],
    )
    p.add_argument("--log", choices=("v1", "v2"), default="v2", help="which log to audit")
    p.add_argument("--from", dest="from_epoch", type=int, help="first epoch (inclusive)")
    p.add_argument("--to", dest="to_epoch", type=int, help="last epoch (inclusive)")
    p.add_argument("--limit", type=int, help="verify at most N epochs from the range")
    p.add_argument("--sample", type=int, help="verify N epochs spread evenly across the range")
    p.add_argument("--jobs", type=int, default=4, help="parallel verifications (default 4)")
    p.add_argument("--out", help="output directory (default audit-transcript-<log>-<ts>)")
    p.add_argument("--plan", action="store_true", help="enumerate + chain check only, no downloads")
    p.add_argument("--resume", action="store_true", help="skip epochs already PASSed in --out")
    p.add_argument("--timeout", type=int, default=900, help="per-epoch timeout seconds")
    p.add_argument(
        "--retries", type=int, default=3, help="attempts per epoch on transport errors"
    )
    p.add_argument(
        "--binary",
        default=os.path.join("target", "release", "akd-examples"),
        help="path to the akd-examples binary",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    base_url = LOGS[args.log]

    if not args.plan and not os.path.exists(args.binary):
        print(
            f"error: auditor binary not found at {args.binary}\n"
            f"       build it with: cargo build --release -p examples --bin akd-examples",
            file=sys.stderr,
        )
        return 2

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = args.out or f"audit-transcript-{args.log}-{stamp}"
    os.makedirs(outdir, exist_ok=True)

    env = collect_environment(args.binary, base_url, args)
    with open(os.path.join(outdir, "environment.txt"), "w") as fh:
        json.dump(env, fh, indent=2)
        fh.write("\n")

    # ---- enumerate -------------------------------------------------------
    print(f"Enumerating {args.log} log at {base_url} …", file=sys.stderr)
    entries = list_bucket(
        base_url, progress=lambda n: progress(f"  discovered {n:,} objects")
    )
    progress(f"  discovered {len(entries):,} objects", final=True)

    unexpected = [e for e in entries if e.get("unexpected")]
    all_epochs = sorted(
        (e for e in entries if not e.get("unexpected")), key=lambda e: e["epoch"]
    )
    if unexpected:
        print(f"  note: {len(unexpected)} object(s) did not parse as audit blobs", file=sys.stderr)

    with gzip.open(os.path.join(outdir, "manifest.jsonl.gz"), "wt") as fh:
        for e in all_epochs:
            fh.write(json.dumps(e) + "\n")
        for e in unexpected:
            fh.write(json.dumps(e) + "\n")

    total_bytes = sum(e["size"] for e in all_epochs)
    print(
        f"  {len(all_epochs):,} epochs "
        f"({all_epochs[0]['epoch']:,}–{all_epochs[-1]['epoch']:,}), "
        f"{human_bytes(total_bytes)} total"
        if all_epochs
        else "  no epochs found",
        file=sys.stderr,
    )

    # ---- check 1: chain linkage -----------------------------------------
    print("Checking root-hash chain linkage …", file=sys.stderr)
    chain = check_chain(all_epochs)
    with open(os.path.join(outdir, "chain.json"), "w") as fh:
        json.dump(chain, fh, indent=2)
        fh.write("\n")
    print(
        f"  {chain['linked_pairs']:,} consecutive pairs linked, "
        f"{len(chain['breaks'])} break(s), {len(chain['gaps'])} gap(s)",
        file=sys.stderr,
    )

    # ---- select epochs to verify ----------------------------------------
    selected = all_epochs
    if args.from_epoch is not None:
        selected = [e for e in selected if e["epoch"] >= args.from_epoch]
    if args.to_epoch is not None:
        selected = [e for e in selected if e["epoch"] <= args.to_epoch]
    if args.sample and args.sample < len(selected):
        step = len(selected) / args.sample
        selected = [selected[int(i * step)] for i in range(args.sample)]
    if args.limit:
        selected = selected[: args.limit]

    results: list[dict] = []
    results_path = os.path.join(outdir, "results.jsonl")
    interrupted = False

    if args.resume and os.path.exists(results_path):
        with open(results_path) as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("status") == "PASS":
                    results.append(rec)
        done = {r["epoch"] for r in results}
        before = len(selected)
        selected = [e for e in selected if e["epoch"] not in done]
        print(f"  resuming: {before - len(selected):,} already verified", file=sys.stderr)

    resumed_count = len(results)
    planned = len(selected)

    if args.plan:
        est_bytes = sum(e["size"] for e in selected)
        print(
            f"\nPLAN: {planned:,} epochs would be verified, "
            f"{human_bytes(est_bytes)} to download.",
            file=sys.stderr,
        )
        print(
            f"      At ~4s/epoch with --jobs {args.jobs}: "
            f"~{human_time(planned * 4 / max(args.jobs, 1))} wall clock.",
            file=sys.stderr,
        )
    else:
        # ---- check 2: verify proofs -------------------------------------
        print(
            f"Verifying {planned:,} epochs with {args.jobs} worker(s) "
            f"({human_bytes(sum(e['size'] for e in selected))} to download) …",
            file=sys.stderr,
        )
        lock = threading.Lock()
        started = time.time()
        completed = 0
        fh = open(results_path, "a" if args.resume else "w")
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs)
        try:
            futures = {
                pool.submit(
                    verify_epoch, args.binary, args.log, e, args.timeout, args.retries
                ): e
                for e in selected
            }
            try:
                for fut in concurrent.futures.as_completed(futures):
                    rec = fut.result()
                    with lock:
                        results.append(rec)
                        fh.write(json.dumps(rec) + "\n")
                        fh.flush()
                        completed += 1
                        elapsed = time.time() - started
                        rate = completed / elapsed if elapsed else 0
                        eta = (planned - completed) / rate if rate else 0
                        nfail = sum(1 for r in results if r["status"] != "PASS")
                        line = (
                            f"  {completed:,}/{planned:,} verified "
                            f"({nfail} failed) — ETA {human_time(eta)}"
                        )
                        progress(line, final=(completed == planned))
                        if rec["status"] != "PASS":
                            print(
                                f"\n  ❌ epoch {rec['epoch']} FAILED "
                                f"(exit {rec['exit_code']}): {rec['output'][:200]}",
                                file=sys.stderr,
                            )
            except KeyboardInterrupt:
                # Still emit a transcript for the work completed so far; the run
                # can be continued later with --resume.
                interrupted = True
                print(
                    f"\n  interrupted after {completed:,}/{planned:,} epochs — "
                    f"writing transcript for completed work",
                    file=sys.stderr,
                )
                for pending in futures:
                    pending.cancel()
        finally:
            fh.close()
            pool.shutdown(wait=False)
        print(file=sys.stderr)

    # ---- transcript ------------------------------------------------------
    overall, failures = write_transcript(
        outdir, env, all_epochs, chain, results, args, planned, interrupted, resumed_count
    )

    # Records are appended in completion order; rewrite sorted by epoch so the
    # file can be scanned directly for coverage and gaps.
    if results:
        with open(results_path, "w") as fh:
            for rec in sorted(results, key=lambda r: r["epoch"]):
                fh.write(json.dumps(rec) + "\n")

    # Checksum only this run's own artifacts. Listing the directory would also
    # pick up unrelated or transient files (editor swap files, partial writes),
    # producing a SHA256SUMS that cannot be verified later.
    artifacts = (
        "TRANSCRIPT.md",
        "manifest.jsonl.gz",
        "chain.json",
        "results.jsonl",
        "environment.txt",
    )
    sums_path = os.path.join(outdir, "SHA256SUMS")
    with open(sums_path, "w") as fh:
        for name in artifacts:
            path = os.path.join(outdir, name)
            if os.path.exists(path):
                fh.write(f"{sha256_file(path)}  {name}\n")

    print(f"\nTranscript written to {outdir}/TRANSCRIPT.md", file=sys.stderr)
    print(f"Result: {overall}", file=sys.stderr)
    if shutil.which("shasum"):
        print(f"Verify integrity with: (cd {outdir} && shasum -a 256 -c SHA256SUMS)", file=sys.stderr)

    if chain["breaks"] or failures:
        return 1
    if any(r["status"] == "ERROR" for r in results):
        return 2  # incomplete: retry with --resume
    return 0


if __name__ == "__main__":
    sys.exit(main())
