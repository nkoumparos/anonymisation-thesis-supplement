from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
import time
from datetime import datetime, timezone

from common import (
    POPULATION_SIZE,
    RID_ORDER_SHA256,
    json_digest,
    require,
)


PROTOCOL_VERSION = "v1.2.4"
NUMPY_VERSION = "2.0.2"
TARGET_SEED = 11001
TARGET_COUNT = 5000
PRIVATE_SCHEMA = "pre-output-target-sample-private-v1.2.4/1.0"
RECEIPT_SCHEMA = "pre-output-target-sample-receipt-v1.2.4/1.0"
_RID = re.compile(r"adult\.data:([1-9][0-9]*)\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def _sequence(value, name):
    require(isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray))
            and len(value) > 0,
            "TARGET_SEQUENCE", name + " must be a nonempty ordered sequence")
    return list(value)


def _line_bytes(values, encoding="ascii"):
    return ("\n".join(str(value) for value in values) + "\n").encode(encoding)


def _artifact(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _canonical_rids(values, fixture_mode):
    rids = _sequence(values, "canonical_rids")
    require(all(type(value) is str and value == value.strip() and value
                and not any(mark in value for mark in ("\0", "\r", "\n", "\t"))
                for value in rids),
            "TARGET_RID_TYPE", "Canonical RIDs must be safe, trimmed strings")
    require(len(set(rids)) == len(rids), "TARGET_RID_UNIQUE",
            "Canonical RIDs must be unique")
    if not fixture_mode:
        require(len(rids) == POPULATION_SIZE, "TARGET_POPULATION_COUNT",
                "Operational sampling requires exactly 30162 canonical RIDs")
        lines = []
        for value in rids:
            match = _RID.fullmatch(value)
            require(match is not None, "TARGET_RID_FORMAT",
                    "Operational RIDs must use adult.data:<physical-line>")
            lines.append(int(match.group(1)))
        require(all(left < right for left, right in zip(lines, lines[1:])),
                "TARGET_RID_ORDER", "Canonical physical-line order is not increasing")
        require(hashlib.sha256(_line_bytes(rids)).hexdigest() == RID_ORDER_SHA256,
                "TARGET_RID_IDENTITY", "RID order differs from the authoritative freeze")
    return rids


def _numpy(module, fixture_mode):
    result = importlib.import_module("numpy") if module is None else module
    require(hasattr(result, "random"), "TARGET_NUMPY_API", "NumPy random API is unavailable")
    if not fixture_mode:
        require(getattr(result, "__version__", None) == NUMPY_VERSION,
                "TARGET_NUMPY_VERSION", "Operational sampling requires pinned NumPy 2.0.2")
    return result


def _sample(module, population_count, sample_count):
    generator = module.random.Generator(module.random.PCG64(TARGET_SEED))
    raw = generator.choice(population_count, size=sample_count,
                           replace=False, shuffle=True)
    try:
        values = raw.tolist()
    except AttributeError:
        values = list(raw)
    result = [int(value) for value in values]
    require(len(result) == sample_count
            and len(set(result)) == sample_count
            and all(0 <= value < population_count for value in result),
            "TARGET_SAMPLE_SRSWOR", "Generated target indices are not a valid SRSWOR sample")
    return result


def private_record_bytes(record):
    require(isinstance(record, dict) and record.get("record_schema") == PRIVATE_SCHEMA,
            "TARGET_PRIVATE_SCHEMA", "Unexpected private target-record schema")
    return (json.dumps(record, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, indent=2) + "\n").encode("ascii")


def receipt_bytes(receipt):
    require(isinstance(receipt, dict) and receipt.get("record_schema") == RECEIPT_SCHEMA,
            "TARGET_RECEIPT_SCHEMA", "Unexpected target-receipt schema")
    data = (json.dumps(receipt, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, indent=2) + "\n").encode("ascii")
    require(b"adult.data:" not in data and b'"target_indices"' not in data
            and b'"target_rids"' not in data,
            "TARGET_RECEIPT_PRIVATE_LEAK", "Bounded receipt contains target identities")
    return data


def prepare_target_sample(canonical_rids, *, fixture_mode=False,
                          fixture_sample_count=None, numpy_module=None):

    require(type(fixture_mode) is bool, "TARGET_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    rids = _canonical_rids(canonical_rids, fixture_mode)
    if fixture_mode:
        require(type(fixture_sample_count) is int
                and 1 <= fixture_sample_count <= len(rids),
                "TARGET_FIXTURE_COUNT",
                "Fixture sampling needs an explicit valid fixture_sample_count")
        sample_count = fixture_sample_count
    else:
        require(fixture_sample_count is None, "TARGET_OPERATIONAL_OVERRIDE",
                "Operational target count cannot be overridden")
        sample_count = TARGET_COUNT

    before = json_digest(rids)
    module = _numpy(numpy_module, fixture_mode)
    indices = _sample(module, len(rids), sample_count)
    regenerated = _sample(module, len(rids), sample_count)
    require(indices == regenerated, "TARGET_REPRODUCIBILITY",
            "Fresh target-sample regeneration differs")
    selected_rids = [rids[index] for index in indices]
    require(len(set(selected_rids)) == sample_count, "TARGET_SAMPLE_RID_UNIQUE",
            "Sampled target RIDs are not unique")
    require(json_digest(rids) == before, "TARGET_INPUT_MUTATION",
            "Canonical RID input changed during sampling")

    private = {
        "record_schema": PRIVATE_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "purpose": "target_sample",
        "derivation": "Generator(PCG64(11001)).choice(N,size=5000,replace=False,shuffle=True)",
        "seed": TARGET_SEED,
        "numpy_version": getattr(module, "__version__", "test-double"),
        "population_count": len(rids),
        "target_count": sample_count,
        "target_indices": indices,
        "target_rids": selected_rids,
        "sample_order": "NUMPY_RETURNED_ORDER_UNSORTED",
        "visibility": "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
    }
    private_bytes = private_record_bytes(private)
    receipt = {
        "record_schema": RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_PRE_OUTPUT",
        "purpose": "target_sample",
        "seed": TARGET_SEED,
        "derivation": "Generator(PCG64(11001)).choice(N,size=5000,replace=False,shuffle=True)",
        "numpy_version": getattr(module, "__version__", "test-double"),
        "population_count": len(rids),
        "target_count": sample_count,
        "canonical_rid_order_sha256": hashlib.sha256(_line_bytes(rids)).hexdigest(),
        "target_index_order_sha256": hashlib.sha256(_line_bytes(indices)).hexdigest(),
        "target_rid_order_sha256": hashlib.sha256(_line_bytes(selected_rids)).hexdigest(),
        "private_record_json": _artifact(private_bytes),
        "sampling_without_replacement": True,
        "sample_order_preserved_unsorted": True,
        "fresh_generation_count": 2,
        "target_sample_reproducible": True,
        "generated_before_cfg_outputs": "ASSERTED_BY_OPERATIONAL_WRAPPER",
        "private_targets_in_receipt": False,
        "holdout_accessed": False,
        "anonymization_invoked": False,
        "attack_scores_computed": False,
        "model_fits_executed": False,
        "main_run_authorization_granted_by_this_artifact": False,
    }
    receipt_bytes(receipt)
    return {"private_record": private, "bounded_receipt": receipt}


def _read_rids(path):
    data = path.read_bytes()
    require(data and not data.startswith(b"\xef\xbb\xbf") and data.endswith(b"\n")
            and b"\r" not in data and b"\0" not in data,
            "TARGET_RID_FILE_BYTES", "RID file must be strict LF text without BOM")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("TARGET_RID_FILE_ASCII: RID file is not ASCII") from error
    return text[:-1].split("\n")


def _write_new(path, data):
    require(not path.exists(), "TARGET_OUTPUT_EXISTS", "Refusing to overwrite target artifact")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "TARGET_TEMP_EXISTS", "Temporary target artifact exists")
    temporary.write_bytes(data)
    temporary.replace(path)


def main(argv=None):
    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    parser = argparse.ArgumentParser()
    parser.add_argument("--rid-order", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--main-run-root", type=Path, required=True)
    parser.add_argument("--repository-head", required=True)
    parser.add_argument("--authorization-record-sha256", required=True)
    args = parser.parse_args(argv)

    require(_COMMIT.fullmatch(args.repository_head) is not None,
            "TARGET_REPOSITORY_HEAD", "Repository HEAD must be a lowercase Git object ID")
    require(re.fullmatch(r"[0-9a-f]{64}", args.authorization_record_sha256) is not None,
            "TARGET_AUTHORIZATION_HASH", "Authorization-record hash must be lowercase SHA-256")
    require(args.main_run_root.is_dir(), "TARGET_RUN_ROOT", "Main-run root must already exist")
    forbidden = tuple(args.main_run_root.rglob("*.full.tsv")) + tuple(
        args.main_run_root.rglob("*.java-report.json")) + tuple(
        args.main_run_root.rglob("*.gate-b.json"))
    require(not forbidden, "TARGET_TOO_LATE",
            "A CFG output/report already exists; target sampling must precede outputs")

    result = prepare_target_sample(_read_rids(args.rid_order))
    receipt = deepcopy(result["bounded_receipt"])
    receipt["repository_head"] = args.repository_head
    receipt["authorization_record_sha256"] = args.authorization_record_sha256
    receipt["generated_before_cfg_outputs"] = True
    receipt["telemetry"] = {
        "stage": "pre_output_target_sampling",
        "status": "PASS",
        "started_at_utc": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "wall_clock_seconds": time.perf_counter() - started_clock,
        "input_records": result["bounded_receipt"]["population_count"],
        "output_target_records": result["bounded_receipt"]["target_count"],
        "peak_resident_memory_bytes": None,
        "peak_resident_memory_available": False,
        "peak_resident_memory_note": "not available from the locked Windows standard-library path",
    }
    private_data = private_record_bytes(result["private_record"])
    receipt["private_record_json"] = _artifact(private_data)
    receipt_data = receipt_bytes(receipt)
    _write_new(args.private_output, private_data)
    _write_new(args.receipt, receipt_data)
    print("RESULT=PRE_OUTPUT_TARGET_SAMPLE_PASS")
    print("TARGET_COUNT=" + str(receipt["target_count"]))
    print("TARGET_RID_ORDER_SHA256=" + receipt["target_rid_order_sha256"])
    print("RECEIPT=" + str(args.receipt))
    print("RECEIPT_BYTES=" + str(len(receipt_data)))
    print("RECEIPT_SHA256=" + hashlib.sha256(receipt_data).hexdigest())
    print("ANONYMIZATION_INVOKED=false")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("RESULT=PRE_OUTPUT_TARGET_SAMPLE_FAIL", file=sys.stderr)
        print("ERROR=" + str(error).replace("\r", " ").replace("\n", " "), file=sys.stderr)
        raise SystemExit(1)
