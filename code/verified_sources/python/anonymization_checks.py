from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from fractions import Fraction
import argparse
import csv
import hashlib
import importlib
import json
import math
from pathlib import Path
import sys
import time
from datetime import datetime, timezone

from common import (
    AssertionViolation,
    POPULATION_SIZE,
    QIS,
    cfg_contract,
    exact_keys,
    integer,
    require,
)


SCHEMA = "section-12-1-gate-b-v1.2.4/1.0"
PHYSICAL_SCHEMA = (
    "sex", "age", "race", "marital-status", "education",
    "native-country", "workclass", "occupation", "salary-class",
)
TARGET = "salary-class"
LOW_LABEL = "<=50K"
HIGH_LABEL = ">50K"
TARGET_LABELS = frozenset((LOW_LABEL, HIGH_LABEL))
EXPECTED_TARGET_COUNTS = {LOW_LABEL: 22654, HIGH_LABEL: 7508}
EXPECTED_SOURCE_BYTES = 2516935
EXPECTED_SOURCE_SHA256 = "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5"
T_TOLERANCE = Fraction(1, 1_000_000_000)


def _sequence(value, name):
    require(isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
            "GATE_B_SEQUENCE", name + " must be an ordered sequence")
    return value


def _cell(value, name):
    require(type(value) is str and value and value == value.strip() and value != "?",
            "GATE_B_CELL", name + " must be a nonmissing trimmed string")
    require(not any(mark in value for mark in ("\0", "\r", "\n", "\t")),
            "GATE_B_CELL_CONTROL", name + " contains a forbidden control character")
    return value


def _row(value, name):
    exact_keys(value, PHYSICAL_SCHEMA, name)
    row = {column: _cell(value[column], name + "." + column) for column in PHYSICAL_SCHEMA}
    require(row[TARGET] in TARGET_LABELS, "GATE_B_TARGET", name + " has an unknown target label")
    return row


def _fraction_record(value):
    require(type(value) is Fraction, "GATE_B_INTERNAL_FRACTION", "Expected an exact Fraction")
    number = float(value)
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "decimal": format(number, ".17g"),
        "float_hex": number.hex(),
    }


def _target_counts(source_target_labels, fixture_mode):
    labels = _sequence(source_target_labels, "source target labels")
    require(fixture_mode or len(labels) == POPULATION_SIZE,
            "GATE_B_SOURCE_COUNT", 'Operational anonymization validation requires all 30162 source labels')
    require(all(type(label) is str and label in TARGET_LABELS for label in labels),
            "GATE_B_SOURCE_TARGET", "Source labels must use the unchanged binary domain")
    counts = Counter(labels)
    require(set(counts) == TARGET_LABELS, "GATE_B_SOURCE_TARGET_DOMAIN",
            "Both source target labels must be represented")
    if not fixture_mode:
        require(dict(counts) == EXPECTED_TARGET_COUNTS, "GATE_B_SOURCE_TARGET_COUNTS",
                "Operational source target counts differ from the frozen training input")
    return counts


def _partition(retained):
    groups = defaultdict(list)
    full = Counter()
    for row in retained:
        key = tuple(row[qi] for qi in QIS)
        groups[key].append(row[TARGET])
        full[key + (row[TARGET],)] += 1
    require(groups, "GATE_B_EMPTY_RELEASE", "No retained equivalence class exists")
    sizes = sorted(len(values) for values in groups.values())
    require(sum(sizes) == len(retained), "GATE_B_PARTITION_COVERAGE",
            "Equivalence classes do not cover the retained release exactly once")
    k_hat = min(sizes)
    l_hat = min(len(set(values)) for values in groups.values())
    unique_qi = sum(size for size in sizes if size == 1)
    unique_full = sum(size for size in full.values() if size == 1)
    return groups, sizes, k_hat, l_hat, unique_qi, unique_full


def _t_hat(groups, global_counts):
    global_total = sum(global_counts.values())
    require(global_total > 0, "GATE_B_GLOBAL_TARGET_EMPTY", "Global target distribution is empty")
    global_high = Fraction(global_counts[HIGH_LABEL], global_total)
    distances = []
    for values in groups.values():
        high = sum(value == HIGH_LABEL for value in values)
        distances.append(abs(Fraction(high, len(values)) - global_high))
    return max(distances), global_high


def _numeric_pycanon(value, kind, name):
    if kind == "integer":
        require(type(value) is int, "GATE_B_PYCANON_TYPE", name + " must return int")
        require(value >= 1, "GATE_B_PYCANON_DOMAIN", name + " must return an integer >= 1")
        return value
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise AssertionViolation("GATE_B_PYCANON_TYPE", name + " must return a finite real") from error
    require(math.isfinite(number) and 0.0 <= number <= 1.0,
            "GATE_B_PYCANON_DOMAIN", name + " must return a finite value in [0,1]")
    return number


def _pycanon(retained, *, anonymity=None, pandas_module=None, version=None):
    if anonymity is None or pandas_module is None:
        package = importlib.import_module("pycanon")
        anonymity = importlib.import_module("pycanon.anonymity")
        pandas_module = importlib.import_module("pandas")
        version = getattr(package, "__version__", None)
    require(version == "1.3.6", "GATE_B_PYCANON_VERSION",
            'Anonymization validation requires the pinned pyCANON 1.3.6')
    frame = pandas_module.DataFrame(
        [[row[column] for column in PHYSICAL_SCHEMA] for row in retained],
        columns=list(PHYSICAL_SCHEMA),
    ).reset_index(drop=True)
    require(list(frame.index) == list(range(len(retained))), "GATE_B_PYCANON_INDEX",
            "The retained pyCANON dataframe index was not reset")
    require(list(frame.columns) == list(PHYSICAL_SCHEMA), "GATE_B_PYCANON_SCHEMA",
            "The retained pyCANON dataframe schema changed")
    require(not bool(frame.isna().to_numpy().any()), "GATE_B_PYCANON_NA",
            "The retained pyCANON dataframe contains NA")

    results = {}
    for name, function, args, kind in (
        ("k_hat", anonymity.k_anonymity, (list(QIS),), "integer"),
        ("l_hat", anonymity.l_diversity, (list(QIS), [TARGET]), "integer"),
        ("t_retained", anonymity.t_closeness, (list(QIS), [TARGET]), "double"),
    ):
        working = frame.copy(deep=True)
        before = working.copy(deep=True)
        value = function(working, *args)
        require(bool(working.equals(before)), "GATE_B_PYCANON_MUTATION",
                "pyCANON " + name + " mutated its dataframe")
        results[name] = _numeric_pycanon(value, kind, "pyCANON " + name)
    return results


def validate_gate_b(*, config_id, full_rows, is_outlier, source_target_labels,
                    fixture_mode=False, anonymity=None, pandas_module=None,
                    pycanon_version=None):
    """Use the ARX outlier mask in original input order to identify suppressed rows."""
    require(type(fixture_mode) is bool, "GATE_B_FIXTURE_MODE", "fixture_mode must be Boolean")
    cfg = cfg_contract(config_id)
    require(config_id != "CFG00", "GATE_B_RAW_CONTROL", 'CFG00 has no anonymization validation anonymized output')
    rows_input = _sequence(full_rows, "full output rows")
    flags = _sequence(is_outlier, "outlier mask")
    require(len(rows_input) == len(flags) and len(rows_input) > 0,
            "GATE_B_ALIGNMENT", "Rows and outlier flags must be nonempty and aligned")
    require(fixture_mode or len(rows_input) == POPULATION_SIZE,
            "GATE_B_OUTPUT_COUNT", 'Operational anonymization validation requires 30162 indexed output rows')
    require(all(type(flag) is bool for flag in flags), "GATE_B_OUTLIER_TYPE",
            "Outlier flags must be exact Booleans")

    rows = [_row(value, "output row " + str(index)) for index, value in enumerate(rows_input)]
    source_counts = _target_counts(source_target_labels, fixture_mode)
    require(len(source_target_labels) == len(rows), "GATE_B_SOURCE_ALIGNMENT",
            "Source target labels and output rows must align")
    require(all(row[TARGET] == label for row, label in zip(rows, source_target_labels)),
            "GATE_B_TARGET_BINDING", "An output target label differs from its source row")

    outlier_count = sum(flags)
    suppression = Fraction(str(cfg["suppression_limit"]))
    budget = len(rows) * suppression.numerator // suppression.denominator
    require(outlier_count <= budget, "GATE_B_SUPPRESSION_BUDGET",
            "Captured outlier count exceeds the exact CFG suppression budget")
    if suppression == 0:
        require(outlier_count == 0, "GATE_B_UNEXPECTED_OUTLIER",
                "A zero-suppression CFG contains an outlier")

    retained = [row for row, flag in zip(rows, flags) if not flag]
    groups, sizes, k_hat, l_hat, unique_qi, unique_full = _partition(retained)
    t_hat, global_high = _t_hat(groups, source_counts)
    retained_counts = Counter(row[TARGET] for row in retained)
    t_retained_custom, retained_high = _t_hat(groups, retained_counts)

    require(k_hat >= cfg["k"], "GATE_B_K", "Independent k_hat is below the CFG threshold")
    if cfg["l"] is not None:
        require(l_hat >= cfg["l"], "GATE_B_L", "Independent distinct l_hat is below the CFG threshold")
    if cfg["t"] is not None:
        require(t_hat <= Fraction(str(cfg["t"])) + T_TOLERANCE,
                "GATE_B_T", "Independent t_hat exceeds the CFG threshold plus 1e-9")

    pycanon = _pycanon(retained, anonymity=anonymity, pandas_module=pandas_module,
                       version=pycanon_version)
    require(pycanon["k_hat"] == k_hat, "GATE_B_PYCANON_K",
            "pyCANON k differs from the independent retained partition")
    require(pycanon["l_hat"] == l_hat, "GATE_B_PYCANON_L",
            "pyCANON distinct l differs from the independent retained partition")
    require(abs(pycanon["t_retained"] - float(t_retained_custom)) <= 1e-9,
            "GATE_B_PYCANON_T", "pyCANON retained-global t differs by more than 1e-9")
    if suppression == 0:
        require(abs(pycanon["t_retained"] - float(t_hat)) <= 1e-9,
                "GATE_B_PYCANON_T_NOSUPPRESSION",
                "Without suppression, pyCANON t differs from the primary custom t")

    return {
        "record_schema": SCHEMA,
        "result": "PASS",
        "config_id": config_id,
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_OUTPUT",
        "n_input": len(rows),
        "n_retained": len(retained),
        "outlier_count": outlier_count,
        "suppression_budget": budget,
        "k_required": cfg["k"],
        "k_hat": k_hat,
        "l_required": cfg["l"],
        "l_hat": l_hat,
        "t_required": cfg["t"],
        "t_hat_original_global": _fraction_record(t_hat),
        "source_positive_proportion": _fraction_record(global_high),
        "retained_positive_proportion": _fraction_record(retained_high),
        "t_hat_retained_global_custom": _fraction_record(t_retained_custom),
        "pycanon": {
            "version": "1.3.6",
            "k_hat": pycanon["k_hat"],
            "l_hat": pycanon["l_hat"],
            "t_retained": {"decimal": format(pycanon["t_retained"], ".17g"),
                           "float_hex": pycanon["t_retained"].hex()},
        },
        "equivalence_class_count": len(sizes),
        "equivalence_class_size_sum": sum(sizes),
        "equivalence_class_size_min": min(sizes),
        "equivalence_class_size_max": max(sizes),
        "u_qi_unique_rows": unique_qi,
        "u_qi": unique_qi / len(retained),
        "u_full_unique_rows": unique_full,
        "u_full": unique_full / len(retained),
        "t_primary_global": "complete_training_input",
        "pycanon_t_role": ("NUMERIC_CROSS_CHECK" if suppression == 0
                            else "RETAINED_GLOBAL_SENSITIVITY"),
        "outlier_source": "captured_DataHandle.isOutlier",
        "main_runs_authorized": False,
        "private_rows_in_receipt": False,
    }


def _parse_table_bytes(data, path, delimiter, expected_schema):
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise AssertionViolation("GATE_B_FILE_UTF8", path.name + " is not strict UTF-8") from error
    parsed = list(csv.reader(text.splitlines(), delimiter=delimiter, quotechar='"', strict=True))
    require(parsed and tuple(parsed[0]) == tuple(expected_schema), "GATE_B_FILE_SCHEMA",
            path.name + " has an unexpected header")
    require(all(len(row) == len(expected_schema) for row in parsed[1:]),
            "GATE_B_FILE_WIDTH", path.name + " contains a ragged row")
    return [{column: value for column, value in zip(expected_schema, row)} for row in parsed[1:]], data


def _read_strict_table(path, delimiter, expected_schema):

    data = path.read_bytes()
    require(data and not data.startswith(b"\xef\xbb\xbf"), "GATE_B_FILE_BOM",
            path.name + " is empty or begins with a UTF-8 BOM")
    require(b"\r" not in data and b"\0" not in data and data.endswith(b"\n"),
            "GATE_B_FILE_BYTES", path.name + " must use strict LF UTF-8 text")
    return _parse_table_bytes(data, path, delimiter, expected_schema)


def _read_frozen_source_table(path, delimiter, expected_schema):

    data = path.read_bytes()
    require(len(data) == EXPECTED_SOURCE_BYTES
            and hashlib.sha256(data).hexdigest() == EXPECTED_SOURCE_SHA256,
            "GATE_B_SOURCE_IDENTITY", "Source input differs from the frozen Adult training table")
    require(data and not data.startswith(b"\xef\xbb\xbf"), "GATE_B_SOURCE_BOM",
            path.name + " is empty or begins with a UTF-8 BOM")
    line_count = POPULATION_SIZE + 1
    without_crlf = data.replace(b"\r\n", b"")
    require(b"\0" not in data
            and data.endswith(b"\r\n")
            and data.count(b"\r\n") == line_count
            and data.count(b"\n") == line_count
            and b"\r" not in without_crlf,
            "GATE_B_SOURCE_BYTES",
            path.name + " must preserve the pinned CRLF UTF-8 source bytes")
    return _parse_table_bytes(data, path, delimiter, expected_schema)


def _write_new(path, payload):
    require(not path.exists(), "GATE_B_REPORT_EXISTS", 'Refusing to overwrite an existing anonymization validation report')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "GATE_B_REPORT_TEMP_EXISTS", 'Temporary anonymization validation report already exists')
    temporary.write_bytes(payload)
    temporary.replace(path)


def main(argv=None):
    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-id", required=True)
    parser.add_argument("--full-output", type=Path, required=True)
    parser.add_argument("--java-report", type=Path, required=True)
    parser.add_argument("--source-input", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)

    java_report_bytes = args.java_report.read_bytes()
    java_report = json.loads(java_report_bytes.decode("utf-8"))
    required = {"record_schema", "result", "config_id", "full_output",
                "outlier_mask", "main_runs_authorized"}
    require(required <= set(java_report), "GATE_B_JAVA_REPORT_KEYS",
            'Java report lacks a required anonymization validation field')
    require(java_report["record_schema"] == "arx-main-cfg-v1.2.4/1.0"
            and java_report["result"] == "PASS" and java_report["config_id"] == args.config_id,
            "GATE_B_JAVA_REPORT_BINDING", "Java report result/config binding failed")
    require(java_report["main_runs_authorized"] is True,
            "GATE_B_JAVA_AUTHORIZATION", "Java report does not record an authorized main run")

    output_rows, output_bytes = _read_strict_table(args.full_output, "\t", PHYSICAL_SCHEMA)
    source_rows, source_bytes = _read_frozen_source_table(
        args.source_input, ";", PHYSICAL_SCHEMA
    )
    artifact = java_report["full_output"]
    exact_keys(artifact, {"filename", "bytes", "sha256"}, "Java full-output identity")
    require(args.full_output.name == artifact["filename"] and len(output_bytes) == artifact["bytes"]
            and hashlib.sha256(output_bytes).hexdigest() == artifact["sha256"],
            "GATE_B_OUTPUT_IDENTITY", "Full output differs from the Java report identity")
    mask = java_report["outlier_mask"]
    exact_keys(mask, {"source", "values", "count"}, "Java outlier mask")
    require(mask["source"] == "DataHandle.isOutlier" and mask["count"] == sum(mask["values"]),
            "GATE_B_OUTLIER_REPORT", "Java outlier-mask metadata is inconsistent")

    receipt = validate_gate_b(
        config_id=args.config_id,
        full_rows=output_rows,
        is_outlier=mask["values"],
        source_target_labels=[row[TARGET] for row in source_rows],
    )
    receipt["full_output_sha256"] = artifact["sha256"]
    receipt["java_report_sha256"] = hashlib.sha256(java_report_bytes).hexdigest()
    completed_at = datetime.now(timezone.utc)
    receipt["telemetry"] = {
        "stage": "independent_gate_b_validation",
        "status": "PASS",
        "started_at_utc": started_at.isoformat().replace("+00:00", "Z"),
        "completed_at_utc": completed_at.isoformat().replace("+00:00", "Z"),
        "wall_clock_seconds": time.perf_counter() - started_clock,
        "input_records": len(output_rows),
        "retained_rows": receipt["n_retained"],
        "peak_resident_memory_bytes": None,
        "peak_resident_memory_available": False,
        "peak_resident_memory_note": "not available from the locked Windows standard-library path",
    }
    payload = (json.dumps(receipt, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, indent=2) + "\n").encode("ascii")
    _write_new(args.report, payload)
    print("RESULT=GATE_B_PASS")
    print("CONFIG_ID=" + args.config_id)
    print("REPORT=" + str(args.report))
    print("REPORT_BYTES=" + str(len(payload)))
    print("REPORT_SHA256=" + hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("RESULT=GATE_B_FAIL", file=sys.stderr)
        print("ERROR=" + str(error).replace("\r", " ").replace("\n", " "), file=sys.stderr)
        raise SystemExit(1)
