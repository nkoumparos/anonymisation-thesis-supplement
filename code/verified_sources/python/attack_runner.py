from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timezone
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


_MODULE_ROOT = Path(__file__).resolve().parent
if str(_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(_MODULE_ROOT))

from common import (  # noqa: E402
    POPULATION_SIZE,
    QIS,
    exact_keys,
    json_digest,
    require,
)
from attack_adapter import (  # noqa: E402
    EVALUATION_PRIVATE_SCHEMA,
    EVALUATION_RECEIPT_SCHEMA,
    PHYSICAL_SCHEMA,
    PROTOCOL_VERSION,
    SCORE_PAYLOAD_SCHEMA,
    SCORE_RECEIPT_SCHEMA,
    SOURCE_INPUT_SHA256,
    evaluate_attack_score_payload,
    evaluation_private_bytes,
    evaluation_receipt_bytes,
    noise_private_bytes,
    noise_receipt_bytes,
    prepare_attack_score_state,
    prepare_cfg00_raw_control,
    prepare_noise_matrices,
    raw_control_receipt_bytes,
    run_attack_oracle,
    score_receipt_bytes,
)
from attack_results_collector import (  # noqa: E402
    ALL_CONFIGURATIONS,
    collect_gate_c,
    gate_c_receipt_bytes,
)
from permutation_control import (  # noqa: E402
    PRIVATE_SCHEMA as PERMUTATION_PRIVATE_SCHEMA,
    RECEIPT_SCHEMA as PERMUTATION_RECEIPT_SCHEMA,
    SCORE_STATE_SCHEMA,
    bounded_receipt_bytes as permutation_receipt_bytes,
    prepare_permutation_control,
    private_record_bytes as permutation_private_bytes,
)


RUNNER_SCHEMA = "section-12-2-gate-c-runner-v1.2.4/1.0"
SESSION_SCHEMA = "section-12-2-gate-c-session-v1.2.4/1.0"
CHECKPOINT_SCHEMA = "section-12-2-gate-c-checkpoint-v1.2.4/1.0"
MINIMUM_SOURCE_COMMIT = "cdfbe855a7eb08758b2d02f6a3b7f1dbed3f7cbb"
EXPECTED_PYTHON = (3, 12, 10)
EXPECTED_NUMPY = "2.0.2"
EXPECTED_SOURCE_BYTES = 2516935
EXPECTED_CONFIGURATION_SHA256 = (
    "ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e"
)
EXPECTED_PROTOCOL_SHA256 = (
    "77ef91e9691eef8f271598b357f27f14650b52ea0f9bb6ebe5c1f4a0e4fd78e5"
)
EXPECTED_RID_SHA256 = (
    "11fd5eeaaa9fd5245361fce5b6d7aa7c8e4f0b7110ca026580586ccecb74ba68"
)
EXPECTED_MASTER_SHA256 = (
    "4e1f8403536e0016645e42663763fd8551ca2f6babdd8185a1f30b7a6a017066"
)
SOURCE_RELATIVE = (
    "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult.csv"
)
RID_RELATIVE = "private/section_12_1_step_6_v1_2_3/rid_order.txt"
MASTER_RELATIVE = "private/section_12_1_step_6_v1_2_3/master_permutation.txt"
RUN_RELATIVE = "runs/main_v1_2_4"
PRIVATE_RELATIVE = "private/main_v1_2_4"

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_AUTH_ID = re.compile(r"AUTH-[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Z0-9_-]+\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_AUTH_KEYS = (
    "record_schema", "effective_protocol", "authorization_id",
    "authorized_at_utc", "authorized_source_commit", "authorized_configs",
    "authorized_by", "main_runs_authorized",
)
_ANONYMIZED_CONFIGURATIONS = tuple(ALL_CONFIGURATIONS[1:])
_CFG_INPUT_KEYS = {
    "release_rows", "is_outlier", "transformation_by_name",
    "gate_b_receipt", "producer_report_bytes",
}
_CHECKPOINT_FILES = (
    "score_payload.private.json",
    "score_state.json",
    "score_receipt.json",
    "permutation.private.json",
    "permutation_receipt.json",
    "actual_evaluation.private.json",
    "actual_evaluation_receipt.json",
    "permuted_evaluation.private.json",
    "permuted_evaluation_receipt.json",
)
_PUBLIC_CHECKPOINT_FILES = (
    "score_state.json",
    "score_receipt.json",
    "permutation_receipt.json",
    "actual_evaluation_receipt.json",
    "permuted_evaluation_receipt.json",
)


HIERARCHY_SPECS = OrderedDict((
    ("age", (
        "data/derived/hierarchies/adult_hierarchy_age_semantic.csv", 2282,
        "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5", 5)),
    ("sex", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_sex.csv", 16,
        "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2", 2)),
    ("race", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_race.csv", 66,
        "df11abf41fa0669455adc9c9f9fa88663afa0cee8327684ecca861cd32dc4209", 2)),
    ("marital-status", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_marital-status.csv", 239,
        "3e7ba2c4a5cd4fec059b4e3a2c57fce6e7c34a20daee1e624990ddd7beba85e5", 3)),
    ("education", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_education.csv", 692,
        "f22e5ee519c28b05538d4e5ddea0fbee5f0017fefb3abab3fa02272325bf9ce5", 4)),
    ("native-country", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_native-country.csv", 840,
        "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023", 3)),
    ("workclass", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_workclass.csv", 211,
        "106f420349bf0071dbb25371795a78799edf24a64c3424619d563c3990ee8d02", 3)),
    ("occupation", (
        "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_occupation.csv", 353,
        "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126", 3)),
))

DEPENDENCY_HASHES = {
    "configurations.csv": EXPECTED_CONFIGURATION_SHA256,
    "manifest/protocol_effective_v1_2_4.txt": EXPECTED_PROTOCOL_SHA256,
    "python/section_12_1_step_7_common.py":
        "2c77c6e9822a587fd5fe55ac47e504777e392b79f69e1989006069b840b87967",
    "python/section_8_pre_output_targets_v1_2_4.py":
        "274ebc302fddb48880eafe7cde6f99cebb53917a36252d64ed23374f7b842509",
    "python/section_12_1_gate_b_v1_2_4.py":
        "ceae0e480bf338d0650629ec1ff40413167ffbcc353f1f2ebef3343aa8ce9c86",
    "python/section_8_attack_scorer_v1_2_4.py":
        "bff7e6b3d8741902d7d53d662bfb4bf4293780f3a71c7a6747f6c55f37a2c930",
    "python/section_12_2_permutation_control_v1_2_4.py":
        "f627bba105a3b2300495e420c2d3327ad5c8aed7d42c2319cfa0e7b279a46c60",
    "python/section_8_attack_adapter_v1_2_4.py":
        "5fd25372768e3c1a48219d68bb2a4eb7c1eb3c40aed15e1057ab86929c68f8a4",
    "python/section_12_2_gate_c_collector_v1_2_4.py":
        "be60d6a35149757a3574c4b6e6fa893386ab7377c31e3bfab395ce2fcc6aee63",
}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _artifact(data):
    return {"bytes": len(data), "sha256": _sha256(data)}


def _json_bytes(value):
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, indent=2) + "\n").encode("ascii")
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("GATE_C_RUNNER_JSON: value is not canonical JSON") from error


def _strict_text(data, name, *, encoding="utf-8"):
    require(isinstance(data, bytes) and data and data.endswith(b"\n")
            and not data.startswith(b"\xef\xbb\xbf")
            and b"\r" not in data and b"\0" not in data,
            "GATE_C_RUNNER_TEXT", name + " must be BOM-free strict LF text")
    try:
        return data.decode(encoding, errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("GATE_C_RUNNER_ENCODING: invalid " + encoding
                         + " in " + name) from error


def _read_json(path, name):
    data = path.read_bytes()
    text = _strict_text(data, name)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError("GATE_C_RUNNER_JSON_PARSE: invalid JSON in " + name) from error
    require(isinstance(value, Mapping), "GATE_C_RUNNER_JSON_OBJECT",
            name + " must contain one JSON object")
    return value, data


def _read_table(path, delimiter, expected_schema, name, *, identity=None):
    data = path.read_bytes()
    text = _strict_text(data, name)
    if identity is not None:
        expected_bytes, expected_hash = identity
        require(len(data) == expected_bytes and _sha256(data) == expected_hash,
                "GATE_C_RUNNER_FILE_IDENTITY", name + " identity differs")
    try:
        parsed = list(csv.reader(text.splitlines(), delimiter=delimiter,
                                 quotechar='"', strict=True))
    except csv.Error as error:
        raise ValueError("GATE_C_RUNNER_CSV: malformed table " + name) from error
    require(parsed and tuple(parsed[0]) == tuple(expected_schema),
            "GATE_C_RUNNER_TABLE_SCHEMA", name + " has an unexpected header")
    require(all(len(row) == len(expected_schema) for row in parsed[1:]),
            "GATE_C_RUNNER_TABLE_WIDTH", name + " contains a ragged row")
    return [dict(zip(expected_schema, row)) for row in parsed[1:]], data


def _read_hierarchy(path, attribute, expected_bytes, expected_hash, width):
    data = path.read_bytes()
    text = _strict_text(data, "hierarchy " + attribute)
    require(len(data) == expected_bytes and _sha256(data) == expected_hash,
            "GATE_C_RUNNER_HIERARCHY_IDENTITY",
            "Pinned hierarchy differs for " + attribute)
    try:
        rows = list(csv.reader(text.splitlines(), delimiter=";",
                               quotechar='"', strict=True))
    except csv.Error as error:
        raise ValueError("GATE_C_RUNNER_HIERARCHY_CSV: malformed hierarchy "+attribute) from error
    require(rows and all(len(row) == width for row in rows),
            "GATE_C_RUNNER_HIERARCHY_WIDTH",
            "Hierarchy width differs for " + attribute)
    require(all(all(type(cell) is str and cell and cell == cell.strip()
                    for cell in row) for row in rows),
            "GATE_C_RUNNER_HIERARCHY_CELL",
            "Hierarchy has an empty or untrimmed cell for " + attribute)
    return {"levels": list(range(width)), "rows": rows}


def _read_lines(path, name, expected_hash, parser=str):
    data = path.read_bytes()
    text = _strict_text(data, name, encoding="ascii")
    require(_sha256(data) == expected_hash, "GATE_C_RUNNER_LINE_IDENTITY",
            name + " differs from the authoritative freeze")
    raw = text[:-1].split("\n")
    try:
        values = [parser(value) for value in raw]
    except (TypeError, ValueError) as error:
        raise ValueError("GATE_C_RUNNER_LINES: invalid value in " + name) from error
    require(len(values) == POPULATION_SIZE, "GATE_C_RUNNER_LINE_COUNT",
            name + " must contain exactly 30162 values")
    return values, data


def parse_authorization(data, current_head):

    text = _strict_text(data, "authorization record")
    values = OrderedDict()
    for line in text[:-1].split("\n"):
        require(line.count("=") == 1 and not line.startswith("="),
                "GATE_C_RUNNER_AUTH_LINE", "Malformed authorization line")
        key, value = line.split("=", 1)
        require(key not in values, "GATE_C_RUNNER_AUTH_DUPLICATE",
                "Duplicate authorization key")
        values[key] = value
    require(tuple(values) == _AUTH_KEYS, "GATE_C_RUNNER_AUTH_KEYS",
            "Authorization keys or order differ from the closed schema")
    require(values["record_schema"] == "main-run-authorization/1.0"
            and values["effective_protocol"] == PROTOCOL_VERSION
            and values["authorized_by"] == "researcher"
            and values["main_runs_authorized"] == "true",
            "GATE_C_RUNNER_AUTH_SEMANTICS",
            "Authorization is not the exact affirmative v1.2.4 record")
    require(_AUTH_ID.fullmatch(values["authorization_id"]) is not None,
            "GATE_C_RUNNER_AUTH_ID", "Authorization ID is not canonical")
    require(_UTC.fullmatch(values["authorized_at_utc"]) is not None,
            "GATE_C_RUNNER_AUTH_TIME", "Authorization time is not canonical UTC")
    expected_cfgs = ",".join(_ANONYMIZED_CONFIGURATIONS)
    require(values["authorized_configs"] == expected_cfgs,
            "GATE_C_RUNNER_AUTH_CONFIGS",
            "Authorization scope must be ordered CFG01 through CFG16")
    require(_COMMIT.fullmatch(current_head) is not None
            and values["authorized_source_commit"] == current_head,
            "GATE_C_RUNNER_AUTH_COMMIT",
            "Authorization does not bind the exact current source commit")
    return values


def _git(repository, *arguments):
    completed = subprocess.run(
        ("git", "-C", str(repository), *arguments), cwd=repository,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
        env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    )
    require(completed.returncode == 0, "GATE_C_RUNNER_GIT",
            "Git command failed: " + " ".join(arguments) + "; "
            + completed.stderr.decode("utf-8", errors="replace"))
    return completed.stdout


def _runtime_guard():
    require(os.name == "nt" and sys.implementation.name == "cpython"
            and sys.version_info[:3] == EXPECTED_PYTHON,
            "GATE_C_RUNNER_RUNTIME",
            'Operational record-linkage evaluation requires Windows CPython 3.12.10')
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode,
            "GATE_C_RUNNER_FLAGS",
            'Invoke operational record-linkage evaluation with Python flags -I -B')


def _repository_guard(repository, authorization_path):
    repository = repository.resolve(strict=True)
    authorization_path = authorization_path.resolve(strict=True)
    require(repository.is_dir() and authorization_path.is_file(),
            "GATE_C_RUNNER_PATH", "Repository or authorization path is invalid")
    head = _git(repository, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    require(_COMMIT.fullmatch(head) is not None, "GATE_C_RUNNER_HEAD",
            "Cannot resolve a canonical Git HEAD")
    status = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    require(status == b"", "GATE_C_RUNNER_DIRTY",
            'Repository must be clean before operational record-linkage evaluation')
    ancestry = subprocess.run(
        ("git", "-C", str(repository), "merge-base", "--is-ancestor",
         MINIMUM_SOURCE_COMMIT, head), cwd=repository,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
        env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    )
    require(ancestry.returncode == 0, "GATE_C_RUNNER_ANCESTRY",
            "Current HEAD does not descend from the verified attack-adapter commit")
    for relative, expected in DEPENDENCY_HASHES.items():
        path = repository / relative
        require(path.is_file() and _sha256(path.read_bytes()) == expected,
                "GATE_C_RUNNER_DEPENDENCY", "Dependency identity differs: " + relative)
    authorization_bytes = authorization_path.read_bytes()
    authorization = parse_authorization(authorization_bytes, head)
    return repository, head, authorization, authorization_bytes


def _configuration_artifacts(*, config_id, canonical_rids, source_rows,
                             master_permutation, hierarchy_tables,
                             target_private, target_receipt, noise_private,
                             noise_receipt, release_rows, is_outlier,
                             transformation_by_name, release_receipt,
                             producer_report_bytes, source_input_sha256,
                             fixture_mode=False, numpy_module=None,
                             score_ready_callback=None):

    score = prepare_attack_score_state(
        config_id=config_id, scenario="BASE", canonical_rids=canonical_rids,
        source_rows=source_rows, release_rows=release_rows,
        is_outlier=is_outlier, master_permutation=master_permutation,
        hierarchy_tables=hierarchy_tables,
        transformation_by_name=transformation_by_name,
        target_private=target_private, target_receipt=target_receipt,
        noise_private=noise_private, noise_receipt=noise_receipt,
        release_validation_receipt=release_receipt,
        source_input_sha256=source_input_sha256,
        producer_report_bytes=producer_report_bytes,
        fixture_mode=fixture_mode,
    )


    score_payload_data = _json_bytes(score["score_payload"])
    require(_sha256(score_payload_data)
            == score["score_state"]["score_payload_sha256"],
            "GATE_C_RUNNER_SCORE_SERIALIZATION",
            "Score payload bytes differ from the pre-join score commitment")
    if score_ready_callback is not None:
        score_ready_callback(config_id, score["score_payload"],
                             score["score_state"], score["bounded_receipt"])
    permutation = prepare_permutation_control(
        config_id=config_id, canonical_rids=canonical_rids,
        master_permutation=master_permutation, is_outlier=is_outlier,
        gate_b_receipt=release_receipt, score_state=score["score_state"],
        fixture_mode=fixture_mode, numpy_module=numpy_module,
    )
    evaluations = OrderedDict()
    for role in ("ACTUAL", "PERMUTED"):
        evaluations[role] = evaluate_attack_score_payload(
            score_payload=score["score_payload"],
            score_state=score["score_state"],
            score_receipt=score["bounded_receipt"],
            target_private=target_private, target_receipt=target_receipt,
            canonical_rids=canonical_rids, source_rows=source_rows,
            permutation_private=permutation["private_record"],
            permutation_receipt=permutation["bounded_receipt"],
            mapping_role=role, fixture_mode=fixture_mode,
        )
    return {
        "score_payload": score["score_payload"],
        "score_state": score["score_state"],
        "score_receipt": score["bounded_receipt"],
        "permutation_private": permutation["private_record"],
        "permutation_receipt": permutation["bounded_receipt"],
        "actual_private": evaluations["ACTUAL"]["private_record"],
        "actual_receipt": evaluations["ACTUAL"]["bounded_receipt"],
        "permuted_private": evaluations["PERMUTED"]["private_record"],
        "permuted_receipt": evaluations["PERMUTED"]["bounded_receipt"],
    }


def prepare_gate_c_records(*, canonical_rids, source_rows, master_permutation,
                           hierarchy_tables, target_private, target_receipt,
                           anonymized_configurations, source_input_sha256,
                           fixture_mode=False, numpy_module=None,
                           fixture_draw_count=None,
                           persist_score_callback=None):

    require(type(fixture_mode) is bool, "GATE_C_RUNNER_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    require(isinstance(anonymized_configurations, Mapping),
            "GATE_C_RUNNER_CONFIGURATIONS", "Configurations must be a mapping")
    supplied = tuple(anonymized_configurations)
    require("CFG00" not in supplied
            and all(cfg in _ANONYMIZED_CONFIGURATIONS for cfg in supplied),
            "GATE_C_RUNNER_CONFIG_IDS", "Supply only CFG01 through CFG16")
    if not fixture_mode:
        require(supplied == _ANONYMIZED_CONFIGURATIONS,
                "GATE_C_RUNNER_OPERATIONAL_MATRIX",
                'Operational record-linkage evaluation requires ordered CFG01 through CFG16')
    else:
        require(bool(supplied), "GATE_C_RUNNER_EMPTY_FIXTURE",
                'Synthetic record-linkage evaluation requires at least one anonymized CFG')
        require(type(fixture_draw_count) is int and fixture_draw_count >= 1,
                "GATE_C_RUNNER_FIXTURE_DRAWS",
                'Synthetic record-linkage evaluation requires an explicit fixture_draw_count')
    if not fixture_mode:
        require(fixture_draw_count is None, "GATE_C_RUNNER_OPERATIONAL_DRAWS",
                "Operational draw count cannot be overridden")
    for cfg, value in anonymized_configurations.items():
        exact_keys(value, _CFG_INPUT_KEYS, cfg + " input")

    raw = prepare_cfg00_raw_control(
        canonical_rids=canonical_rids, source_rows=source_rows,
        master_permutation=master_permutation,
        source_input_sha256=source_input_sha256,
        fixture_mode=fixture_mode,
    )
    target_count = target_private.get("target_count")
    noise = prepare_noise_matrices(
        fixture_mode=fixture_mode,
        fixture_target_count=target_count if fixture_mode else None,
        fixture_draw_count=fixture_draw_count if fixture_mode else None,
        numpy_module=numpy_module,
    )
    oracle = run_attack_oracle()
    zero = {attribute: 0 for attribute in QIS}
    complete_inputs = OrderedDict()
    complete_inputs["CFG00"] = {
        "release_rows": source_rows,
        "is_outlier": [False] * len(source_rows),
        "transformation_by_name": zero,
        "gate_b_receipt": raw["bounded_receipt"],
        "producer_report_bytes": None,
    }
    complete_inputs.update(anonymized_configurations)

    artifacts = OrderedDict()
    gate_records = OrderedDict()
    for config_id, inputs in complete_inputs.items():


        result = _configuration_artifacts(
            config_id=config_id, canonical_rids=canonical_rids,
            source_rows=source_rows, master_permutation=master_permutation,
            hierarchy_tables=hierarchy_tables, target_private=target_private,
            target_receipt=target_receipt, noise_private=noise["private_record"],
            noise_receipt=noise["bounded_receipt"],
            release_rows=inputs["release_rows"],
            is_outlier=inputs["is_outlier"],
            transformation_by_name=inputs["transformation_by_name"],
            release_receipt=inputs["gate_b_receipt"],
            producer_report_bytes=inputs["producer_report_bytes"],
            source_input_sha256=source_input_sha256,
            fixture_mode=fixture_mode, numpy_module=numpy_module,
            score_ready_callback=persist_score_callback,
        )
        artifacts[config_id] = result
        gate_records[config_id] = {
            key: result[key] for key in (
                "score_state", "score_receipt", "permutation_receipt",
                "actual_private", "actual_receipt",
                "permuted_private", "permuted_receipt",
            )
        }
    gate = collect_gate_c(
        canonical_rids=canonical_rids, oracle_receipt=oracle,
        configurations=gate_records, fixture_mode=fixture_mode,
    )
    return {
        "raw_control": raw,
        "noise": noise,
        "oracle_receipt": oracle,
        "configurations": artifacts,
        "gate_c_receipt": gate,
    }


def _write_new(path, data):
    require(not path.exists(), "GATE_C_RUNNER_OUTPUT_EXISTS",
            "Refusing to overwrite artifact: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "GATE_C_RUNNER_TEMP_EXISTS",
            "Temporary output already exists: " + str(temporary))
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _checkpoint_bytes(artifacts):
    return OrderedDict((
        ("score_payload.private.json", _json_bytes(artifacts["score_payload"])),
        ("score_state.json", _json_bytes(artifacts["score_state"])),
        ("score_receipt.json", score_receipt_bytes(artifacts["score_receipt"])),
        ("permutation.private.json",
         permutation_private_bytes(artifacts["permutation_private"])),
        ("permutation_receipt.json",
         permutation_receipt_bytes(artifacts["permutation_receipt"])),
        ("actual_evaluation.private.json",
         evaluation_private_bytes(artifacts["actual_private"])),
        ("actual_evaluation_receipt.json",
         evaluation_receipt_bytes(artifacts["actual_receipt"])),
        ("permuted_evaluation.private.json",
         evaluation_private_bytes(artifacts["permuted_private"])),
        ("permuted_evaluation_receipt.json",
         evaluation_receipt_bytes(artifacts["permuted_receipt"])),
    ))


def _begin_checkpoint(root, config_id, score_payload, score_state, score_receipt):

    pending = root / (config_id + ".pending")
    complete = root / config_id
    require(not pending.exists() and not complete.exists(),
            "GATE_C_RUNNER_CHECKPOINT_EXISTS",
            "Checkpoint already exists for " + config_id)
    pending.mkdir(parents=True, exist_ok=False)
    initial = OrderedDict((
        ("score_payload.private.json", _json_bytes(score_payload)),
        ("score_state.json", _json_bytes(score_state)),
        ("score_receipt.json", score_receipt_bytes(score_receipt)),
    ))
    for name, data in initial.items():
        _write_new(pending / name, data)
    return pending


def _finish_checkpoint(root, config_id, artifacts, elapsed_seconds):
    pending = root / (config_id + ".pending")
    complete = root / config_id
    require(pending.is_dir() and not complete.exists(),
            "GATE_C_RUNNER_CHECKPOINT_PHASE",
            "Durable pre-join score checkpoint is absent for " + config_id)
    all_bytes = _checkpoint_bytes(artifacts)
    for name in _CHECKPOINT_FILES[:3]:
        require((pending / name).read_bytes() == all_bytes[name],
                "GATE_C_RUNNER_SCORE_CHECKPOINT_CHANGED",
                "Pre-join score checkpoint changed for " + config_id)
    for name in _CHECKPOINT_FILES[3:]:
        _write_new(pending / name, all_bytes[name])
    records = OrderedDict(
        (name, _artifact((pending / name).read_bytes()))
        for name in _CHECKPOINT_FILES
    )
    marker = {
        "record_schema": CHECKPOINT_SCHEMA,
        "result": "PASS",
        "effective_protocol": PROTOCOL_VERSION,
        "config_id": config_id,
        "stage_order": [
            "complete_BASE_scores", "persist_score_commitment",
            "generate_sigma_after_scores", "join_ACTUAL_ground_truth",
            "join_PERMUTED_ground_truth", "close_checkpoint",
        ],
        "score_persisted_before_ground_truth": True,
        "artifacts": records,
        "wall_clock_seconds": elapsed_seconds,
        "holdout_accessed": False,
        "model_fit_executed": False,
        "numeric_risk_pass_fail_criterion": None,
    }
    _write_new(pending / "CHECKPOINT.json", _json_bytes(marker))
    pending.replace(complete)
    return marker


def _load_checkpoint(root, config_id):
    directory = root / config_id
    require(directory.is_dir() and not (root / (config_id + ".pending")).exists(),
            "GATE_C_RUNNER_CHECKPOINT_INCOMPLETE",
            "Checkpoint is absent or partial for " + config_id)
    marker, _ = _read_json(directory / "CHECKPOINT.json", config_id + " checkpoint")
    require(marker.get("record_schema") == CHECKPOINT_SCHEMA
            and marker.get("result") == "PASS"
            and marker.get("config_id") == config_id
            and marker.get("score_persisted_before_ground_truth") is True,
            "GATE_C_RUNNER_CHECKPOINT_MARKER",
            "Checkpoint marker is invalid for " + config_id)
    expected = marker.get("artifacts")
    require(isinstance(expected, Mapping) and set(expected) == set(_CHECKPOINT_FILES),
            "GATE_C_RUNNER_CHECKPOINT_SCOPE",
            "Checkpoint artifact scope differs for " + config_id)
    values = {}
    for name in _CHECKPOINT_FILES:
        value, data = _read_json(directory / name, config_id + " " + name)
        require(expected[name] == _artifact(data),
                "GATE_C_RUNNER_CHECKPOINT_HASH",
                "Checkpoint artifact identity differs: " + config_id + "/" + name)
        values[name] = value
    schema_by_name = {
        "score_payload.private.json": SCORE_PAYLOAD_SCHEMA,
        "score_state.json": SCORE_STATE_SCHEMA,
        "score_receipt.json": SCORE_RECEIPT_SCHEMA,
        "permutation.private.json": PERMUTATION_PRIVATE_SCHEMA,
        "permutation_receipt.json": PERMUTATION_RECEIPT_SCHEMA,
        "actual_evaluation.private.json": EVALUATION_PRIVATE_SCHEMA,
        "actual_evaluation_receipt.json": EVALUATION_RECEIPT_SCHEMA,
        "permuted_evaluation.private.json": EVALUATION_PRIVATE_SCHEMA,
        "permuted_evaluation_receipt.json": EVALUATION_RECEIPT_SCHEMA,
    }
    for name, schema in schema_by_name.items():
        require(values[name].get("record_schema") == schema,
                "GATE_C_RUNNER_CHECKPOINT_SCHEMA",
                "Checkpoint schema differs: " + config_id + "/" + name)
    return {
        "score_payload": values["score_payload.private.json"],
        "score_state": values["score_state.json"],
        "score_receipt": values["score_receipt.json"],
        "permutation_private": values["permutation.private.json"],
        "permutation_receipt": values["permutation_receipt.json"],
        "actual_private": values["actual_evaluation.private.json"],
        "actual_receipt": values["actual_evaluation_receipt.json"],
        "permuted_private": values["permuted_evaluation.private.json"],
        "permuted_receipt": values["permuted_evaluation_receipt.json"],
    }, marker


def _validate_resumed_artifacts(*, config_id, artifacts, canonical_rids,
                                source_rows, master_permutation, target_private,
                                target_receipt, is_outlier, release_receipt,
                                fixture_mode=False, numpy_module=None):

    expected_permutation = prepare_permutation_control(
        config_id=config_id, canonical_rids=canonical_rids,
        master_permutation=master_permutation, is_outlier=is_outlier,
        gate_b_receipt=release_receipt,
        score_state=artifacts["score_state"], fixture_mode=fixture_mode,
        numpy_module=numpy_module,
    )
    require(artifacts["permutation_private"]
            == expected_permutation["private_record"]
            and artifacts["permutation_receipt"]
            == expected_permutation["bounded_receipt"],
            "GATE_C_RUNNER_RESUME_PERMUTATION",
            "Resumed sigma/mapping differs from exact regeneration for " + config_id)
    for role, private_key, receipt_key in (
        ("ACTUAL", "actual_private", "actual_receipt"),
        ("PERMUTED", "permuted_private", "permuted_receipt"),
    ):
        expected = evaluate_attack_score_payload(
            score_payload=artifacts["score_payload"],
            score_state=artifacts["score_state"],
            score_receipt=artifacts["score_receipt"],
            target_private=target_private, target_receipt=target_receipt,
            canonical_rids=canonical_rids, source_rows=source_rows,
            permutation_private=expected_permutation["private_record"],
            permutation_receipt=expected_permutation["bounded_receipt"],
            mapping_role=role, fixture_mode=fixture_mode,
        )
        require(artifacts[private_key] == expected["private_record"]
                and artifacts[receipt_key] == expected["bounded_receipt"],
                "GATE_C_RUNNER_RESUME_EVALUATION",
                "Resumed evaluation differs from exact reconstruction for "
                + config_id + "/" + role)


def _load_operational_inputs(repository, run_root, head, authorization_hash):
    source_rows, source_data = _read_table(
        repository / SOURCE_RELATIVE, ";", PHYSICAL_SCHEMA, "Adult training input",
        identity=(EXPECTED_SOURCE_BYTES, SOURCE_INPUT_SHA256),
    )
    require(len(source_rows) == POPULATION_SIZE, "GATE_C_RUNNER_SOURCE_ROWS",
            "Adult training input must contain exactly 30162 rows")
    rids, rid_data = _read_lines(repository / RID_RELATIVE, "canonical RID order",
                                 EXPECTED_RID_SHA256)
    master, master_data = _read_lines(
        repository / MASTER_RELATIVE, "master permutation",
        EXPECTED_MASTER_SHA256, parser=int)
    require(sorted(master) == list(range(POPULATION_SIZE)),
            "GATE_C_RUNNER_MASTER_BIJECTION",
            "Master permutation is not a complete zero-based bijection")

    target_private, target_private_data = _read_json(
        repository / PRIVATE_RELATIVE / "target_sample.private.json",
        "private target sample")
    target_receipt, target_receipt_data = _read_json(
        run_root / "pre_output_target_sample_receipt.json",
        "target-sample receipt")
    require(target_receipt.get("repository_head") == head
            and target_receipt.get("authorization_record_sha256") == authorization_hash,
            "GATE_C_RUNNER_TARGET_CONTEXT",
            "Target sample does not bind current HEAD and authorization")

    summary, summary_data = _read_json(run_root / "gate_b_matrix_summary.json",
                                       'Anonymization validation matrix summary')
    require(summary.get("record_schema") == "gate-b-matrix-v1.2.4/1.0"
            and summary.get("result") == "PASS"
            and summary.get("repository_head") == head
            and summary.get("authorization_record_sha256") == authorization_hash
            and summary.get("configuration_count") == 16
            and summary.get("configurations") == list(_ANONYMIZED_CONFIGURATIONS)
            and summary.get("gate_b") == "PASS"
            and summary.get("gate_c") == "pending",
            "GATE_C_RUNNER_GATE_B_SUMMARY",
            'Anonymization validation matrix summary does not bind the complete current run')

    hierarchies = OrderedDict()
    hierarchy_artifacts = OrderedDict()
    for attribute, (relative, byte_count, digest, width) in HIERARCHY_SPECS.items():
        path = repository / relative
        hierarchies[attribute] = _read_hierarchy(
            path, attribute, byte_count, digest, width)
        hierarchy_artifacts[attribute] = {
            "relative_path": relative, "bytes": byte_count, "sha256": digest,
        }

    input_artifacts = OrderedDict()
    for config_id in _ANONYMIZED_CONFIGURATIONS:
        _configuration, artifacts = _read_operational_configuration(
            run_root, config_id, head, authorization_hash)
        input_artifacts[config_id] = artifacts
    context = {
        "source_input": _artifact(source_data),
        "rid_order": _artifact(rid_data),
        "master_permutation": _artifact(master_data),
        "target_private": _artifact(target_private_data),
        "target_receipt": _artifact(target_receipt_data),
        "gate_b_matrix_summary": _artifact(summary_data),
        "hierarchies": hierarchy_artifacts,
        "configurations": input_artifacts,
    }
    return {
        "canonical_rids": rids,
        "source_rows": source_rows,
        "master_permutation": master,
        "target_private": target_private,
        "target_receipt": target_receipt,
        "hierarchy_tables": hierarchies,
        "run_root": run_root,
        "repository_head": head,
        "authorization_record_sha256": authorization_hash,
        "source_input_sha256": _sha256(source_data),
        "context": context,
    }


def _read_operational_configuration(run_root, config_id, head,
                                    authorization_hash):

    require(config_id in _ANONYMIZED_CONFIGURATIONS,
            "GATE_C_RUNNER_CFG_LOAD", "Only CFG01 through CFG16 may be loaded")
    directory = run_root / config_id
    output_rows, output_data = _read_table(
        directory / (config_id + ".full.tsv"), "\t", PHYSICAL_SCHEMA,
        config_id + " full output")
    report, report_data = _read_json(
        directory / (config_id + ".java-report.json"),
        config_id + " Java report")
    gate_b, gate_b_data = _read_json(
        directory / (config_id + ".gate-b.json"),
        config_id + ' anonymization validation receipt')
    authorization = report.get("authorization")
    require(isinstance(authorization, Mapping)
            and authorization.get("record_sha256") == authorization_hash
            and authorization.get("authorized_source_commit") == head
            and authorization.get("main_runs_authorized") is True,
            "GATE_C_RUNNER_JAVA_AUTHORIZATION",
            "Java report does not bind current authorization: " + config_id)
    require(report.get("main_runs_executed") is True
            and report.get("anonymization_invoked") is True,
            "GATE_C_RUNNER_JAVA_EXECUTION",
            "Java execution status is incomplete: " + config_id)
    mask = report.get("outlier_mask")
    transformation = report.get("transformation_by_name")
    require(isinstance(mask, Mapping) and isinstance(mask.get("values"), list)
            and len(mask["values"]) == POPULATION_SIZE
            and all(type(value) is bool for value in mask["values"]),
            "GATE_C_RUNNER_OUTLIER_MASK",
            "Java outlier mask is invalid: " + config_id)
    exact_keys(transformation, QIS, config_id + " transformation")
    require(all(type(value) is int and value >= 0
                for value in transformation.values()),
            "GATE_C_RUNNER_TRANSFORMATION",
            "Java transformation vector is invalid: " + config_id)
    return ({
        "release_rows": output_rows,
        "is_outlier": mask["values"],
        "transformation_by_name": transformation,
        "gate_b_receipt": gate_b,
        "producer_report_bytes": report_data,
    }, {
        "full_output": _artifact(output_data),
        "java_report": _artifact(report_data),
        "gate_b_receipt": _artifact(gate_b_data),
    })


def _session_record(head, authorization_hash, context):
    return {
        "record_schema": SESSION_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "repository_head": head,
        "authorization_record_sha256": authorization_hash,
        "configuration_order": list(ALL_CONFIGURATIONS),
        "input_context": context,
        "gate_b_required": "PASS",
        "gate_c_initial": "pending",
        "score_scenario": "BASE",
        "score_before_ground_truth_required": True,
        "numeric_risk_acceptance_ranges": None,
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
    }


def _prepare_common(session_root, inputs, numpy_module):
    common = session_root / "common"
    if common.exists():
        require(common.is_dir(), "GATE_C_RUNNER_COMMON", "Common checkpoint is invalid")
        raw_receipt, raw_receipt_data = _read_json(common / "cfg00_raw_control_receipt.json",
                                                   "CFG00 raw-control receipt")
        raw_data = (common / "cfg00_raw_control.tsv").read_bytes()
        noise_private, noise_private_data = _read_json(common / "noise.private.json",
                                                       "private noise")
        noise_receipt, noise_receipt_data = _read_json(common / "noise_receipt.json",
                                                       "noise receipt")
        oracle, oracle_data = _read_json(common / "attack_oracle_receipt.json",
                                         "attack oracle receipt")
        expected_raw = prepare_cfg00_raw_control(
            canonical_rids=inputs["canonical_rids"],
            source_rows=inputs["source_rows"],
            master_permutation=inputs["master_permutation"],
            source_input_sha256=inputs["source_input_sha256"],
        )
        expected_noise = prepare_noise_matrices(numpy_module=numpy_module)
        require(raw_data == expected_raw["release_tsv_bytes"]
                and raw_receipt == expected_raw["bounded_receipt"]
                and noise_private == expected_noise["private_record"]
                and noise_receipt == expected_noise["bounded_receipt"]
                and _sha256(raw_data) == raw_receipt.get("release_output_sha256")
                and _sha256(raw_receipt_data) == _sha256(raw_control_receipt_bytes(raw_receipt))
                and _sha256(noise_private_data) == _sha256(noise_private_bytes(noise_private))
                and _sha256(noise_receipt_data) == _sha256(noise_receipt_bytes(noise_receipt))
                and oracle == run_attack_oracle()
                and _sha256(oracle_data) == _sha256(_json_bytes(oracle)),
                "GATE_C_RUNNER_COMMON_BINDING",
                "Common checkpoint differs from its bound artifacts")
        return {
            "raw_control": {"release_tsv_bytes": raw_data,
                            "bounded_receipt": raw_receipt},
            "noise": {"private_record": noise_private,
                      "bounded_receipt": noise_receipt},
            "oracle_receipt": oracle,
        }
    pending = session_root / "common.pending"
    require(not pending.exists(), "GATE_C_RUNNER_COMMON_PARTIAL",
            "A partial common checkpoint exists; preserve it and stop for review")
    pending.mkdir(parents=True, exist_ok=False)
    raw = prepare_cfg00_raw_control(
        canonical_rids=inputs["canonical_rids"],
        source_rows=inputs["source_rows"],
        master_permutation=inputs["master_permutation"],
        source_input_sha256=inputs["source_input_sha256"],
    )
    noise = prepare_noise_matrices(numpy_module=numpy_module)
    oracle = run_attack_oracle()
    _write_new(pending / "cfg00_raw_control.tsv", raw["release_tsv_bytes"])
    _write_new(pending / "cfg00_raw_control_receipt.json",
               raw_control_receipt_bytes(raw["bounded_receipt"]))
    _write_new(pending / "noise.private.json",
               noise_private_bytes(noise["private_record"]))
    _write_new(pending / "noise_receipt.json",
               noise_receipt_bytes(noise["bounded_receipt"]))
    _write_new(pending / "attack_oracle_receipt.json", _json_bytes(oracle))
    pending.replace(common)
    return {"raw_control": raw, "noise": noise, "oracle_receipt": oracle}


def _prepare_one_operational(session_root, config_id, inputs, common, numpy_module):
    if config_id == "CFG00":
        cfg = {
            "release_rows": inputs["source_rows"],
            "is_outlier": [False] * len(inputs["source_rows"]),
            "transformation_by_name": {attribute: 0 for attribute in QIS},
            "gate_b_receipt": common["raw_control"]["bounded_receipt"],
            "producer_report_bytes": None,
        }
    else:
        cfg, observed_artifacts = _read_operational_configuration(
            inputs["run_root"], config_id, inputs["repository_head"],
            inputs["authorization_record_sha256"])
        require(observed_artifacts
                == inputs["context"]["configurations"][config_id],
                "GATE_C_RUNNER_CFG_CONTEXT_CHANGED",
                'Anonymization validation artifacts changed after session binding: ' + config_id)
    if (session_root / config_id).is_dir():
        artifacts, marker = _load_checkpoint(session_root, config_id)
        _validate_resumed_artifacts(
            config_id=config_id, artifacts=artifacts,
            canonical_rids=inputs["canonical_rids"],
            source_rows=inputs["source_rows"],
            master_permutation=inputs["master_permutation"],
            target_private=inputs["target_private"],
            target_receipt=inputs["target_receipt"],
            is_outlier=cfg["is_outlier"],
            release_receipt=cfg["gate_b_receipt"],
            numpy_module=numpy_module,
        )
        return artifacts, marker
    require(not (session_root / (config_id + ".pending")).exists(),
            "GATE_C_RUNNER_PARTIAL_CFG",
            "Partial checkpoint exists for " + config_id + "; preserve and review")
    started = time.perf_counter()
    def persist_score(observed_config_id, payload, state, receipt):
        require(observed_config_id == config_id,
                "GATE_C_RUNNER_SCORE_CALLBACK_CFG",
                "Score callback received the wrong configuration")
        _begin_checkpoint(session_root, config_id, payload, state, receipt)

    artifacts = _configuration_artifacts(
        config_id=config_id, canonical_rids=inputs["canonical_rids"],
        source_rows=inputs["source_rows"],
        master_permutation=inputs["master_permutation"],
        hierarchy_tables=inputs["hierarchy_tables"],
        target_private=inputs["target_private"],
        target_receipt=inputs["target_receipt"],
        noise_private=common["noise"]["private_record"],
        noise_receipt=common["noise"]["bounded_receipt"],
        release_rows=cfg["release_rows"], is_outlier=cfg["is_outlier"],
        transformation_by_name=cfg["transformation_by_name"],
        release_receipt=cfg["gate_b_receipt"],
        producer_report_bytes=cfg["producer_report_bytes"],
        source_input_sha256=inputs["source_input_sha256"],
        numpy_module=numpy_module, score_ready_callback=persist_score,
    )
    marker = _finish_checkpoint(
        session_root, config_id, artifacts, time.perf_counter() - started)
    return artifacts, marker


def _publish(run_root, session_root, common, gate_receipt,
             session, checkpoints, started_at, elapsed):
    final = run_root / "gate_c"
    pending = run_root / "gate_c.pending"
    require(not final.exists() and not pending.exists(),
            "GATE_C_RUNNER_PUBLIC_EXISTS",
            'Record-linkage evaluation public output or pending output already exists')
    pending.mkdir(parents=True, exist_ok=False)
    _write_new(pending / "cfg00_raw_control.tsv",
               common["raw_control"]["release_tsv_bytes"])
    _write_new(pending / "cfg00_raw_control_receipt.json",
               raw_control_receipt_bytes(common["raw_control"]["bounded_receipt"]))
    _write_new(pending / "noise_receipt.json",
               noise_receipt_bytes(common["noise"]["bounded_receipt"]))
    _write_new(pending / "attack_oracle_receipt.json",
               _json_bytes(common["oracle_receipt"]))
    for config_id in ALL_CONFIGURATIONS:
        source = session_root / config_id
        destination = pending / config_id
        destination.mkdir(parents=True, exist_ok=False)
        for name in _PUBLIC_CHECKPOINT_FILES:
            _write_new(destination / name, (source / name).read_bytes())
    gate_data = gate_c_receipt_bytes(gate_receipt)
    _write_new(pending / "gate_c_receipt.json", gate_data)
    summary = {
        "record_schema": RUNNER_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "gate_a": "PASS_PRESERVED",
        "step8_technical_registration": "PASS_PRESERVED",
        "gate_b": "PASS",
        "gate_c": "PASS",
        "repository_head": session["repository_head"],
        "authorization_record_sha256": session["authorization_record_sha256"],
        "configuration_count": len(ALL_CONFIGURATIONS),
        "configuration_order": list(ALL_CONFIGURATIONS),
        "checkpoint_receipt_sha256": {
            config_id: json_digest(checkpoints[config_id])
            for config_id in ALL_CONFIGURATIONS
        },
        "gate_c_receipt": _artifact(gate_data),
        "execution_started_at_utc": started_at,
        "execution_completed_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "wall_clock_seconds": elapsed,
        "resume_supported_from_complete_private_cfg_checkpoints": True,
        "base_scenario_executed": True,
        "sensitivity_scenarios_executed": False,
        "bootstrap_executed": False,
        "holdout_accessed": False,
        "model_fits_executed": False,
        "raw_to_model_end_to_end_verified": False,
        "production_pipeline_verified": False,
        "numeric_risk_pass_fail_criterion": None,
        "main_run_authorization_granted_by_this_artifact": False,
    }
    _write_new(pending / "gate_c_runner_summary.json", _json_bytes(summary))
    pending.replace(final)
    return summary, final


def run_operational(repository, authorization_path):

    _runtime_guard()
    repository, head, _authorization, authorization_data = _repository_guard(
        repository, authorization_path)
    authorization_hash = _sha256(authorization_data)
    run_root = repository / RUN_RELATIVE
    private_root = repository / PRIVATE_RELATIVE
    require(run_root.is_dir() and private_root.is_dir(),
            "GATE_C_RUNNER_MAIN_ROOTS",
            'Anonymization validation run/private roots are missing')
    require(not (run_root / "gate_c").exists(), "GATE_C_RUNNER_ALREADY_COMPLETE",
            'Record-linkage evaluation public output already exists')
    inputs = _load_operational_inputs(
        repository, run_root, head, authorization_hash)

    session_root = private_root / "gate_c"
    session_data = _session_record(head, authorization_hash, inputs["context"])
    if session_root.exists():
        require(session_root.is_dir(), "GATE_C_RUNNER_SESSION_PATH",
                'Private record-linkage evaluation session path is not a directory')
        observed, observed_data = _read_json(session_root / "SESSION.json",
                                             'Record-linkage evaluation session')
        require(observed == session_data
                and observed_data == _json_bytes(session_data),
                "GATE_C_RUNNER_SESSION_CONTEXT",
                "Existing session does not bind the exact current inputs")
    else:
        session_root.mkdir(parents=True, exist_ok=False)
        _write_new(session_root / "SESSION.json", _json_bytes(session_data))

    import numpy as np
    require(np.__version__ == EXPECTED_NUMPY, "GATE_C_RUNNER_NUMPY",
            'Operational record-linkage evaluation requires pinned NumPy 2.0.2')
    common = _prepare_common(session_root, inputs, np)
    gate_records = OrderedDict()
    checkpoints = OrderedDict()
    started_clock = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for config_id in ALL_CONFIGURATIONS:
        print("CHECKPOINT=" + config_id + "_START", flush=True)
        artifacts, marker = _prepare_one_operational(
            session_root, config_id, inputs, common, np)
        checkpoints[config_id] = marker
        gate_records[config_id] = {
            key: artifacts[key] for key in (
                "score_state", "score_receipt", "permutation_receipt",
                "actual_private", "actual_receipt",
                "permuted_private", "permuted_receipt",
            )
        }
        print("CHECKPOINT=" + config_id + "_PASS", flush=True)
    gate = collect_gate_c(
        canonical_rids=inputs["canonical_rids"],
        oracle_receipt=common["oracle_receipt"],
        configurations=gate_records,
    )
    elapsed = time.perf_counter() - started_clock
    summary, output = _publish(
        run_root, session_root, common, gate, session_data,
        checkpoints, started_at, elapsed)
    return summary, output


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--authorization-record", type=Path, required=True)
    args = parser.parse_args(argv)
    summary, output = run_operational(args.repository, args.authorization_record)
    print("RESULT=GATE_C_OPERATIONAL_PASS")
    print("HEAD=" + summary["repository_head"])
    print("OUTPUT=" + str(output))
    print("GATE_B=PASS")
    print("GATE_C=PASS")
    print("SENSITIVITY_SCENARIOS_EXECUTED=false")
    print("BOOTSTRAP_EXECUTED=false")
    print("HOLDOUT_ACCESSED=false")
    print("MODEL_FITS_EXECUTED=false")
    print("RAW_TO_MODEL_END_TO_END_VERIFIED=false")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("RESULT=GATE_C_OPERATIONAL_FAIL", file=sys.stderr)
        print("ERROR=" + str(error).replace("\r", " ").replace("\n", " "),
              file=sys.stderr)
        raise SystemExit(1)
