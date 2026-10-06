"""Run a validated record-linkage continuation."""
from __future__ import annotations

import argparse
from collections import OrderedDict
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile

TOOL_REVISION = "1.1"
RECORD_SCHEMA = "gate-c-authorized-overlay-continuation-v1.2.4/1.0"
HEAD = "f479fbabe2422315f98dd0d39ade2f26d92aef04"
TREE = "82dcf163bf1a1123c2bf2e7bec54ac0a002b1e52"
RUNNER_SHA256 = "59a4e12cf232f8f1e1175c6a8c9c86537b5e37c9473093160504ef86ba5253a2"
OVERLAY_FILE = "attack_compatibility_overlay.py"
LAUNCHER_FILE = "run_authorized_attack_continuation.py"
TEST_FILE = "test_gate_c_authorized_overlay_continuation_f479fbab_v1_2_4.py"
OVERLAY_IDENTITY = {"bytes": 15380, "sha256": "2988a0e45c39189609195e348207274c7a3fbe6959afd9a962cbff9285693dbc"}
AUTH_FILE = "evidence/gate_c_execution_authorization_f479fbab_overlay_2988a0e4_v1_2_4.txt"
AUTHORIZATION_ID = "AUTH-2026-09-14-GATE_C_OVERLAY_F479FBAB_2988A0E4"
AUTHORIZATION_IDENTITY = {"bytes": 1301, "sha256": "bbafc4cda1521b0aaeec70b76a73d89ba80238470f4aea518a688ddd8fc848e1"}
MAIN_AUTH_FILE = "evidence/main_run_authorization_f479fbab_v1_2_4.txt"
MAIN_AUTHORIZATION_ID = "AUTH-2026-09-13-GATE_B_F479FBAB"
MAIN_AUTH_IDENTITY = {"bytes": 387, "sha256": "035cb52ad4c3c677f9fac8456442050338fa024f6cd09afe37b3b4d81d5276a6"}
GATE_B_FILE = "evidence/gate_b_completed_run_verification_receipt_f479fbab_v1_2_4.zip"
GATE_B_IDENTITY = {"bytes": 8850, "sha256": "c215235c7c992a76d1eccf31b89fb3fc3a43c2d625beda6bb0c274e260e1a6b1"}
PREFLIGHT_FILE = "evidence/gate_c_overlay_windows_preflight_f479fbab_v1_2_4_r1.zip"
PREFLIGHT_IDENTITY = {"bytes": 42957, "sha256": "6ead13d7cda620c063bb876cfbf87a7de00fa10ce6dd50afd101ec2c6327df79"}
INDEPENDENT_FILE = "evidence/gate_c_overlay_preflight_independent_verification_f479fbab_v1_2_4_r1.zip"
INDEPENDENT_IDENTITY = {"bytes": 2902, "sha256": "ee34755b4db345da6d6ea6815e6f7e1dbc065876ccee19e96741995e695304df"}
FAILED_REVIEW_FILE = "evidence/gate_c_authorized_execution_review_f479fbab_v1_2_4.zip"
FAILED_REVIEW_IDENTITY = {"bytes": 5185, "sha256": "aed5241c8d9025ca622b501ae3c82193f52a1e8ea889044a8344563f0669093d"}
FAILED_INDEPENDENT_FILE = "evidence/gate_c_failed_attempt_independent_review_f479fbab_v1_2_4.zip"
FAILED_INDEPENDENT_IDENTITY = {"bytes": 2083, "sha256": "52c0ca9085fa1fa4362cdef5190528fc4893e581ccf8c4da5d481454b2ebaf83"}
RUNTIME_PREFLIGHT_FILE = "evidence/gate_c_runtime_read_compatibility_windows_preflight_f479fbab_v1_2_4.zip"
RUNTIME_PREFLIGHT_IDENTITY = {"bytes": 34821, "sha256": "c263836fef450c8aca3101c34227e79d08770b6e5d21b2b40c3514da8bb87d6c"}
RUNTIME_INDEPENDENT_FILE = "evidence/gate_c_runtime_read_preflight_independent_verification_f479fbab_v1_2_4.zip"
RUNTIME_INDEPENDENT_IDENTITY = {"bytes": 2936, "sha256": "4923d7195fe35b58d6ebd6cdf8afcafe75e22a6172ef7b7cea65f91da4fedb14"}
ORIGINAL_LAUNCHER_IDENTITY = {"bytes": 36851, "sha256": "514efb91572cec80e8f4ebc439a1c7c8d65a5a6c0b0a9cbdb6253922a61694a6"}
FAILED_SESSION_IDENTITY = {"bytes": 11346, "sha256": "0505b472064adef0d31b80bb7f017f8446d6e5e78873c92dfadcc1fdfc3c69aa"}
NUMPY_RUNTIME_TREE = {"file_count": 1217, "total_bytes": 65455827, "tree_sha256": "4a4787bc55b8371c884cfaff1da41edcf026e413f9369b741fdb515ca7a622b2"}
CONTINUATION_AUTH_FILE = "evidence/gate_c_continuation_authorization_f479fbab_runtime_4a4787bc_v1_2_4.txt"
CONTINUATION_AUTHORIZATION_ID = "AUTH-2026-09-14-GATE_C_CONTINUE_F479FBAB_4A4787BC"
CONFIGURATIONS = tuple("CFG" + str(index).zfill(2) for index in range(17))
ANONYMIZED_CONFIGURATIONS = CONFIGURATIONS[1:]
PACKAGE_FILES = {
    OVERLAY_FILE, LAUNCHER_FILE,
    TEST_FILE, "INSTRUCTIONS.md",
    AUTH_FILE, MAIN_AUTH_FILE, GATE_B_FILE, PREFLIGHT_FILE, INDEPENDENT_FILE,
    FAILED_REVIEW_FILE, FAILED_INDEPENDENT_FILE,
    RUNTIME_PREFLIGHT_FILE, RUNTIME_INDEPENDENT_FILE, CONTINUATION_AUTH_FILE,
}
AUTH_KEYS = (
    "record_schema", "effective_protocol", "authorization_id", "authorized_at_utc",
    "authorized_source_commit", "authorized_runner_sha256",
    "main_run_authorization_id", "main_run_authorization_sha256",
    "gate_b_verification_receipt_sha256", "compatibility_overlay_sha256",
    "windows_preflight_review_sha256", "independent_preflight_verification_sha256",
    "authorized_configs", "authorized_action", "gate_c_execution_authorized",
    "gate_b_rerun_authorized", "post_gate_c_stop_required",
    "holdout_access_authorized", "bootstrap_authorized",
    "sensitivity_scenarios_authorized", "model_fits_authorized", "authorized_by",
)
AUTH_EXPECTED = OrderedDict((
    ("record_schema", "gate-c-execution-authorization/1.0"),
    ("effective_protocol", "v1.2.4"),
    ("authorization_id", AUTHORIZATION_ID),
    ("authorized_at_utc", "2026-09-14T09:30:33Z"),
    ("authorized_source_commit", HEAD),
    ("authorized_runner_sha256", RUNNER_SHA256),
    ("main_run_authorization_id", MAIN_AUTHORIZATION_ID),
    ("main_run_authorization_sha256", MAIN_AUTH_IDENTITY["sha256"]),
    ("gate_b_verification_receipt_sha256", GATE_B_IDENTITY["sha256"]),
    ("compatibility_overlay_sha256", OVERLAY_IDENTITY["sha256"]),
    ("windows_preflight_review_sha256", PREFLIGHT_IDENTITY["sha256"]),
    ("independent_preflight_verification_sha256", INDEPENDENT_IDENTITY["sha256"]),
    ("authorized_configs", ",".join(ANONYMIZED_CONFIGURATIONS)),
    ("authorized_action", "GATE_C_ONLY_EXISTING_GATE_B_RESULTS"),
    ("gate_c_execution_authorized", "true"),
    ("gate_b_rerun_authorized", "false"),
    ("post_gate_c_stop_required", "true"),
    ("holdout_access_authorized", "false"),
    ("bootstrap_authorized", "false"),
    ("sensitivity_scenarios_authorized", "false"),
    ("model_fits_authorized", "false"),
    ("authorized_by", "researcher"),
))
CONTINUATION_AUTH_KEYS = (
    "record_schema", "effective_protocol", "authorization_id", "authorized_at_utc",
    "authorized_source_commit", "authorized_source_tree", "authorized_runner_sha256",
    "authorized_overlay_sha256", "authorized_launcher_sha256",
    "main_run_authorization_id", "main_run_authorization_sha256",
    "original_gate_c_authorization_id", "original_gate_c_authorization_sha256",
    "gate_b_verification_receipt_sha256", "original_failed_review_sha256",
    "failed_attempt_independent_review_sha256", "runtime_preflight_review_sha256",
    "runtime_preflight_independent_verification_sha256", "numpy_runtime_tree_file_count",
    "numpy_runtime_tree_bytes", "numpy_runtime_tree_sha256", "failed_session_sha256",
    "authorized_configs", "authorized_action", "gate_c_continuation_authorized",
    "fresh_gate_c_restart_authorized", "gate_b_rerun_authorized",
    "post_gate_c_stop_required", "holdout_access_authorized", "bootstrap_authorized",
    "sensitivity_scenarios_authorized", "model_fits_authorized", "authorized_by",
)
CONTINUATION_FIXED = OrderedDict((
    ("record_schema", "gate-c-continuation-authorization/1.0"),
    ("effective_protocol", "v1.2.4"),
    ("authorization_id", CONTINUATION_AUTHORIZATION_ID),
    ("authorized_source_commit", HEAD),
    ("authorized_source_tree", TREE),
    ("authorized_runner_sha256", RUNNER_SHA256),
    ("authorized_overlay_sha256", OVERLAY_IDENTITY["sha256"]),
    ("main_run_authorization_id", MAIN_AUTHORIZATION_ID),
    ("main_run_authorization_sha256", MAIN_AUTH_IDENTITY["sha256"]),
    ("original_gate_c_authorization_id", AUTHORIZATION_ID),
    ("original_gate_c_authorization_sha256", AUTHORIZATION_IDENTITY["sha256"]),
    ("gate_b_verification_receipt_sha256", GATE_B_IDENTITY["sha256"]),
    ("original_failed_review_sha256", FAILED_REVIEW_IDENTITY["sha256"]),
    ("failed_attempt_independent_review_sha256", FAILED_INDEPENDENT_IDENTITY["sha256"]),
    ("runtime_preflight_review_sha256", RUNTIME_PREFLIGHT_IDENTITY["sha256"]),
    ("runtime_preflight_independent_verification_sha256", RUNTIME_INDEPENDENT_IDENTITY["sha256"]),
    ("numpy_runtime_tree_file_count", str(NUMPY_RUNTIME_TREE["file_count"])),
    ("numpy_runtime_tree_bytes", str(NUMPY_RUNTIME_TREE["total_bytes"])),
    ("numpy_runtime_tree_sha256", NUMPY_RUNTIME_TREE["tree_sha256"]),
    ("failed_session_sha256", FAILED_SESSION_IDENTITY["sha256"]),
    ("authorized_configs", ",".join(ANONYMIZED_CONFIGURATIONS)),
    ("authorized_action", "RESUME_GATE_C_FROM_EXACT_SESSION_ONLY"),
    ("gate_c_continuation_authorized", "true"),
    ("fresh_gate_c_restart_authorized", "false"),
    ("gate_b_rerun_authorized", "false"),
    ("post_gate_c_stop_required", "true"),
    ("holdout_access_authorized", "false"),
    ("bootstrap_authorized", "false"),
    ("sensitivity_scenarios_authorized", "false"),
    ("model_fits_authorized", "false"),
    ("authorized_by", "researcher"),
))
PRIVATE_CHECKPOINT_FILES = (
    "score_payload.private.json", "score_state.json", "score_receipt.json",
    "permutation.private.json", "permutation_receipt.json",
    "actual_evaluation.private.json", "actual_evaluation_receipt.json",
    "permuted_evaluation.private.json", "permuted_evaluation_receipt.json",
    "CHECKPOINT.json",
)
PUBLIC_CHECKPOINT_FILES = (
    "score_state.json", "score_receipt.json", "permutation_receipt.json",
    "actual_evaluation_receipt.json", "permuted_evaluation_receipt.json",
)


class ExecutionError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ExecutionError(message)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def file_identity(path):
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            count += len(block)
            digest.update(block)
    return {"bytes": count, "sha256": digest.hexdigest()}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def strict_text(data, name):
    require(isinstance(data, bytes) and data and data.endswith(b"\n")
            and not data.startswith(b"\xef\xbb\xbf") and b"\r" not in data
            and b"\0" not in data, name + " must be BOM-free strict LF text")
    try:
        return data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ExecutionError(name + " must be ASCII") from error


def parse_authorization(data):
    require(identity(data) == AUTHORIZATION_IDENTITY,
            'Record-linkage evaluation execution authorization identity differs')
    values = OrderedDict()
    for line in strict_text(data, 'Record-linkage evaluation execution authorization')[:-1].split("\n"):
        require(line.count("=") == 1 and not line.startswith("="),
                'Malformed record-linkage evaluation execution authorization line')
        key, value = line.split("=", 1)
        require(key not in values, 'Duplicate record-linkage evaluation execution authorization key')
        values[key] = value
    require(tuple(values) == AUTH_KEYS and values == AUTH_EXPECTED,
            'Record-linkage evaluation execution authorization content or order differs')
    return values


def parse_continuation_authorization(data, launcher_path):
    values = OrderedDict()
    for line in strict_text(data, 'Record-linkage evaluation continuation authorization')[:-1].split("\n"):
        require(line.count("=") == 1 and not line.startswith("="),
                'Malformed record-linkage evaluation continuation authorization line')
        key, value = line.split("=", 1)
        require(key not in values, 'Duplicate record-linkage evaluation continuation authorization key')
        values[key] = value
    require(tuple(values) == CONTINUATION_AUTH_KEYS,
            'Record-linkage evaluation continuation authorization key order differs')
    require(re.fullmatch(r"2026-09-14T\d{2}:\d{2}:\d{2}Z",
                         values["authorized_at_utc"]) is not None,
            'Record-linkage evaluation continuation authorization timestamp differs')
    launcher_identity = file_identity(launcher_path)
    require(values["authorized_launcher_sha256"] == launcher_identity["sha256"],
            'Record-linkage evaluation continuation authorization does not bind this launcher')
    observed_fixed = OrderedDict((key, value) for key, value in values.items()
                                 if key not in {"authorized_at_utc",
                                                "authorized_launcher_sha256"})
    require(observed_fixed == CONTINUATION_FIXED,
            'Record-linkage evaluation continuation authorization content differs')
    return values, launcher_identity


def safe_zip_bytes(data, expected_names, name):
    require(len(data) < 10_000_000, name + " is unexpectedly large")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        require(len(names) == len(set(names)) and set(names) == set(expected_names),
                name + " member set differs")
        require(archive.testzip() is None, name + " CRC integrity failure")
        for item in infos:
            pure = PurePosixPath(item.filename)
            require(not pure.is_absolute() and ".." not in pure.parts
                    and "\\" not in item.filename, name + " contains unsafe path")
            require(stat.S_IFMT(item.external_attr >> 16) != stat.S_IFLNK,
                    name + " contains a symbolic link")
            require(not (item.flag_bits & 0x1), name + " contains encrypted content")
        return {item.filename: archive.read(item.filename) for item in infos}


def read_package(package):
    manifest_data = (package / "PACKAGE_MANIFEST.json").read_bytes()
    manifest = json.loads(strict_text(manifest_data, "Package manifest"))
    require(manifest.get("record_schema")
            == "gate-c-authorized-continuation-execution-package-v1.2.4/1.0",
            "Unexpected package manifest schema")
    require(set(manifest.get("files", {})) == PACKAGE_FILES,
            "Package manifest file set differs")
    observed = {path.relative_to(package).as_posix()
                for path in package.rglob("*") if path.is_file()}
    require(observed == PACKAGE_FILES | {"PACKAGE_MANIFEST.json"},
            "Package closed file set differs")
    for relative, expected in manifest["files"].items():
        path = package / relative
        require(path.is_file() and not path.is_symlink() and not path.is_junction(),
                "Unsafe package member: " + relative)
        require(file_identity(path) == expected,
                "Package member identity differs: " + relative)
    require(manifest.get("gate_c_continuation_authorized") is True
            and manifest.get("fresh_gate_c_restart_authorized") is False
            and manifest.get("gate_b_rerun_authorized") is False,
            "Package authorization scope differs")
    return manifest, manifest_data


def load_overlay(path):
    require(file_identity(path) == OVERLAY_IDENTITY, "Overlay identity differs")
    spec = importlib.util.spec_from_file_location("gate_c_execution_overlay", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    require(module.EXPECTED_HEAD == HEAD and module.EXPECTED_TREE == TREE
            and module.RUNNER_SHA256 == RUNNER_SHA256
            and module.TOOL_REVISION == "1.1",
            "Overlay source binding differs")
    return module


def runtime_guard(repository):
    require(os.name == "nt" and platform.system() == "Windows"
            and platform.python_implementation() == "CPython"
            and sys.version_info[:3] == (3, 12, 10) and struct.calcsize("P") == 8,
            "Windows CPython 3.12.10 x64 is required")
    require(sys.flags.isolated == 1 and sys.dont_write_bytecode, "Use Python flags -I -B")
    require(Path(sys.executable).resolve() == (repository / ".venv/Scripts/python.exe").resolve(),
            "Use the repository's pinned .venv interpreter")
    return {"system": "Windows", "python": platform.python_version(),
            "bits": 64, "numpy_runtime_identity": "SHA256_TREE_VERIFIED_BEFORE_EXECUTION",
            "isolated": True, "bytecode_writes_disabled": True}


def read_evidence(package):
    main_auth = (package / MAIN_AUTH_FILE).read_bytes()
    require(identity(main_auth) == MAIN_AUTH_IDENTITY, "Main authorization identity differs")
    gate_b_data = (package / GATE_B_FILE).read_bytes()
    require(identity(gate_b_data) == GATE_B_IDENTITY, 'Anonymization validation evidence identity differs')
    gate_b_members = safe_zip_bytes(gate_b_data, {
        "GATE_B_INDEPENDENT_VERIFICATION.json", "gate_b_artifact_inventory.json",
        "main_run_authorization_f479fbab_v1_2_4.txt",
    }, 'Anonymization validation evidence')
    gate_b = json.loads(gate_b_members["GATE_B_INDEPENDENT_VERIFICATION.json"])
    gate_b_inventory = json.loads(gate_b_members["gate_b_artifact_inventory.json"])
    require(gate_b["result"] == "PASS" and gate_b["stage_status"]["gate_b"] == "PASS"
            and gate_b["source"]["head"] == HEAD and gate_b["source"]["tree"] == TREE
            and gate_b["authorization"]["authorization_id"] == MAIN_AUTHORIZATION_ID
            and gate_b_members["main_run_authorization_f479fbab_v1_2_4.txt"] == main_auth,
            'Anonymization validation PASS or source/authorization binding differs')
    require(set(gate_b_inventory) == {"public", "private"}
            and len(gate_b_inventory["public"]) == 65
            and len(gate_b_inventory["private"]) == 1,
            'Anonymization validation artifact inventory differs')

    preflight_data = (package / PREFLIGHT_FILE).read_bytes()
    require(identity(preflight_data) == PREFLIGHT_IDENTITY, "Windows preflight identity differs")
    preflight_members = safe_zip_bytes(preflight_data, {
        "PREFLIGHT_REVIEW.json", "logs/tests.exitcode.txt", "logs/tests.stderr.bin",
        "logs/tests.stdout.bin", "package/INSTRUCTIONS.md", "package/PACKAGE_MANIFEST.json",
        "package/evidence/gate_b_completed_run_verification_receipt_f479fbab_v1_2_4.zip",
        "package/evidence/main_run_authorization_f479fbab_v1_2_4.txt",
        "package/fixtures/gate_c_pinned_hierarchies.zip",
        "package/gate_c_compatibility_overlay_f479fbab_v1_2_4.py",
        "package/preflight_gate_c_overlay_f479fbab_v1_2_4.py",
        "package/test_gate_c_overlay_f479fbab_v1_2_4.py",
    }, "Windows preflight review")
    preflight = json.loads(preflight_members["PREFLIGHT_REVIEW.json"])
    require(preflight["result"] == "PASS" and preflight["repository_head"] == HEAD
            and preflight["repository_tree"] == TREE
            and preflight["overlay_identity"] == OVERLAY_IDENTITY
            and preflight["targeted_tests"]["tests_run"] == 67
            and preflight["targeted_tests"]["result"] == "PASS"
            and preflight["artifacts_before"] == preflight["artifacts_after"]
            and preflight["repository_and_artifacts_preserved_byte_exact"] is True
            and preflight["gate_b_rerun"] is False and preflight["gate_c_executed"] is False,
            "Windows preflight PASS binding differs")

    independent_data = (package / INDEPENDENT_FILE).read_bytes()
    require(identity(independent_data) == INDEPENDENT_IDENTITY,
            "Independent preflight verification identity differs")
    independent_members = safe_zip_bytes(independent_data, {
        "GATE_C_OVERLAY_PREFLIGHT_INDEPENDENT_VERIFICATION.json",
        "gate_c_overlay_windows_preflight_member_inventory.json",
    }, "Independent preflight verification")
    independent = json.loads(
        independent_members["GATE_C_OVERLAY_PREFLIGHT_INDEPENDENT_VERIFICATION.json"])
    require(independent["result"] == "PASS"
            and independent["source_review_zip"] == PREFLIGHT_IDENTITY
            and independent["bindings"]["repository_head"] == HEAD
            and independent["bindings"]["repository_tree"] == TREE
            and independent["bindings"]["runner"]["sha256"] == RUNNER_SHA256
            and independent["bindings"]["overlay"] == OVERLAY_IDENTITY
            and independent["stage_status"]["gate_c_execution"]
                == "NOT_EXECUTED_NOT_YET_AUTHORIZED",
            "Independent preflight verification binding differs")

    failed_data = (package / FAILED_REVIEW_FILE).read_bytes()
    require(identity(failed_data) == FAILED_REVIEW_IDENTITY,
            'Failed record-linkage evaluation review identity differs')
    failed_members = safe_zip_bytes(failed_data, {
        "GATE_C_EXECUTION_REVIEW.json",
        "gate_c_execution_authorization_f479fbab_overlay_2988a0e4_v1_2_4.txt",
        "logs/gate_c.stderr.bin", "logs/gate_c.stdout.bin",
        "logs/launcher_traceback.txt", "logs/tests.exitcode.txt",
        "logs/tests.stderr.bin", "logs/tests.stdout.bin",
        "gate_c_private_inventory.json", "gate_c_public_inventory.json",
        "gate_c_public_pending_inventory.json",
    }, 'Failed record-linkage evaluation review')
    failed = json.loads(failed_members["GATE_C_EXECUTION_REVIEW.json"])
    require(failed["result"] == "FAIL" and failed["gate_c_invoked"] is True
            and failed["gate_c_completed"] is False
            and failed["gate_b_rerun"] is False
            and failed["production_noise_created"] is False
            and failed["production_attack_scores_created"] is False
            and failed["production_sigma_created"] is False
            and json.loads(failed_members["gate_c_private_inventory.json"])
                == [{"path": "SESSION.json", **FAILED_SESSION_IDENTITY}]
            and json.loads(failed_members["gate_c_public_inventory.json"]) == []
            and json.loads(failed_members["gate_c_public_pending_inventory.json"]) == [],
            'Failed record-linkage evaluation review stage differs')

    failed_independent_data = (package / FAILED_INDEPENDENT_FILE).read_bytes()
    require(identity(failed_independent_data) == FAILED_INDEPENDENT_IDENTITY,
            "Independent failed-attempt review identity differs")
    failed_independent_members = safe_zip_bytes(failed_independent_data, {
        "GATE_C_FAILED_ATTEMPT_INDEPENDENT_REVIEW.json",
        "source_review_member_inventory.json",
    }, "Independent failed-attempt review")
    failed_independent = json.loads(
        failed_independent_members["GATE_C_FAILED_ATTEMPT_INDEPENDENT_REVIEW.json"])
    require(failed_independent["review_result"] == "PASS"
            and failed_independent["execution_result"] == "FAIL_CONFIRMED"
            and failed_independent["source_review_zip"] == FAILED_REVIEW_IDENTITY
            and failed_independent["rerun_authorized_by_this_review"] is False,
            "Independent failed-attempt review binding differs")

    runtime_data = (package / RUNTIME_PREFLIGHT_FILE).read_bytes()
    require(identity(runtime_data) == RUNTIME_PREFLIGHT_IDENTITY,
            "Runtime-read Windows preflight identity differs")
    runtime_members = safe_zip_bytes(runtime_data, {
        "PREFLIGHT_REVIEW.json", "logs/numpy_probe.exitcode.txt",
        "logs/numpy_probe.stderr.bin", "logs/numpy_probe.stdout.bin",
        "logs/tests.exitcode.txt", "logs/tests.stderr.bin", "logs/tests.stdout.bin",
        "package/INSTRUCTIONS.md", "package/PACKAGE_MANIFEST.json",
        "package/evidence/gate_c_authorized_execution_review_f479fbab_v1_2_4.zip",
        "package/evidence/gate_c_failed_attempt_independent_review_f479fbab_v1_2_4.zip",
        "package/preflight_gate_c_runtime_read_compatibility_f479fbab_v1_2_4.py",
        "package/test_gate_c_runtime_read_compatibility_f479fbab_v1_2_4.py",
    }, "Runtime-read Windows preflight")
    runtime_preflight = json.loads(runtime_members["PREFLIGHT_REVIEW.json"])
    require(runtime_preflight["result"] == "PASS"
            and runtime_preflight["repository_before"] == runtime_preflight["repository_after"]
            and runtime_preflight["repository_before"]["head"] == HEAD
            and runtime_preflight["repository_before"]["tree"] == TREE
            and runtime_preflight["repository_before"]["runner"]["sha256"] == RUNNER_SHA256
            and runtime_preflight["failed_session_before"]
                == runtime_preflight["failed_session_after"]
            and runtime_preflight["failed_session_before"]["session"]
                == FAILED_SESSION_IDENTITY
            and runtime_preflight["numpy_runtime_probe"]["runtime_tree_before"]
                == NUMPY_RUNTIME_TREE
            and runtime_preflight["numpy_runtime_probe"]["runtime_tree_after"]
                == NUMPY_RUNTIME_TREE
            and runtime_preflight["numpy_runtime_probe"]["allowed_read_roots"]
                == [".venv/Lib/site-packages/numpy",
                    ".venv/Lib/site-packages/numpy.libs"]
            and runtime_preflight["numpy_runtime_probe"]["write_access_to_runtime_roots"]
                is False
            and runtime_preflight["numpy_runtime_probe"]["broader_site_packages_read_allowed"]
                is False
            and runtime_preflight["gate_c_executed"] is False
            and runtime_preflight["continuation_authorized_by_preflight"] is False,
            "Runtime-read Windows preflight binding differs")

    runtime_independent_data = (package / RUNTIME_INDEPENDENT_FILE).read_bytes()
    require(identity(runtime_independent_data) == RUNTIME_INDEPENDENT_IDENTITY,
            "Independent runtime-read verification identity differs")
    runtime_independent_members = safe_zip_bytes(runtime_independent_data, {
        "GATE_C_RUNTIME_READ_PREFLIGHT_INDEPENDENT_VERIFICATION.json",
        "source_review_member_inventory.json", "verified_runtime_binding.json",
    }, "Independent runtime-read verification")
    runtime_independent = json.loads(runtime_independent_members[
        "GATE_C_RUNTIME_READ_PREFLIGHT_INDEPENDENT_VERIFICATION.json"])
    runtime_binding = json.loads(
        runtime_independent_members["verified_runtime_binding.json"])
    require(runtime_independent["result"] == "PASS"
            and runtime_independent["source_review_zip"] == RUNTIME_PREFLIGHT_IDENTITY
            and runtime_independent["continuation_authorized_by_verification"] is False
            and runtime_binding["repository_head"] == HEAD
            and runtime_binding["repository_tree"] == TREE
            and runtime_binding["runner"]["sha256"] == RUNNER_SHA256
            and runtime_binding["runtime_tree"] == NUMPY_RUNTIME_TREE
            and runtime_binding["allowed_read_roots"]
                == [".venv/Lib/site-packages/numpy",
                    ".venv/Lib/site-packages/numpy.libs"]
            and runtime_binding["writes_to_runtime_roots_allowed"] is False
            and runtime_binding["broader_site_packages_read_allowed"] is False
            and runtime_binding["failed_session"] == FAILED_SESSION_IDENTITY,
            "Independent runtime-read verification binding differs")
    return main_auth, gate_b_inventory, preflight, runtime_binding


def inventory(root):
    if not root.exists():
        return []
    require(root.is_dir() and not root.is_symlink() and not root.is_junction(),
            "Unsafe artifact root: " + str(root))
    records = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        require(not path.is_symlink() and not path.is_junction(),
                "Link/junction in artifacts: " + str(path))
        if path.is_file():
            records.append({"path": path.relative_to(root).as_posix(), **file_identity(path)})
        else:
            require(path.is_dir(), "Non-regular artifact: " + str(path))
    return records


def verify_gate_b_inventory(repository, expected, *, allow_gate_c):
    roots = {"public": repository / "runs/main_v1_2_4",
             "private": repository / "private/main_v1_2_4"}
    result = {}
    for scope, root in roots.items():
        observed = inventory(root)
        if allow_gate_c:
            base = [item for item in observed if not item["path"].startswith("gate_c/")]
        else:
            base = observed
        require(base == expected[scope], 'Existing anonymization validation ' + scope + " inventory differs")
        result[scope] = len(base)
    return result


def context_paths(repository, context):
    result = {
        "source_input": repository / "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult.csv",
        "rid_order": repository / "private/section_12_1_step_6_v1_2_3/rid_order.txt",
        "master_permutation": repository / "private/section_12_1_step_6_v1_2_3/master_permutation.txt",
        "target_private": repository / "private/main_v1_2_4/target_sample.private.json",
        "target_receipt": repository / "runs/main_v1_2_4/pre_output_target_sample_receipt.json",
        "gate_b_matrix_summary": repository / "runs/main_v1_2_4/gate_b_matrix_summary.json",
    }
    for attribute, item in context["hierarchies"].items():
        result["hierarchy:" + attribute] = repository / item["relative_path"]
    for config_id, items in context["configurations"].items():
        result[config_id + ":full_output"] = repository / "runs/main_v1_2_4" / config_id / (config_id + ".full.tsv")
        result[config_id + ":java_report"] = repository / "runs/main_v1_2_4" / config_id / (config_id + ".java-report.json")
        result[config_id + ":gate_b_receipt"] = repository / "runs/main_v1_2_4" / config_id / (config_id + ".gate-b.json")
    return result


def verify_context(repository, context):
    paths = context_paths(repository, context)
    expected = {
        "source_input": context["source_input"], "rid_order": context["rid_order"],
        "master_permutation": context["master_permutation"],
        "target_private": context["target_private"], "target_receipt": context["target_receipt"],
        "gate_b_matrix_summary": context["gate_b_matrix_summary"],
    }
    expected.update({"hierarchy:" + key: {"bytes": value["bytes"], "sha256": value["sha256"]}
                     for key, value in context["hierarchies"].items()})
    for config_id, items in context["configurations"].items():
        expected[config_id + ":full_output"] = items["full_output"]
        expected[config_id + ":java_report"] = items["java_report"]
        expected[config_id + ":gate_b_receipt"] = items["gate_b_receipt"]
    observed = {name: file_identity(path) for name, path in paths.items()}
    require(observed == expected, 'Pinned record-linkage evaluation input identity differs')
    return paths, observed


def safe_output_parents(repository):
    for relative in ("runs/main_v1_2_4", "private/main_v1_2_4"):
        current = repository
        for part in Path(relative).parts:
            current = current / part
            require(current.is_dir() and not current.is_symlink() and not current.is_junction(),
                    "Unsafe output parent: " + relative)


def verify_failed_session(repository):
    private_root = repository / "private/main_v1_2_4/gate_c"
    public_root = repository / "runs/main_v1_2_4/gate_c"
    pending_root = repository / "runs/main_v1_2_4/gate_c.pending"
    require(inventory(private_root)
            == [{"path": "SESSION.json", **FAILED_SESSION_IDENTITY}],
            'Record-linkage evaluation continuation requires the exact SESSION-only failed state')
    require(not public_root.exists() and not pending_root.exists(),
            'Record-linkage evaluation continuation requires absent public and pending outputs')
    return {"state": "EXACT_SESSION_ONLY", "session": FAILED_SESSION_IDENTITY,
            "public_final_exists": False, "public_pending_exists": False}


def numpy_runtime_roots(repository):
    site_packages = repository / ".venv/Lib/site-packages"
    roots = (site_packages / "numpy", site_packages / "numpy.libs")
    require(site_packages.is_dir() and not site_packages.is_symlink()
            and not site_packages.is_junction(), "Unsafe site-packages root")
    for root in roots:
        require(root.is_dir() and not root.is_symlink() and not root.is_junction(),
                "Missing or unsafe exact NumPy runtime root: " + root.name)
    return roots


def runtime_tree_identity(roots):
    records = []
    total_bytes = 0
    for root in roots:
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            require(not path.is_symlink() and not path.is_junction(),
                    "Link or junction in NumPy runtime tree")
            if path.is_file():
                item_identity = file_identity(path)
                total_bytes += item_identity["bytes"]
                records.append({
                    "path": root.name + "/" + path.relative_to(root).as_posix(),
                    **item_identity,
                })
            else:
                require(path.is_dir(), "Non-regular NumPy runtime item")
    require(bool(records), "NumPy runtime tree is empty")
    return {"file_count": len(records), "total_bytes": total_bytes,
            "tree_sha256": hashlib.sha256(json_bytes(records)).hexdigest()}


def install_audit(repository, read_files, write_roots, runtime_read_roots):
    root = os.path.normcase(os.path.abspath(repository))
    prefix = root + os.sep
    reads = {os.path.normcase(os.path.abspath(path)) for path in read_files}
    writes = tuple(os.path.normcase(os.path.abspath(path)) for path in write_roots)
    runtime_reads = tuple(os.path.normcase(os.path.abspath(path))
                          for path in runtime_read_roots)

    def normalized(value):
        if isinstance(value, (str, bytes, os.PathLike)):
            return os.path.normcase(os.path.abspath(os.fsdecode(value)))
        return None

    def inside(path, base):
        return path == base or path.startswith(base + os.sep)

    def in_repository(value):
        path = normalized(value)
        return path is not None and (path == root or path.startswith(prefix))

    def permitted_write(value):
        path = normalized(value)
        return path is not None and any(inside(path, base) for base in writes)

    def audit(event, args):
        if event == "open" and in_repository(args[0]):
            mode = args[1] or ""
            flags = args[2]
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            writing = any(character in mode for character in "wax+") or bool(flags & write_flags)
            if writing:
                require(permitted_write(args[0]), 'Blocked repository write outside record-linkage evaluation roots')
            else:
                path = normalized(args[0])
                require(path in reads or any(inside(path, base) for base in writes)
                        or any(inside(path, base) for base in runtime_reads),
                        "Blocked non-pinned repository read: " + str(args[0]))
        if event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime",
                     "os.rename", "os.link", "os.symlink", "os.truncate"}:
            path_args = args[:2] if event in {"os.rename", "os.link", "os.symlink"} else args[:1]
            for value in path_args:
                if in_repository(value):
                    require(permitted_write(value),
                            'Blocked repository mutation outside record-linkage evaluation roots')
    sys.addaudithook(audit)


class Tee:
    def __init__(self, stream):
        self.stream = stream
        self.buffer = io.StringIO()
        self.encoding = getattr(stream, "encoding", "utf-8")

    def write(self, value):
        self.buffer.write(value)
        return self.stream.write(value)

    def flush(self):
        self.buffer.flush()
        self.stream.flush()

    def bytes(self):
        return self.buffer.getvalue().encode("utf-8")


def expected_output_paths():
    private = {"SESSION.json", *("common/" + name for name in (
        "cfg00_raw_control.tsv", "cfg00_raw_control_receipt.json", "noise.private.json",
        "noise_receipt.json", "attack_oracle_receipt.json"))}
    public = {"cfg00_raw_control.tsv", "cfg00_raw_control_receipt.json", "noise_receipt.json",
              "attack_oracle_receipt.json", "gate_c_receipt.json", "gate_c_runner_summary.json"}
    for config_id in CONFIGURATIONS:
        private.update(config_id + "/" + name for name in PRIVATE_CHECKPOINT_FILES)
        public.update(config_id + "/" + name for name in PUBLIC_CHECKPOINT_FILES)
    return private, public


def verify_completed_outputs(repository, returned_summary, returned_output):
    private_root = repository / "private/main_v1_2_4/gate_c"
    public_root = repository / "runs/main_v1_2_4/gate_c"
    require(returned_output.resolve(strict=True) == public_root.resolve(strict=True),
            "Runner returned an unexpected output path")
    private_inventory = inventory(private_root)
    public_inventory = inventory(public_root)
    expected_private, expected_public = expected_output_paths()
    require({item["path"] for item in private_inventory} == expected_private
            and {item["path"] for item in public_inventory} == expected_public,
            'Completed record-linkage evaluation output file set differs')
    require(len(private_inventory) == 176 and len(public_inventory) == 91,
            'Completed record-linkage evaluation output count differs')
    require(not (repository / "runs/main_v1_2_4/gate_c.pending").exists()
            and not any(path.name.endswith(".pending")
                        for path in private_root.iterdir()),
            'A partial record-linkage evaluation artifact remains after PASS')
    summary_data = (public_root / "gate_c_runner_summary.json").read_bytes()
    summary = json.loads(strict_text(summary_data, 'Record-linkage evaluation runner summary'))
    receipt_data = (public_root / "gate_c_receipt.json").read_bytes()
    receipt = json.loads(strict_text(receipt_data, 'Record-linkage evaluation receipt'))
    require(summary == returned_summary and summary["result"] == "PASS"
            and summary["gate_b"] == "PASS" and summary["gate_c"] == "PASS"
            and summary["repository_head"] == HEAD
            and summary["authorization_record_sha256"] == MAIN_AUTH_IDENTITY["sha256"]
            and summary["configuration_order"] == list(CONFIGURATIONS)
            and summary["configuration_count"] == 17
            and summary["sensitivity_scenarios_executed"] is False
            and summary["bootstrap_executed"] is False
            and summary["holdout_accessed"] is False
            and summary["model_fits_executed"] is False,
            'Record-linkage evaluation runner summary differs from the authorized scope')
    require(receipt["result"] == "PASS" and receipt["gate_c_status"] == "PASS"
            and receipt["scope"] == "OPERATIONAL_FULL_MATRIX"
            and receipt["configurations"] == list(CONFIGURATIONS)
            and receipt["configuration_count"] == 17
            and receipt["cfg00_numeric_acceptance_range"] is None
            and receipt["permutation_numeric_acceptance_range"] is None
            and receipt["risk_values_descriptive_not_gate_thresholds"] is True
            and receipt["private_values_in_receipt"] is False
            and receipt["holdout_accessed"] is False
            and receipt["model_fit_executed"] is False,
            'Record-linkage evaluation receipt differs from the fixed contract')
    for item in public_inventory:
        if item["path"].endswith(".json"):
            data = (public_root / item["path"]).read_bytes()
            strict_text(data, 'Public record-linkage evaluation JSON')
            json.loads(data)
            private_tokens = (b'"target_ids"', b'"release_ids"', b'"success_draws"',
                              b'"cluster_keys"', b'"actual_row_to_rid"',
                              b'"permuted_row_to_rid"', b'"base_matrix"',
                              b'"s4_matrix"', b'"records"', b"adult.data:")
            require(not any(token in data for token in private_tokens),
                    'Private values detected in public record-linkage evaluation JSON')
    return private_inventory, public_inventory, summary, receipt


def detected_stage(repository):
    private_root = repository / "private/main_v1_2_4/gate_c"
    public_root = repository / "runs/main_v1_2_4/gate_c"
    pending_root = repository / "runs/main_v1_2_4/gate_c.pending"
    candidates = []
    if private_root.exists():
        candidates.extend(path for path in private_root.rglob("*") if path.is_file())
    return {
        "private_session_exists": private_root.exists(),
        "public_final_exists": public_root.exists(),
        "public_pending_exists": pending_root.exists(),
        "noise_created": any(path.name == "noise.private.json" for path in candidates),
        "attack_scores_created": any(path.name == "score_payload.private.json" for path in candidates),
        "sigma_created": any(path.name == "permutation.private.json" for path in candidates),
    }


def write_review(workdir, report, logs, authorization_data,
                 continuation_authorization_data, repository):
    inventories = {
        "gate_c_private_inventory.json": inventory(repository / "private/main_v1_2_4/gate_c"),
        "gate_c_public_inventory.json": inventory(repository / "runs/main_v1_2_4/gate_c"),
        "gate_c_public_pending_inventory.json": inventory(repository / "runs/main_v1_2_4/gate_c.pending"),
    }
    review_zip = workdir / "gate_c_authorized_continuation_review_f479fbab_v1_2_4.zip"
    with zipfile.ZipFile(review_zip, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("GATE_C_EXECUTION_REVIEW.json", json_bytes(report))
        archive.writestr(PurePosixPath(AUTH_FILE).name, authorization_data)
        archive.writestr(PurePosixPath(CONTINUATION_AUTH_FILE).name,
                         continuation_authorization_data)
        for name, data in sorted(logs.items()):
            archive.writestr("logs/" + name, data)
        for name, records in sorted(inventories.items()):
            archive.writestr(name, json_bytes(records))
        public_root = repository / "runs/main_v1_2_4/gate_c"
        if report["result"] == "PASS":
            for path in sorted(public_root.rglob("*.json"), key=lambda item: item.as_posix()):
                archive.writestr("public_json/" + path.relative_to(public_root).as_posix(),
                                 path.read_bytes())
    with zipfile.ZipFile(review_zip) as archive:
        require(archive.testzip() is None, "Review ZIP integrity failure")
    return review_zip


def execute(package, repository, workdir, report, logs):
    manifest, manifest_data = read_package(package)
    report["package_manifest"] = identity(manifest_data)
    report["runtime"] = runtime_guard(repository)

    authorization_data = (package / AUTH_FILE).read_bytes()
    authorization = parse_authorization(authorization_data)
    report["gate_c_execution_authorization"] = {
        "authorization_id": authorization["authorization_id"], **AUTHORIZATION_IDENTITY}
    continuation_authorization_data = (package / CONTINUATION_AUTH_FILE).read_bytes()
    continuation_authorization, launcher_identity = parse_continuation_authorization(
        continuation_authorization_data, package / LAUNCHER_FILE)
    report["gate_c_continuation_authorization"] = {
        "authorization_id": continuation_authorization["authorization_id"],
        **identity(continuation_authorization_data),
    }
    report["launcher_identity"] = launcher_identity
    main_auth, gate_b_inventory, preflight, runtime_binding = read_evidence(package)
    report["bound_evidence"] = {
        "main_authorization": MAIN_AUTH_IDENTITY, "gate_b_receipt": GATE_B_IDENTITY,
        "windows_preflight_review": PREFLIGHT_IDENTITY,
        "independent_preflight_verification": INDEPENDENT_IDENTITY,
        "failed_execution_review": FAILED_REVIEW_IDENTITY,
        "failed_attempt_independent_review": FAILED_INDEPENDENT_IDENTITY,
        "runtime_read_windows_preflight": RUNTIME_PREFLIGHT_IDENTITY,
        "runtime_read_independent_verification": RUNTIME_INDEPENDENT_IDENTITY,
    }
    overlay = load_overlay(package / OVERLAY_FILE)
    report["overlay"] = OVERLAY_IDENTITY
    require("numpy" not in sys.modules, 'NumPy was imported before authorized record-linkage evaluation')
    print("CHECKPOINT=AUTHORIZED_LAUNCHER_TESTS_START", flush=True)
    tests = subprocess.run(
        (sys.executable, "-I", "-B", str(package / TEST_FILE)), cwd=package,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    logs["tests.stdout.bin"] = tests.stdout
    logs["tests.stderr.bin"] = tests.stderr
    logs["tests.exitcode.txt"] = (str(tests.returncode) + "\n").encode("ascii")
    require(tests.returncode == 0, 'Authorized-launcher tests failed; record-linkage evaluation was not invoked')
    report["targeted_tests"] = json.loads(tests.stdout.decode("ascii"))
    require(report["targeted_tests"]["result"] == "PASS"
            and report["targeted_tests"]["tests_run"] == 36
            and report["targeted_tests"]["failures"] == 0
            and report["targeted_tests"]["errors"] == 0
            and report["targeted_tests"]["skipped"] == 0
            and report["targeted_tests"]["operational_gate_c_executed"] is False,
            "Authorized-launcher test summary differs")
    require("numpy" not in sys.modules, "Launcher tests unexpectedly imported NumPy")
    print("CHECKPOINT=AUTHORIZED_LAUNCHER_TESTS_PASS", flush=True)
    safe_output_parents(repository)
    runtime_roots = numpy_runtime_roots(repository)
    runtime_tree_before = runtime_tree_identity(runtime_roots)
    require(runtime_tree_before == NUMPY_RUNTIME_TREE
            and runtime_binding["runtime_tree"] == NUMPY_RUNTIME_TREE,
            "Installed NumPy runtime tree differs from the verified Windows preflight")
    report["numpy_runtime_tree_before"] = runtime_tree_before
    public_gate_c = repository / "runs/main_v1_2_4/gate_c"
    public_pending = repository / "runs/main_v1_2_4/gate_c.pending"
    private_gate_c = repository / "private/main_v1_2_4/gate_c"
    report["continuation_state_before"] = verify_failed_session(repository)
    report["gate_b_inventory_before"] = verify_gate_b_inventory(
        repository, gate_b_inventory, allow_gate_c=True)
    context = preflight["input_context"]
    input_paths, input_before = verify_context(repository, context)
    report["input_identity_count"] = len(input_before)

    runner, overlay_evidence = overlay.install(repository)
    require(overlay_evidence["execution_authorization_granted"] is False
            and overlay_evidence["scientific_functions_replaced"] is False
            and len(overlay_evidence["changes"]) == 3,
            "Overlay installation delta differs")
    require(runner.__name__ == overlay.RUNNER_NAME
            and runner.__file__.endswith("attack_runner.py"),
            'Loaded record-linkage evaluation runner differs')
    read_files = set(input_paths.values())
    read_files.update(repository / "runs/main_v1_2_4" / item["path"]
                      for item in gate_b_inventory["public"])
    read_files.update(repository / "private/main_v1_2_4" / item["path"]
                      for item in gate_b_inventory["private"])
    read_files.update(repository / relative for relative in overlay_evidence["source_identities"])
    for path in read_files:
        overlay.safe_file(repository, path.relative_to(repository))
    install_audit(repository, read_files,
                  (private_gate_c, public_pending, public_gate_c), runtime_roots)

    stdout_tee = Tee(sys.stdout)
    stderr_tee = Tee(sys.stderr)
    report["gate_c_invoked"] = True
    try:
        with redirect_stdout(stdout_tee), redirect_stderr(stderr_tee):
            returned_summary, returned_output = runner.run_operational(
                repository, package / MAIN_AUTH_FILE)
    finally:
        logs["gate_c.stdout.bin"] = stdout_tee.bytes()
        logs["gate_c.stderr.bin"] = stderr_tee.bytes()

    private_inventory, public_inventory, summary, receipt = verify_completed_outputs(
        repository, returned_summary, returned_output)
    require(verify_context(repository, context)[1] == input_before,
            'A pinned record-linkage evaluation input changed during execution')
    runtime_tree_after = runtime_tree_identity(runtime_roots)
    require(runtime_tree_after == runtime_tree_before,
            'The NumPy runtime tree changed during record-linkage evaluation continuation')
    report["numpy_runtime_tree_after"] = runtime_tree_after
    report["gate_b_inventory_after"] = verify_gate_b_inventory(
        repository, gate_b_inventory, allow_gate_c=True)
    overlay.check_repository(repository)
    require(runner.DEPENDENCY_HASHES == overlay.DEPENDENCY_HASHES_AFTER,
            "Overlay dependency binding changed during execution")
    report["outputs"] = {
        "private_file_count": len(private_inventory),
        "public_file_count": len(public_inventory),
        "runner_summary": file_identity(repository / "runs/main_v1_2_4/gate_c/gate_c_runner_summary.json"),
        "gate_c_receipt": file_identity(repository / "runs/main_v1_2_4/gate_c/gate_c_receipt.json"),
        "configuration_count": summary["configuration_count"],
        "gate_c_status": receipt["gate_c_status"],
    }
    report["inputs_and_gate_b_artifacts_preserved_byte_exact"] = True
    report["numpy_runtime_tree_preserved_byte_exact"] = True
    report["continuation_mode"] = "RESUMED_EXACT_SESSION_ONLY"
    report["fresh_gate_c_restart"] = False
    report["gate_c_completed"] = True
    report["result"] = "PASS"
    return authorization_data, continuation_authorization_data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--review-directory", type=Path)
    args = parser.parse_args(argv)
    package = Path(__file__).resolve().parent
    repository = args.repository.resolve(strict=True)
    destination = (args.review_directory or repository.parent).resolve(strict=True)
    require(not package.is_relative_to(repository) and not destination.is_relative_to(repository),
            "Package and review destination must remain outside the repository")
    workdir = Path(tempfile.mkdtemp(prefix="gate_c_authorized_execution_review_", dir=destination))
    report = {
        "record_schema": RECORD_SCHEMA, "tool_revision": TOOL_REVISION,
        "result": "FAIL", "started_at_utc": utc_now(), "gate_c_invoked": False,
        "gate_c_completed": False, "gate_b_rerun": False,
        "arx_anonymization_invoked": False, "production_target_sample_created": False,
        "holdout_accessed": False, "bootstrap_executed": False,
        "sensitivity_scenarios_executed": False, "model_fits_executed": False,
        "raw_to_model_end_to_end_verified": False, "production_pipeline_verified": False,
        "independent_post_execution_verification_completed": False,
        "continuation_mode": "RESUMED_EXACT_SESSION_ONLY",
        "fresh_gate_c_restart": False,
    }
    logs = {}
    authorization_data = (package / AUTH_FILE).read_bytes() if (package / AUTH_FILE).is_file() else b""
    continuation_authorization_data = ((package / CONTINUATION_AUTH_FILE).read_bytes()
                                       if (package / CONTINUATION_AUTH_FILE).is_file() else b"")
    started = time.perf_counter()
    print("RESULT=GATE_C_AUTHORIZED_OVERLAY_CONTINUATION_STARTING", flush=True)
    print("HEAD=" + HEAD, flush=True)
    print("ORIGINAL_AUTHORIZATION_ID=" + AUTHORIZATION_ID, flush=True)
    print("CONTINUATION_AUTHORIZATION_ID=" + CONTINUATION_AUTHORIZATION_ID, flush=True)
    print("OVERLAY_SHA256=" + OVERLAY_IDENTITY["sha256"], flush=True)
    try:
        authorization_data, continuation_authorization_data = execute(
            package, repository, workdir, report, logs)
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error).replace("\r", " ").replace("\n", " ")
        logs["launcher_traceback.txt"] = traceback.format_exc().encode("utf-8")
    report["detected_artifact_stage"] = detected_stage(repository)
    report["production_noise_created"] = report["detected_artifact_stage"]["noise_created"]
    report["production_attack_scores_created"] = report["detected_artifact_stage"]["attack_scores_created"]
    report["production_sigma_created"] = report["detected_artifact_stage"]["sigma_created"]
    report["completed_at_utc"] = utc_now()
    report["wall_clock_seconds"] = time.perf_counter() - started
    review_zip = write_review(workdir, report, logs, authorization_data,
                              continuation_authorization_data, repository)
    review_identity = file_identity(review_zip)
    print("RESULT=GATE_C_AUTHORIZED_OVERLAY_CONTINUATION_" + report["result"])
    print("TOOL_REVISION=" + TOOL_REVISION)
    if report["result"] == "PASS":
        print("TARGETED_TESTS=" + str(report["targeted_tests"]["tests_run"]) + "/"
              + str(report["targeted_tests"]["tests_run"]) + "_PASS")
        print("CONFIGURATIONS=17/17_PASS")
        print("GATE_B=PASS_PRESERVED_NOT_RERUN")
        print("GATE_C=PASS_PENDING_INDEPENDENT_VERIFICATION")
        print("CONTINUATION_MODE=RESUMED_EXACT_SESSION_ONLY")
        print("NUMPY_RUNTIME_TREE_SHA256=" + NUMPY_RUNTIME_TREE["tree_sha256"])
        print("PRIVATE_GATE_C_FILES=176")
        print("PUBLIC_GATE_C_FILES=91")
    else:
        print("ERROR=" + report.get("error", "Unspecified execution failure"))
        print("GATE_C=FAIL_OR_INCOMPLETE_PRESERVE_ALL_ARTIFACTS")
    print("ARX_ANONYMIZATION_INVOKED=false")
    print("HOLDOUT_ACCESSED=false")
    print("BOOTSTRAP_EXECUTED=false")
    print("SENSITIVITY_SCENARIOS_EXECUTED=false")
    print("MODEL_FITS_EXECUTED=false")
    print("REVIEW_ZIP=" + str(review_zip))
    print("REVIEW_ZIP_BYTES=" + str(review_identity["bytes"]))
    print("REVIEW_ZIP_SHA256=" + review_identity["sha256"])
    print("NEXT=Upload the review ZIP and full output; do not rerun or access downstream stages")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ExecutionError, OSError) as error:
        print("RESULT=GATE_C_AUTHORIZED_OVERLAY_CONTINUATION_SETUP_FAIL")
        print("ERROR=" + str(error).replace("\r", " ").replace("\n", " "))
        raise SystemExit(1)
