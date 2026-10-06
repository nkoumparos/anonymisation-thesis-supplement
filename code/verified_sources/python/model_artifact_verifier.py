"""Verify stored prediction models and outputs."""

from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import zipfile


TOOL_REVISION = "1.0"
PROTOCOL_VERSION = "v1.2.4"

MODEL_HEAD = "96dc9b6840b1daf13d67749d2bbcd6658a88af72"
MODEL_TREE = "ef9c0024cea6ae3a8e3814ffd5b0034f398988a2"
PRODUCER_HEAD = "f479fbabe2422315f98dd0d39ade2f26d92aef04"
PRODUCER_TREE = "82dcf163bf1a1123c2bf2e7bec54ac0a002b1e52"

MODEL_AUTHORIZATION = {
    "bytes": 1151,
    "sha256": "db5d227061089aa2398b73240af2e22e1217f203d14a2a75af1be1a6afdf0178",
}
MODEL_REVIEW_ZIP = {
    "bytes": 111912,
    "sha256": "c5c60a9b6fbf78a3f2349fec5f6e391c8ee113ae5438fb398081ca65a687e210",
}
PUBLIC_MODEL_RECEIPT = {
    "bytes": 410632,
    "sha256": "282fc843621765955af4f5fa52a35b439b66391fa746e20832be540cbd4fab67",
}
PRIVATE_MODEL_ARTIFACT = {
    "bytes": 30556459,
    "sha256": "854cf97c41627bc0c1df541270b586c54926c00d31078b09ff3b7fe4d8290109",
}
PRIVATE_MODEL_SESSION = {
    "bytes": 934,
    "sha256": "1fa838820d9c29a062079d073683d1c198d4d8ba16fff4c7bb259ac216d53483",
}
GATE_B_RECEIPT = {
    "bytes": 8850,
    "sha256": "c215235c7c992a76d1eccf31b89fb3fc3a43c2d625beda6bb0c274e260e1a6b1",
}
GATE_C_RECEIPT = {
    "bytes": 19608,
    "sha256": "3662ba9fc9a53b76566202c1dbfbf60bb354fe1ee328e3810ae0960bc2897542",
}
IMPLEMENTATION_RECEIPT = {
    "bytes": 25781,
    "sha256": "f2529daf7e9160b6332cd37d1386f0f00f8e1a642189bea19801238f89e89097",
}

EXPECTED_PYTHON = (3, 12, 10)
EXPECTED_BITS = 64
EXPECTED_HOLDOUT_ROWS = 15060
EXPECTED_HOLDOUT_LABEL_COUNTS = {0: 11360, 1: 3700}
EXPECTED_HOLDOUT_ROW_IDS_SHA256 = (
    "ee0b5d8037208af8056fa2734733dc5564c0540f020152d67e0f0635a175bc1d"
)
EXPECTED_HOLDOUT_LABELS_SHA256 = (
    "3ca25a778a960ec9277531485697d22cd089d477cb737ae0f64ccd747e9dfce5"
)
EXPECTED_SOURCE_CONTEXT_SHA256 = (
    "b30c70cc18dc8db279a7020ef3ecc8bfe22d5cf28ef4dbdfc43f655a9243a9ca"
)
EXPECTED_CLASS_PRIOR = [0.7510775147536636, 0.24892248524633645]

AUTHORIZATION_SCHEMA = "raw-to-model-model-artifact-verification-authorization/1.0"
PRIVATE_SCHEMA = "raw-to-model-model-private-v1.2.4/1.0"
PUBLIC_SCHEMA = "raw-to-model-model-execution-receipt-v1.2.4/1.0"
MODEL_SESSION_SCHEMA = "raw-to-model-model-session-v1.2.4/1.0"
VERIFICATION_SESSION_SCHEMA = (
    "raw-to-model-model-artifact-verification-session-v1.2.4/1.0"
)
VERIFICATION_RECEIPT_SCHEMA = (
    "raw-to-model-model-artifact-independent-verification-v1.2.4/1.0"
)
VERIFICATION_FAILURE_SCHEMA = (
    "raw-to-model-model-artifact-verification-failure-v1.2.4/1.0"
)

VERIFIER_RELATIVE = (
    "python/section_12_3_raw_to_model_model_artifact_verifier_v1_2_4.py"
)
WRAPPER_RELATIVE = (
    "scripts/run_raw_to_model_model_artifact_verifier_v1_2_4.ps1"
)
PRIVATE_ARTIFACT_RELATIVE = (
    "private/main_v1_2_4/raw_to_model_model/model_predictions.private.json"
)
PRIVATE_SESSION_RELATIVE = "private/main_v1_2_4/raw_to_model_model/SESSION.json"
PUBLIC_RECEIPT_RELATIVE = (
    "runs/main_v1_2_4/raw_to_model_model/model_execution_receipt.json"
)
PRIVATE_OUTPUT_RELATIVE = (
    "private/main_v1_2_4/raw_to_model_model_artifact_verification"
)
PUBLIC_OUTPUT_RELATIVE = (
    "runs/main_v1_2_4/raw_to_model_model_artifact_verification"
)

CONFIGURATIONS = tuple("CFG%02d" % index for index in range(17))
FINAL_MODEL_KEYS = frozenset({"CFG00"} | {
    config_id + suffix
    for config_id in CONFIGURATIONS[1:]
    for suffix in ("/release", "/counterfactual")
})
PRIVATE_KEYS = {
    "record_schema", "effective_protocol", "repository_head",
    "repository_tree", "producer_head", "producer_tree",
    "authorization_record_sha256", "source_context", "selected_C",
    "holdout_row_ids", "holdout_labels", "final_models", "prior_baseline",
    "model_fit_count", "prediction_model_count", "visibility",
}
PRIVATE_MODEL_KEYS = {
    "cfg_id", "training_role", "C", "prediction_row_ids",
    "prediction_probabilities", "prediction_sha256",
}
PRIVATE_BASELINE_KEYS = {
    "prediction_row_ids", "prediction_probabilities", "prediction_sha256",
    "class_prior",
}
SOURCE_CONTEXT_KEYS = {
    "uci_training", "uci_training_canonical", "arx_training", "uci_holdout",
    "uci_holdout_canonical", "rid_order", "master_permutation", "hierarchies",
    "gate_b_matrix_summary", "target_sample_receipt", "configurations",
    "training_metrics", "holdout_metrics",
}
PUBLIC_FORBIDDEN_KEYS = {
    "X", "y", "labels", "training_X", "holdout_X", "training_row_ids",
    "holdout_row_ids", "prediction_row_ids", "prediction_probabilities",
    "target_indices", "target_rids", "training_indices",
    "validation_indices", "fold_plan", "source_context",
}
AUTHORIZATION_KEYS = {
    "record_schema", "effective_protocol", "authorization_id",
    "authorized_at_utc", "authorized_by", "authorized_source_commit",
    "authorized_source_tree", "bound_model_execution_commit",
    "bound_model_execution_tree", "bound_model_execution_authorization",
    "bound_model_execution_review_zip", "bound_public_model_receipt",
    "bound_private_model_artifact", "bound_private_model_session",
    "implementation_artifacts", "authorized_stage",
    "model_execution_review_zip_read_authorized",
    "public_model_receipt_read_authorized",
    "private_model_session_read_authorized",
    "private_model_artifact_read_authorized", "raw_holdout_source_read_authorized",
    "model_fits_authorized", "prediction_generation_authorized",
    "dummy_baseline_metric_recomputation_authorized",
    "primary_utility_metrics_authorized", "utility_bootstrap_authorized",
    "bootstrap_indices_generation_authorized",
    "sensitivity_scenarios_authorized", "rtm_impl_05_authorized",
    "network_access_authorized", "private_payload_copy_or_publication_authorized",
    "single_use", "stop_after_bounded_verification_receipt",
}
REVIEW_MEMBERS = {
    "EXECUTION_REVIEW.json",
    "authorization/raw_to_model_model_execution_authorization_96dc9b68_v1_2_4.json",
    "evidence/gate_b_completed_run_verification_receipt_f479fbab_v1_2_4.zip",
    "evidence/gate_c_completed_run_verification_receipt_f479fbab_v1_2_4.zip",
    "evidence/raw_to_model_model_stage_implementation_commit_receipt_v1_2_4.zip",
    "logs/model_stage.exitcode.txt",
    "logs/model_stage.stderr.bin",
    "logs/model_stage.stdout.bin",
    "logs/targeted_synthetic_tests.exitcode.txt",
    "logs/targeted_synthetic_tests.stderr.bin",
    "logs/targeted_synthetic_tests.stdout.bin",
    "public/model_execution_receipt.json",
    "repository/python/section_12_3_raw_to_model_model_runner_v1_2_4.py",
    "repository/scripts/run_raw_to_model_model_v1_2_4.ps1",
    "repository/tests/run_section_12_3_raw_to_model_model_runner_v1_2_4_tests.py",
    "repository/tests/test_section_12_3_raw_to_model_model_runner_v1_2_4.py",
}
PREDICTION_MAGIC = b"step7-predict-proba-f64le/1\x00"

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_AUTH_ID = re.compile(r"AUTH-[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Z0-9_-]+\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_HOLDOUT_RID = re.compile(r"adult\.test:([0-9]+)\Z")


class VerificationError(ValueError):


    def __init__(self, code, message):
        self.code = code
        super().__init__(code + ": " + message)


def require(condition, code, message):
    if not condition:
        raise VerificationError(code, message)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _artifact(data):
    return {"bytes": len(data), "sha256": _sha256(data)}


def _json_bytes(value):
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    except (TypeError, ValueError, OverflowError) as error:
        raise VerificationError("VERIFY_JSON_VALUE", "unsupported JSON value") from error


def _json_digest(value):
    return _sha256(_json_bytes(value)[:-1])


def _unique_json(data, name, *, canonical=False):
    require(type(data) is bytes and data and not data.startswith(b"\xef\xbb\xbf")
            and b"\x00" not in data, "VERIFY_JSON_BYTES", name + " has invalid bytes")

    def pairs(items):
        result = {}
        for key, value in items:
            require(type(key) is str and key not in result,
                    "VERIFY_JSON_DUPLICATE", name + " contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("VERIFY_JSON_PARSE", "invalid " + name) from error
    if canonical:
        require(data == _json_bytes(value), "VERIFY_JSON_CANONICAL",
                name + " must be canonical ASCII JSON with one final LF")
    return value


def _read_stable(path):
    require(path.is_file() and not path.is_symlink(), "VERIFY_INPUT_FILE",
            "missing regular non-symlink input")
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    require(before.st_size == after.st_size == len(data)
            and before.st_mtime_ns == after.st_mtime_ns,
            "VERIFY_INPUT_CHANGED", "input changed while read")
    return data


def _read_exact(path, identity, name):
    data = _read_stable(path)
    require(_artifact(data) == identity, "VERIFY_INPUT_IDENTITY", name + " identity differs")
    return data


def _safe_zip_bytes(data, name):
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise VerificationError("VERIFY_ZIP", name + " is not a ZIP") from error
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        require(names and len(names) == len(set(names)) and archive.testzip() is None,
                "VERIFY_ZIP", name + " has duplicate members or a CRC failure")
        result = {}
        for info in infos:
            member = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            require(not member.is_absolute() and ".." not in member.parts
                    and "\\" not in info.filename and member.as_posix() == info.filename
                    and not stat.S_ISLNK(mode) and not (info.flag_bits & 1)
                    and not info.is_dir(), "VERIFY_ZIP", name + " contains an unsafe member")
            result[info.filename] = archive.read(info.filename)
    return result


def _utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _assert_artifact(value, expected, name):
    require(type(value) is dict and set(value) == {"bytes", "sha256"}
            and type(value["bytes"]) is int and value["bytes"] >= 0
            and type(value["sha256"]) is str
            and _SHA256.fullmatch(value["sha256"]) is not None
            and value == expected, "VERIFY_ARTIFACT", name + " identity differs")


def _assert_public(value, path="$"):
    if type(value) is dict:
        for key, item in value.items():
            require(key not in PUBLIC_FORBIDDEN_KEYS, "VERIFY_PUBLIC_PRIVATE_KEY",
                    "private key in public receipt at " + path + "." + key)
            if key == "rows":
                require(type(item) is int and item >= 0,
                        "VERIFY_PUBLIC_ROWS", "nonaggregate rows field")
            _assert_public(item, path + "." + key)
    elif type(value) is list:
        for index, item in enumerate(value):
            _assert_public(item, path + "[" + str(index) + "]")
    elif type(value) is str:
        require(_HOLDOUT_RID.fullmatch(value) is None,
                "VERIFY_PUBLIC_RID", "private RID in public receipt")


def _artifact_mapping(value, name):
    require(type(value) is dict and set(value) == {VERIFIER_RELATIVE, WRAPPER_RELATIVE},
            "VERIFY_AUTH_IMPLEMENTATION", name + " fields differ")
    for path, identity in value.items():
        require(type(identity) is dict and set(identity) == {"bytes", "sha256"}
                and type(identity["bytes"]) is int and identity["bytes"] > 0
                and type(identity["sha256"]) is str
                and _SHA256.fullmatch(identity["sha256"]) is not None,
                "VERIFY_AUTH_IMPLEMENTATION", path + " identity is invalid")
    return value


def parse_authorization(data, current_head, current_tree):
    record = _unique_json(data, "artifact verification authorization", canonical=True)
    require(type(record) is dict and set(record) == AUTHORIZATION_KEYS,
            "VERIFY_AUTH_SCHEMA", "authorization fields differ")
    require(record["record_schema"] == AUTHORIZATION_SCHEMA
            and record["effective_protocol"] == PROTOCOL_VERSION,
            "VERIFY_AUTH_SCHEMA", 'authorization schema or execution specification differs')
    require(type(record["authorization_id"]) is str
            and _AUTH_ID.fullmatch(record["authorization_id"]) is not None,
            "VERIFY_AUTH_ID", "authorization ID is invalid")
    require(type(record["authorized_at_utc"]) is str
            and _UTC.fullmatch(record["authorized_at_utc"]) is not None,
            "VERIFY_AUTH_TIME", "authorization time must be whole-second UTC")
    require(record["authorized_by"] == "researcher"
            and record["authorized_source_commit"] == current_head
            and record["authorized_source_tree"] == current_tree
            and _COMMIT.fullmatch(current_head) is not None
            and _COMMIT.fullmatch(current_tree) is not None,
            "VERIFY_AUTH_SOURCE", "authorization does not bind current HEAD/tree")
    require(record["bound_model_execution_commit"] == MODEL_HEAD
            and record["bound_model_execution_tree"] == MODEL_TREE,
            "VERIFY_AUTH_MODEL_SOURCE", "model-stage source binding differs")
    _assert_artifact(record["bound_model_execution_authorization"],
                     MODEL_AUTHORIZATION, "model authorization")
    _assert_artifact(record["bound_model_execution_review_zip"],
                     MODEL_REVIEW_ZIP, "model review ZIP")
    _assert_artifact(record["bound_public_model_receipt"],
                     PUBLIC_MODEL_RECEIPT, "public model receipt")
    _assert_artifact(record["bound_private_model_artifact"],
                     PRIVATE_MODEL_ARTIFACT, "private model artifact")
    _assert_artifact(record["bound_private_model_session"],
                     PRIVATE_MODEL_SESSION, "private model session")
    _artifact_mapping(record["implementation_artifacts"], "implementation artifacts")
    require(record["authorized_stage"]
            == "PRIVATE_MODEL_ARTIFACT_INTEGRITY_ONLY_NO_METRICS"
            and record["model_execution_review_zip_read_authorized"] is True
            and record["public_model_receipt_read_authorized"] is True
            and record["private_model_session_read_authorized"] is True
            and record["private_model_artifact_read_authorized"] is True,
            "VERIFY_AUTH_SCOPE", "required read-only verification scope is absent")
    for key in (
        "raw_holdout_source_read_authorized", "model_fits_authorized",
        "prediction_generation_authorized",
        "dummy_baseline_metric_recomputation_authorized",
        "primary_utility_metrics_authorized", "utility_bootstrap_authorized",
        "bootstrap_indices_generation_authorized", "sensitivity_scenarios_authorized",
        "rtm_impl_05_authorized", "network_access_authorized",
        "private_payload_copy_or_publication_authorized",
    ):
        require(record[key] is False, "VERIFY_AUTH_BOUNDARY",
                key + " must be explicitly false")
    require(record["single_use"] is True
            and record["stop_after_bounded_verification_receipt"] is True,
            "VERIFY_AUTH_BOUNDARY", "single-use stop boundary differs")
    return record


def _run(command, *, cwd=None):
    environment = dict(os.environ)
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"):
        environment.pop(key, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(command, cwd=str(cwd) if cwd else None, env=environment,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def _git(repository, *arguments):
    executable = shutil.which("git")
    require(executable is not None, "VERIFY_GIT", "Git executable is unavailable")
    result = _run([executable, "-c", "core.quotepath=false", "-C", str(repository),
                   *arguments])
    require(result.returncode == 0, "VERIFY_GIT",
            "Git command failed: " + " ".join(arguments))
    return result.stdout


def _runtime_guard(repository):
    require(sys.implementation.name == "cpython" and sys.platform == "win32"
            and platform.system() == "Windows" and sys.version_info[:3] == EXPECTED_PYTHON
            and struct.calcsize("P") * 8 == EXPECTED_BITS,
            "VERIFY_RUNTIME", "64-bit CPython 3.12.10 on Windows is required")
    require(sys.flags.isolated and sys.dont_write_bytecode,
            "VERIFY_RUNTIME", "invoke verifier with -I -B")
    expected = repository / ".venv" / "Scripts" / "python.exe"
    require(Path(sys.executable).resolve() == expected.resolve(),
            "VERIFY_RUNTIME", "interpreter is not repository .venv Python")


def _repository_guard(repository, authorization_data):
    require(repository.is_absolute() and repository.is_dir(),
            "VERIFY_REPOSITORY", "repository must be an existing absolute directory")
    root = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip())
    require(root.resolve() == repository.resolve(),
            "VERIFY_REPOSITORY", "path is not the Git root")
    head = _git(repository, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    tree = _git(repository, "rev-parse", "--verify", "HEAD^{tree}").decode("ascii").strip()
    authorization = parse_authorization(authorization_data, head, tree)
    ancestry = _run([shutil.which("git"), "-C", str(repository), "merge-base",
                     "--is-ancestor", MODEL_HEAD, head])
    require(ancestry.returncode == 0, "VERIFY_REPOSITORY",
            "current HEAD does not descend from model-stage commit")
    require(_git(repository, "rev-parse", MODEL_HEAD + "^{tree}").decode("ascii").strip()
            == MODEL_TREE, "VERIFY_REPOSITORY", "model-stage tree identity differs")
    require(_git(repository, "status", "--porcelain=v1", "-z", "--untracked-files=no")
            == b"", "VERIFY_REPOSITORY", "tracked repository state is not clean")
    for relative, identity in authorization["implementation_artifacts"].items():
        data = _read_stable(repository / relative)
        require(_artifact(data) == identity
                and _git(repository, "show", "HEAD:" + relative) == data,
                "VERIFY_IMPLEMENTATION_IDENTITY", relative + " differs from authorization/HEAD")
    return head, tree, authorization


def _validate_review_zip(data, public_data):
    require(_artifact(data) == MODEL_REVIEW_ZIP,
            "VERIFY_REVIEW_IDENTITY", "model-stage review ZIP identity differs")
    members = _safe_zip_bytes(data, "model-stage review ZIP")
    require(set(members) == REVIEW_MEMBERS,
            "VERIFY_REVIEW_MEMBERS", "model-stage review ZIP members differ")
    require(members["public/model_execution_receipt.json"] == public_data,
            "VERIFY_REVIEW_PUBLIC", "local public receipt differs from reviewed receipt")
    review = _unique_json(members["EXECUTION_REVIEW.json"],
                          "model-stage execution review")
    require(review.get("record_schema")
            == "raw-to-model-model-stage-authorized-execution-review-v1.2.4/1.0"
            and review.get("result") == "PASS"
            and review.get("classification")
            == "MODEL_PREDICTIONS_PASS_PENDING_INDEPENDENT_VERIFICATION",
            "VERIFY_REVIEW_STATUS", "model-stage execution review status differs")
    repository = review.get("repository")
    require(type(repository) is dict and repository.get("head") == MODEL_HEAD
            and repository.get("tree") == MODEL_TREE
            and repository.get("tracked_state_clean_after_execution") is True,
            "VERIFY_REVIEW_REPOSITORY", "model-stage review repository binding differs")
    _assert_artifact({key: review["authorization"][key] for key in ("bytes", "sha256")},
                     MODEL_AUTHORIZATION, "reviewed model authorization")
    require(review["authorization"].get("single_use") is True,
            "VERIFY_REVIEW_AUTH", "model authorization was not single-use")
    _assert_artifact(review["public_model_receipt"], PUBLIC_MODEL_RECEIPT,
                     "reviewed public receipt")
    reviewed_private = review.get("private_model_artifact")
    require(type(reviewed_private) is dict
            and {key: reviewed_private.get(key) for key in ("bytes", "sha256")}
            == PRIVATE_MODEL_ARTIFACT
            and reviewed_private.get("included_in_review_zip") is False
            and reviewed_private.get("local_identity_verified") is True,
            "VERIFY_REVIEW_PRIVATE", "reviewed private artifact binding differs")
    reviewed_session = review.get("private_session_record")
    require(type(reviewed_session) is dict
            and {key: reviewed_session.get(key) for key in ("bytes", "sha256")}
            == PRIVATE_MODEL_SESSION and reviewed_session.get("included_in_review_zip") is False,
            "VERIFY_REVIEW_SESSION", "reviewed private session binding differs")
    require(review.get("configuration_count") == 17
            and review.get("raw_cv_fit_count") == 15
            and review.get("final_model_fit_count") == 33
            and review.get("prior_baseline_fit_count") == 1
            and review.get("total_actual_model_fit_count") == 49
            and review.get("prediction_model_count") == 34
            and review.get("holdout_accessed") is True
            and review.get("model_fits_executed") is True
            and review.get("predictions_generated") is True
            and review.get("dummy_baseline_descriptive_metrics_computed") is True,
            "VERIFY_REVIEW_COUNTS", "model-stage execution counts differ")
    for key in ("primary_utility_metrics_executed", "utility_bootstrap_executed",
                "bootstrap_indices_generated", "sensitivity_scenarios_executed",
                "gate_b_rerun", "gate_c_rerun", "arx_anonymization_invoked",
                "model_stage_independently_verified", "raw_to_model_end_to_end_verified",
                "production_pipeline_verified"):
        require(review.get(key) is False,
                "VERIFY_REVIEW_BOUNDARY", key + " must remain false")
    require(review.get("rtm_impl_05") == "NOT_IMPLEMENTED",
            "VERIFY_REVIEW_BOUNDARY", "RTM-IMPL-05 state differs")
    auth_member = members[
        "authorization/raw_to_model_model_execution_authorization_96dc9b68_v1_2_4.json"
    ]
    require(_artifact(auth_member) == MODEL_AUTHORIZATION,
            "VERIFY_REVIEW_AUTH", "embedded model authorization identity differs")
    _unique_json(auth_member, "embedded model authorization", canonical=True)
    for member, identity in (
        ("evidence/gate_b_completed_run_verification_receipt_f479fbab_v1_2_4.zip",
         GATE_B_RECEIPT),
        ("evidence/gate_c_completed_run_verification_receipt_f479fbab_v1_2_4.zip",
         GATE_C_RECEIPT),
        ("evidence/raw_to_model_model_stage_implementation_commit_receipt_v1_2_4.zip",
         IMPLEMENTATION_RECEIPT),
    ):
        require(_artifact(members[member]) == identity,
                "VERIFY_REVIEW_EVIDENCE", member + " identity differs")
        _safe_zip_bytes(members[member], member)
    require(members["logs/model_stage.exitcode.txt"] == b"0\n"
            and members["logs/targeted_synthetic_tests.exitcode.txt"] == b"0\n"
            and len(members["logs/model_stage.stderr.bin"]) == 0,
            "VERIFY_REVIEW_LOG", "reviewed execution/test exit status differs")
    return review


def _expected_model_session():
    return {
        "record_schema": MODEL_SESSION_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "repository_head": MODEL_HEAD,
        "repository_tree": MODEL_TREE,
        "producer_head": PRODUCER_HEAD,
        "producer_tree": PRODUCER_TREE,
        "authorization_record": MODEL_AUTHORIZATION,
        "gate_b_verification_receipt": GATE_B_RECEIPT,
        "gate_c_verification_receipt": GATE_C_RECEIPT,
        "authorized_stage": "MODEL_PREDICTIONS_AND_DESCRIPTIVE_PRIOR_BASELINE_ONLY",
        "dummy_baseline_descriptive_metrics_authorized": True,
        "primary_utility_metrics_authorized": False,
        "utility_bootstrap_authorized": False,
        "sensitivity_scenarios_authorized": False,
    }


def _validate_model_session(data, *, operational=True):
    session = _unique_json(data, "private model session", canonical=True)
    require(type(session) is dict, "VERIFY_MODEL_SESSION", "model session is not a mapping")
    if operational:
        require(_artifact(data) == PRIVATE_MODEL_SESSION
                and session == _expected_model_session(),
                "VERIFY_MODEL_SESSION", "private model session differs")
    return session


def _expected_role(key):
    if key == "CFG00":
        return "CFG00", "raw_training"
    cfg_id, suffix = key.split("/", 1)
    return cfg_id, "released_training" if suffix == "release" else "counterfactual_training"


def _validate_ids(value, *, operational):
    require(type(value) is list and value, "VERIFY_ROW_IDS", "holdout row IDs must be a list")
    numbers = []
    for item in value:
        require(type(item) is str and item and "\x00" not in item,
                "VERIFY_ROW_IDS", "holdout row ID is invalid")
        try:
            item.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise VerificationError("VERIFY_ROW_IDS", "holdout row ID is invalid") from error
        match = _HOLDOUT_RID.fullmatch(item)
        require(match is not None, "VERIFY_ROW_IDS", "holdout row ID format differs")
        numbers.append(int(match.group(1)))
    require(len(value) == len(set(value)) and numbers == sorted(numbers)
            and len(numbers) == len(set(numbers)),
            "VERIFY_ROW_IDS", "holdout row IDs are duplicated or out of order")
    if operational:
        require(len(value) == EXPECTED_HOLDOUT_ROWS
                and numbers[0] >= 2 and numbers[-1] <= 16282
                and _json_digest(value) == EXPECTED_HOLDOUT_ROW_IDS_SHA256,
                "VERIFY_ROW_IDS", "holdout row ID population differs")
    return value


def _validate_labels(value, row_count, *, operational):
    require(type(value) is list and len(value) == row_count
            and all(type(item) is int and item in (0, 1) for item in value),
            "VERIFY_LABELS", "holdout labels differ")
    if operational:
        require(dict(Counter(value)) == EXPECTED_HOLDOUT_LABEL_COUNTS
                and _json_digest(value) == EXPECTED_HOLDOUT_LABELS_SHA256,
                "VERIFY_LABELS", "holdout label population differs")
    return value


def _prediction_identity(row_ids, probabilities):
    require(type(probabilities) is list and len(probabilities) == len(row_ids),
            "VERIFY_PREDICTIONS", "prediction row count differs")
    digest = hashlib.sha256()
    digest.update(PREDICTION_MAGIC)
    digest.update(struct.pack("<QQ", len(row_ids), 2))
    byte_count = len(PREDICTION_MAGIC) + 16
    for rid, row in zip(row_ids, probabilities):
        require(type(row) is list and len(row) == 2,
                "VERIFY_PREDICTIONS", "prediction must have two columns")
        require(all(type(value) is float and math.isfinite(value)
                    and 0.0 <= value <= 1.0 for value in row),
                "VERIFY_PREDICTIONS", "prediction value is invalid")
        require(abs(row[0] + row[1] - 1.0) <= 1e-12,
                "VERIFY_PREDICTIONS", "prediction columns are not normalized")
        encoded = rid.encode("utf-8")
        pieces = (struct.pack("<Q", len(encoded)), encoded,
                  struct.pack("<dd", row[0], row[1]))
        for piece in pieces:
            digest.update(piece)
            byte_count += len(piece)
    return {"bytes": byte_count, "sha256": digest.hexdigest()}


def _fit_receipt_boundary(receipt, key, role, prediction_identity):
    require(type(receipt) is dict and receipt.get("record_schema")
            == "step7-guarded-fit-consumer-diagnostics/1"
            and receipt.get("result") == "PASS"
            and receipt.get("execution_kind") == "NATIVE_SKLEARN"
            and receipt.get("actual_native_fit_count") == 1
            and receipt.get("synthetic_double_fit_count") == 0
            and receipt.get("fit_id") == "final/" + key
            and receipt.get("selected_C") == 1.0
            and receipt.get("training_role") == role
            and receipt.get("prediction_role") == "holdout"
            and receipt.get("prediction_sha256") == prediction_identity["sha256"]
            and receipt.get("prediction_bytes") == prediction_identity["bytes"],
            "VERIFY_FINAL_RECEIPT", key + " public fit receipt differs")
    alignment = receipt.get("prediction_alignment")
    require(type(alignment) is dict and alignment.get("result") == "PASS"
            and alignment.get("rows") == EXPECTED_HOLDOUT_ROWS
            and alignment.get("row_order_sha256") == EXPECTED_HOLDOUT_ROW_IDS_SHA256
            and alignment.get("y_sha256") == EXPECTED_HOLDOUT_LABELS_SHA256
            and alignment.get("prediction_sha256") == prediction_identity["sha256"],
            "VERIFY_FINAL_RECEIPT", key + " prediction alignment differs")
    convergence = receipt.get("final_convergence")
    require(type(convergence) is dict and convergence.get("result") == "PASS",
            "VERIFY_FINAL_RECEIPT", key + " convergence status differs")


def _validate_public_receipt(data, *, operational):
    public = _unique_json(data, "public model receipt", canonical=True)
    require(type(public) is dict and public.get("record_schema") == PUBLIC_SCHEMA
            and public.get("effective_protocol") == PROTOCOL_VERSION
            and public.get("result") == "PASS"
            and public.get("classification")
            == "MODEL_PREDICTIONS_PASS_PENDING_INDEPENDENT_VERIFICATION",
            "VERIFY_PUBLIC_SCHEMA", "public model receipt status differs")
    require(public.get("repository_head") == MODEL_HEAD
            and public.get("repository_tree") == MODEL_TREE
            and public.get("producer_head") == PRODUCER_HEAD
            and public.get("producer_tree") == PRODUCER_TREE,
            "VERIFY_PUBLIC_SOURCE", "public model receipt source differs")
    auth = public.get("authorization")
    require(type(auth) is dict and auth.get("record_sha256") == MODEL_AUTHORIZATION["sha256"]
            and auth.get("single_use") is True
            and auth.get("authorized_stage")
            == "MODEL_PREDICTIONS_AND_DESCRIPTIVE_PRIOR_BASELINE_ONLY",
            "VERIFY_PUBLIC_AUTH", "public model authorization binding differs")
    require(public.get("configuration_count") == 17
            and public.get("raw_cv_fit_count") == 15
            and public.get("final_model_fit_count") == 33
            and public.get("prior_baseline_fit_count") == 1
            and public.get("total_actual_model_fit_count") == 49
            and public.get("prediction_model_count") == 34
            and public.get("holdout_accessed") is True
            and public.get("model_fits_executed") is True
            and public.get("predictions_generated") is True
            and public.get("dummy_baseline_descriptive_metrics_computed") is True,
            "VERIFY_PUBLIC_COUNTS", "public model-stage counts differ")
    for key in ("primary_utility_metrics_executed", "utility_bootstrap_executed",
                "bootstrap_indices_generated", "sensitivity_scenarios_executed",
                "gate_b_rerun", "gate_c_rerun", "arx_anonymization_invoked",
                "raw_to_model_model_stage_verified", "raw_to_model_end_to_end_verified",
                "production_pipeline_verified"):
        require(public.get(key) is False,
                "VERIFY_PUBLIC_BOUNDARY", key + " must remain false")
    require(public.get("remaining_static_obligation") == "RTM-IMPL-05"
            and public.get("private_payloads_in_public_receipt") is False,
            "VERIFY_PUBLIC_BOUNDARY", "public downstream/privacy boundary differs")
    require(public.get("private_model_artifact") == PRIVATE_MODEL_ARTIFACT
            if operational else type(public.get("private_model_artifact")) is dict,
            "VERIFY_PUBLIC_PRIVATE_ID", "private artifact identity differs")
    source_hash = public.get("source_context_sha256")
    require(type(source_hash) is str and _SHA256.fullmatch(source_hash) is not None,
            "VERIFY_PUBLIC_CONTEXT", "source context hash is invalid")
    if operational:
        require(_artifact(data) == PUBLIC_MODEL_RECEIPT
                and source_hash == EXPECTED_SOURCE_CONTEXT_SHA256,
                "VERIFY_PUBLIC_IDENTITY", "public receipt identity/context differs")
    _assert_public(public)
    return public


def verify_model_records(private_data, public_data, *, operational=True):

    public = _validate_public_receipt(public_data, operational=operational)
    private = _unique_json(private_data, "private model artifact", canonical=True)
    require(type(private) is dict and set(private) == PRIVATE_KEYS,
            "VERIFY_PRIVATE_SCHEMA", "private model artifact fields differ")
    require(private["record_schema"] == PRIVATE_SCHEMA
            and private["effective_protocol"] == PROTOCOL_VERSION
            and private["repository_head"] == MODEL_HEAD
            and private["repository_tree"] == MODEL_TREE
            and private["producer_head"] == PRODUCER_HEAD
            and private["producer_tree"] == PRODUCER_TREE
            and private["authorization_record_sha256"] == MODEL_AUTHORIZATION["sha256"]
            and private["selected_C"] == 1.0
            and private["model_fit_count"] == 49
            and private["prediction_model_count"] == 34
            and private["visibility"] == "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
            "VERIFY_PRIVATE_STATUS", "private model artifact status differs")
    if operational:
        require(_artifact(private_data) == PRIVATE_MODEL_ARTIFACT,
                "VERIFY_PRIVATE_IDENTITY", "private model artifact identity differs")
    require(public.get("private_model_artifact") == _artifact(private_data),
            "VERIFY_PRIVATE_PUBLIC_IDENTITY",
            "public receipt does not bind the supplied private artifact")
    context = private["source_context"]
    require(type(context) is dict and set(context) == SOURCE_CONTEXT_KEYS,
            "VERIFY_SOURCE_CONTEXT", "source context fields differ")
    context_hash = _json_digest(context)
    require(context_hash == public["source_context_sha256"],
            "VERIFY_SOURCE_CONTEXT", "private/public source context binding differs")
    if operational:
        require(context_hash == EXPECTED_SOURCE_CONTEXT_SHA256,
                "VERIFY_SOURCE_CONTEXT", "source context identity differs")

    row_ids = _validate_ids(private["holdout_row_ids"], operational=operational)
    labels = _validate_labels(private["holdout_labels"], len(row_ids),
                              operational=operational)
    public_final = public.get("final_fit_receipts")
    private_final = private["final_models"]
    require(type(public_final) is dict and type(private_final) is dict
            and set(public_final) == FINAL_MODEL_KEYS
            and set(private_final) == FINAL_MODEL_KEYS,
            "VERIFY_FINAL_MODELS", "final model key set differs")

    prediction_hashes = []
    final_fit_ids = []
    prediction_bytes = None
    for key in sorted(FINAL_MODEL_KEYS):
        item = private_final[key]
        require(type(item) is dict and set(item) == PRIVATE_MODEL_KEYS,
                "VERIFY_PRIVATE_MODEL", key + " fields differ")
        cfg_id, role = _expected_role(key)
        require(item["cfg_id"] == cfg_id and item["training_role"] == role
                and item["C"] == 1.0 and item["prediction_row_ids"] == row_ids,
                "VERIFY_PRIVATE_MODEL", key + " identity/role/rows differ")
        identity = _prediction_identity(row_ids, item["prediction_probabilities"])
        require(item["prediction_sha256"] == identity["sha256"],
                "VERIFY_PREDICTION_HASH", key + " stored prediction hash differs")
        receipt = public_final[key]
        if operational:
            _fit_receipt_boundary(receipt, key, role, identity)
        else:
            require(type(receipt) is dict
                    and receipt.get("prediction_sha256") == identity["sha256"]
                    and receipt.get("prediction_bytes") == identity["bytes"]
                    and receipt.get("fit_id") == "final/" + key,
                    "VERIFY_FINAL_RECEIPT", key + " fixture receipt differs")
        prediction_hashes.append(identity["sha256"])
        final_fit_ids.append(receipt["fit_id"])
        if prediction_bytes is None:
            prediction_bytes = identity["bytes"]
        require(prediction_bytes == identity["bytes"],
                "VERIFY_PREDICTION_BYTES", "prediction serialization sizes differ")

    baseline = private["prior_baseline"]
    require(type(baseline) is dict and set(baseline) == PRIVATE_BASELINE_KEYS
            and baseline["prediction_row_ids"] == row_ids,
            "VERIFY_BASELINE", "private baseline fields/rows differ")
    class_prior = baseline["class_prior"]
    require(type(class_prior) is list and len(class_prior) == 2
            and all(type(value) is float and math.isfinite(value)
                    and 0.0 <= value <= 1.0 for value in class_prior)
            and abs(sum(class_prior) - 1.0) <= 1e-12,
            "VERIFY_BASELINE", "baseline class prior differs")
    if operational:
        require(class_prior == EXPECTED_CLASS_PRIOR,
                "VERIFY_BASELINE", "baseline class prior identity differs")
    probabilities = baseline["prediction_probabilities"]
    require(type(probabilities) is list
            and all(row == class_prior for row in probabilities),
            "VERIFY_BASELINE", "baseline predictions are not constant priors")
    baseline_identity = _prediction_identity(row_ids, probabilities)
    require(baseline["prediction_sha256"] == baseline_identity["sha256"],
            "VERIFY_BASELINE_HASH", "baseline prediction hash differs")
    public_baseline = public.get("prior_baseline_receipt")
    require(type(public_baseline) is dict
            and public_baseline.get("fit_id") == "final/prior-baseline"
            and public_baseline.get("result") == "PASS"
            and public_baseline.get("execution_kind") == "NATIVE_SKLEARN"
            and public_baseline.get("actual_native_fit_count") == 1
            and public_baseline.get("synthetic_double_fit_count") == 0
            and public_baseline.get("prediction_sha256") == baseline_identity["sha256"]
            and public_baseline.get("prediction_bytes") == baseline_identity["bytes"]
            and public_baseline.get("fitted_class_prior") == class_prior
            and public_baseline.get("primary_release_delta_included") is False
            and public_baseline.get("intervals") is None,
            "VERIFY_BASELINE_RECEIPT", "public baseline receipt differs")

    raw_cv = public.get("raw_cv")
    cv_receipts = raw_cv.get("fit_receipts") if type(raw_cv) is dict else None
    require(type(raw_cv) is dict and raw_cv.get("selected_C") == 1.0
            and raw_cv.get("fit_count") == 15
            and raw_cv.get("selection_scope") == "raw_training_only"
            and raw_cv.get("holdout_used_for_selection") is False
            and type(cv_receipts) is list and len(cv_receipts) == 15,
            "VERIFY_RAW_CV", "raw-CV receipt differs")
    cv_fit_ids = []
    for item in cv_receipts:
        require(type(item) is dict and type(item.get("fit_receipt")) is dict,
                "VERIFY_RAW_CV", "raw-CV fit receipt is invalid")
        fit = item["fit_receipt"]
        require(fit.get("result") == "PASS"
                and fit.get("execution_kind") == "NATIVE_SKLEARN"
                and fit.get("actual_native_fit_count") == 1
                and fit.get("synthetic_double_fit_count") == 0
                and fit.get("fit_id") == item.get("fit_id"),
                "VERIFY_RAW_CV", "raw-CV native fit identity differs")
        cv_fit_ids.append(fit["fit_id"])
    all_fit_ids = cv_fit_ids + final_fit_ids + [public_baseline["fit_id"]]
    require(len(all_fit_ids) == len(set(all_fit_ids)) == 49,
            "VERIFY_FIT_IDENTITIES", "49 fit identities are incomplete or duplicated")

    return {
        "private_artifact": _artifact(private_data),
        "public_receipt": _artifact(public_data),
        "source_context_sha256": context_hash,
        "holdout_row_ids_sha256": _json_digest(row_ids),
        "holdout_labels_sha256": _json_digest(labels),
        "holdout_rows": len(row_ids),
        "final_model_count": len(private_final),
        "prediction_model_count": len(private_final) + 1,
        "fit_identity_count": len(all_fit_ids),
        "prediction_serialization_bytes_per_model": prediction_bytes,
        "prediction_hash_count": len(prediction_hashes) + 1,
        "all_prediction_hashes_recomputed": True,
        "baseline_constant_prior_verified": True,
    }


def _write_new(path, data):
    require(not path.exists(), "VERIFY_OUTPUT_EXISTS", "refusing to overwrite output")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "VERIFY_OUTPUT_TEMP", "temporary output exists")
    temporary.write_bytes(data)
    temporary.replace(path)


def _repository_path(repository, relative):
    path = repository / relative
    try:
        inside = path.resolve().is_relative_to(repository.resolve())
    except (OSError, RuntimeError):
        inside = False
    require(inside, "VERIFY_REPOSITORY_PATH", "repository path resolves outside root")
    return path


def _failure_code(error):
    code = getattr(error, "code", None)
    if type(code) is str and 0 < len(code) <= 128:
        return code
    return type(error).__name__


def run_operational(repository, authorization_path, review_zip_path):
    repository = repository.resolve()
    _runtime_guard(repository)
    authorization_data = _read_stable(authorization_path.resolve())
    head, tree, authorization = _repository_guard(repository, authorization_data)

    private_root = _repository_path(repository, PRIVATE_OUTPUT_RELATIVE)
    private_pending = _repository_path(repository, PRIVATE_OUTPUT_RELATIVE + ".pending")
    public_root = _repository_path(repository, PUBLIC_OUTPUT_RELATIVE)
    public_pending = _repository_path(repository, PUBLIC_OUTPUT_RELATIVE + ".pending")
    failure_path = _repository_path(repository, "runs/main_v1_2_4/" + (
        "raw_to_model_model_artifact_verification_failure_"
        + authorization["authorization_id"] + ".json"))
    require(not private_root.exists() and not private_pending.exists()
            and not public_root.exists() and not public_pending.exists()
            and not failure_path.exists(),
            "VERIFY_SINGLE_USE", "verification stage or prior attempt already exists")

    progress = {
        "record_schema": VERIFICATION_FAILURE_SCHEMA,
        "result": "IN_PROGRESS",
        "authorization_id": authorization["authorization_id"],
        "authorization_record_sha256": _sha256(authorization_data),
        "verifier_repository_head": head,
        "verifier_repository_tree": tree,
        "model_execution_repository_head": MODEL_HEAD,
        "model_execution_repository_tree": MODEL_TREE,
        "stage": "AUTHORIZED_BEFORE_PRIVATE_ARTIFACT_ACCESS",
        "model_execution_review_zip_accessed": False,
        "public_model_receipt_accessed": False,
        "private_model_session_accessed": False,
        "private_model_artifact_accessed": False,
        "raw_holdout_source_accessed": False,
        "model_fits_executed": False,
        "predictions_generated": False,
        "dummy_baseline_metrics_recomputed": False,
        "primary_utility_metrics_executed": False,
        "utility_bootstrap_executed": False,
        "bootstrap_indices_generated": False,
        "sensitivity_scenarios_executed": False,
        "rtm_impl_05_executed": False,
        "network_accessed": False,
    }
    private_pending.mkdir(parents=True, exist_ok=False)
    session = {
        "record_schema": VERIFICATION_SESSION_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "authorization_record": _artifact(authorization_data),
        "verifier_repository_head": head,
        "verifier_repository_tree": tree,
        "model_execution_repository_head": MODEL_HEAD,
        "model_execution_repository_tree": MODEL_TREE,
        "authorized_stage": "PRIVATE_MODEL_ARTIFACT_INTEGRITY_ONLY_NO_METRICS",
        "raw_holdout_source_read_authorized": False,
        "model_fits_authorized": False,
        "primary_utility_metrics_authorized": False,
        "utility_bootstrap_authorized": False,
        "sensitivity_scenarios_authorized": False,
        "private_payload_copy_or_publication_authorized": False,
    }
    _write_new(private_pending / "SESSION.json", _json_bytes(session))
    started_at = _utc_now()
    started_clock = time.perf_counter()
    try:
        progress["stage"] = "READ_BOUND_PUBLIC_EVIDENCE"
        public_data = _read_exact(_repository_path(repository, PUBLIC_RECEIPT_RELATIVE),
                                  PUBLIC_MODEL_RECEIPT, "public model receipt")
        progress["public_model_receipt_accessed"] = True
        review_data = _read_exact(review_zip_path.resolve(), MODEL_REVIEW_ZIP,
                                  "model-stage review ZIP")
        progress["model_execution_review_zip_accessed"] = True
        _validate_review_zip(review_data, public_data)

        progress["stage"] = "READ_BOUND_PRIVATE_ARTIFACTS"
        model_session_data = _read_exact(_repository_path(repository, PRIVATE_SESSION_RELATIVE),
                                         PRIVATE_MODEL_SESSION, "private model session")
        progress["private_model_session_accessed"] = True
        _validate_model_session(model_session_data, operational=True)
        private_data = _read_exact(_repository_path(repository, PRIVATE_ARTIFACT_RELATIVE),
                                   PRIVATE_MODEL_ARTIFACT, "private model artifact")
        progress["private_model_artifact_accessed"] = True

        progress["stage"] = "INDEPENDENT_SCHEMA_ASSOCIATION_AND_HASH_VERIFICATION"
        summary = verify_model_records(private_data, public_data, operational=True)
        receipt = {
            "record_schema": VERIFICATION_RECEIPT_SCHEMA,
            "tool_revision": TOOL_REVISION,
            "effective_protocol": PROTOCOL_VERSION,
            "result": "PASS",
            "classification": "MODEL_STAGE_PRIVATE_AND_PUBLIC_ARTIFACTS_INDEPENDENTLY_VERIFIED",
            "verifier_repository_head": head,
            "verifier_repository_tree": tree,
            "model_execution_repository_head": MODEL_HEAD,
            "model_execution_repository_tree": MODEL_TREE,
            "authorization": {
                "authorization_id": authorization["authorization_id"],
                "record_sha256": _sha256(authorization_data),
                "authorized_stage": authorization["authorized_stage"],
                "single_use": True,
            },
            "bound_artifacts": {
                "model_execution_review_zip": MODEL_REVIEW_ZIP,
                "public_model_receipt": summary["public_receipt"],
                "private_model_artifact": summary["private_artifact"],
                "private_model_session": PRIVATE_MODEL_SESSION,
            },
            "verification_checks": {
                "canonical_private_json_verified": True,
                "canonical_public_json_verified": True,
                "review_evidence_chain_verified": True,
                "private_public_source_context_binding_verified": True,
                "source_context_sha256": summary["source_context_sha256"],
                "holdout_row_ids_sha256": summary["holdout_row_ids_sha256"],
                "holdout_labels_sha256": summary["holdout_labels_sha256"],
                "holdout_rows": summary["holdout_rows"],
                "final_model_count": summary["final_model_count"],
                "prediction_model_count": summary["prediction_model_count"],
                "fit_identity_count": summary["fit_identity_count"],
                "prediction_hash_count": summary["prediction_hash_count"],
                "prediction_serialization_bytes_per_model":
                    summary["prediction_serialization_bytes_per_model"],
                "all_prediction_hashes_recomputed": True,
                "baseline_constant_prior_verified": True,
            },
            "private_model_artifact_locally_accessed": True,
            "private_payloads_copied": False,
            "private_payloads_in_public_receipt": False,
            "raw_holdout_source_accessed": False,
            "model_fits_executed": False,
            "predictions_generated": False,
            "dummy_baseline_metrics_recomputed": False,
            "primary_utility_metrics_executed": False,
            "utility_bootstrap_executed": False,
            "bootstrap_indices_generated": False,
            "sensitivity_scenarios_executed": False,
            "rtm_impl_05_executed": False,
            "network_accessed": False,
            "raw_to_model_model_stage_verified": True,
            "raw_to_model_end_to_end_verified": False,
            "production_pipeline_verified": False,
            "remaining_static_obligation": "RTM-IMPL-05",
            "next_required_control": (
                "SEPARATE_REVIEW_AND_AUTHORIZATION_REQUIRED_BEFORE_ANY_PRIMARY_UTILITY_"
                "METRIC_BOOTSTRAP_SENSITIVITY_OR_RTM_IMPL_05_EXECUTION"
            ),
            "execution_started_at_utc": started_at,
            "execution_completed_at_utc": _utc_now(),
            "wall_clock_seconds": time.perf_counter() - started_clock,
        }
        _assert_public(receipt)
        public_pending.mkdir(parents=True, exist_ok=False)
        _write_new(public_pending / "model_artifact_verification_receipt.json",
                   _json_bytes(receipt))
        private_pending.replace(private_root)
        public_pending.replace(public_root)
        return receipt, public_root
    except Exception as error:
        progress.update(result="FAIL", stage_status="STOP_PRESERVE_ALL_ARTIFACTS",
                        error_code=_failure_code(error), failed_at_utc=_utc_now())
        if private_pending.is_dir() and not (private_pending / "FAILURE.json").exists():
            _write_new(private_pending / "FAILURE.json", _json_bytes(progress))
        if not failure_path.exists():
            _assert_public(progress)
            _write_new(failure_path, _json_bytes(progress))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--authorization-record", required=True, type=Path)
    parser.add_argument("--model-execution-review-zip", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print("RESULT=RAW_TO_MODEL_MODEL_ARTIFACT_VERIFICATION_STARTING", flush=True)
        receipt, output = run_operational(
            args.repository, args.authorization_record, args.model_execution_review_zip)
        checks = receipt["verification_checks"]
        print("RESULT=RAW_TO_MODEL_MODEL_ARTIFACT_VERIFICATION_PASS", flush=True)
        print("TOOL_REVISION=" + TOOL_REVISION, flush=True)
        print("VERIFIER_REPOSITORY_HEAD=" + receipt["verifier_repository_head"], flush=True)
        print("MODEL_EXECUTION_REPOSITORY_HEAD=" + MODEL_HEAD, flush=True)
        print("PRIVATE_MODEL_ARTIFACT_SHA256="
              + receipt["bound_artifacts"]["private_model_artifact"]["sha256"], flush=True)
        print("FINAL_MODELS_VERIFIED=" + str(checks["final_model_count"]), flush=True)
        print("PREDICTION_MODELS_VERIFIED=" + str(checks["prediction_model_count"]), flush=True)
        print("PREDICTION_HASHES_RECOMPUTED=" + str(checks["prediction_hash_count"]), flush=True)
        print("PRIVATE_MODEL_ARTIFACT_LOCALLY_ACCESSED=true", flush=True)
        print("RAW_HOLDOUT_SOURCE_ACCESSED=false", flush=True)
        print("MODEL_FITS_EXECUTED=false", flush=True)
        print("PRIMARY_UTILITY_METRICS_EXECUTED=false", flush=True)
        print("UTILITY_BOOTSTRAP_EXECUTED=false", flush=True)
        print("SENSITIVITY_SCENARIOS_EXECUTED=false", flush=True)
        print("PUBLIC_OUTPUT=" + PUBLIC_OUTPUT_RELATIVE, flush=True)
        print("RESULT=STOP_AFTER_BOUNDED_MODEL_ARTIFACT_VERIFICATION_RECEIPT", flush=True)
        return 0
    except Exception as error:
        print("RESULT=RAW_TO_MODEL_MODEL_ARTIFACT_VERIFICATION_FAIL", flush=True)
        print("ERROR_CODE=" + _failure_code(error), flush=True)
        print("RESULT=STOP_PRESERVE_ALL_ARTIFACTS", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
