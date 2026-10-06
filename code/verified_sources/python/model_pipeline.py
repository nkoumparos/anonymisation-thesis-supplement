"""Train and validate prediction models."""

from __future__ import annotations

import argparse
from collections import Counter, OrderedDict
import csv
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


_MODULE_ROOT = Path(__file__).resolve().parent
if str(_MODULE_ROOT) not in sys.path:
    sys.path.insert(0, str(_MODULE_ROOT))

from common import QIS, json_digest, require  # noqa: E402
from dummy_baseline import fit_prior_baseline_guarded  # noqa: E402
from model_driver_diagnostics import (  # noqa: E402
    run_guarded_utility_models,
)
from transformation_bridge import (  # noqa: E402
    build_guarded_transformation_inputs,
)
from utility_evaluation import prediction_bytes  # noqa: E402


TOOL_REVISION = "1.0"
PROTOCOL_VERSION = "v1.2.4"
PRODUCER_HEAD = "f479fbabe2422315f98dd0d39ade2f26d92aef04"
PRODUCER_TREE = "82dcf163bf1a1123c2bf2e7bec54ac0a002b1e52"
PRODUCER_AUTHORIZATION_SHA256 = (
    "035cb52ad4c3c677f9fac8456442050338fa024f6cd09afe37b3b4d81d5276a6"
)
GATE_B_RECEIPT_BYTES = 8850
GATE_B_RECEIPT_SHA256 = (
    "c215235c7c992a76d1eccf31b89fb3fc3a43c2d625beda6bb0c274e260e1a6b1"
)
GATE_C_RECEIPT_BYTES = 19608
GATE_C_RECEIPT_SHA256 = (
    "3662ba9fc9a53b76566202c1dbfbf60bb354fe1ee328e3810ae0960bc2897542"
)

AUTHORIZATION_SCHEMA = "raw-to-model-model-execution-authorization/1.0"
PRIVATE_SCHEMA = "raw-to-model-model-private-v1.2.4/1.0"
PUBLIC_SCHEMA = "raw-to-model-model-execution-receipt-v1.2.4/1.0"
SESSION_SCHEMA = "raw-to-model-model-session-v1.2.4/1.0"
FAILURE_SCHEMA = "raw-to-model-model-failure-v1.2.4/1.0"

EXPECTED_PYTHON = (3, 12, 10)
EXPECTED_BITS = 64
EXPECTED_NUMPY = "2.0.2"
EXPECTED_SKLEARN = "1.9.0"
CONFIGURATIONS = tuple("CFG%02d" % index for index in range(17))
OUTPUT_CONFIGURATIONS = CONFIGURATIONS[1:]
PHYSICAL_SCHEMA = (
    "sex", "age", "race", "marital-status", "education",
    "native-country", "workclass", "occupation", "salary-class",
)
UCI_COLUMNS = (
    "age", "workclass", "fnlwgt", "education", "education-num",
    "marital-status", "occupation", "relationship", "race", "sex",
    "capital-gain", "capital-loss", "hours-per-week", "native-country",
    "salary-class",
)
PROJECTION = tuple(UCI_COLUMNS.index(name) for name in PHYSICAL_SCHEMA)

ARX_COMMIT = "4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f"
ARX_ROOT = "data/raw/arx-adult/" + ARX_COMMIT
ARX_TRAINING = ARX_ROOT + "/adult.csv"
UCI_ROOT = "data/raw/uci-adult"
UCI_TRAINING = UCI_ROOT + "/adult.data"
UCI_HOLDOUT = UCI_ROOT + "/adult.test"
RID_ORDER = "private/section_12_1_step_6_v1_2_3/rid_order.txt"
MASTER_PERMUTATION = "private/section_12_1_step_6_v1_2_3/master_permutation.txt"
RUN_ROOT = "runs/main_v1_2_4"
PRIVATE_ROOT = "private/main_v1_2_4"

ARX_TRAINING_IDENTITY = (
    2_516_935,
    "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5",
)
UCI_TRAINING_IDENTITY = (
    3_974_305,
    "5b00264637dbfec36bdeaab5676b0b309ff9eb788d63554ca0a249491c86603d",
)
UCI_HOLDOUT_IDENTITY = (
    2_003_153,
    "a2a9044bc167a35b2361efbabec64e89d69ce82d9790d2980119aac5fd7e9c05",
)
TRAINING_CANONICAL_IDENTITY = (
    2_486_772,
    "0711f26a4ba718f2eb8fa04395fc296cb3be1ba67135c828b93f6506bf4d8ca9",
)
HOLDOUT_CANONICAL_IDENTITY = (
    1_241_052,
    "8e363515eda22f5b3545fdb427450c688b41f461d5eefce32eac9c515577019b",
)
RID_ORDER_SHA256 = "11fd5eeaaa9fd5245361fce5b6d7aa7c8e4f0b7110ca026580586ccecb74ba68"
MASTER_PERMUTATION_SHA256 = (
    "4e1f8403536e0016645e42663763fd8551ca2f6babdd8185a1f30b7a6a017066"
)

HIERARCHIES = OrderedDict((
    ("age", (
        "data/derived/hierarchies/adult_hierarchy_age_semantic.csv", 2282,
        "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5", 5)),
    ("sex", (
        ARX_ROOT + "/adult_hierarchy_sex.csv", 16,
        "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2", 2)),
    ("race", (
        ARX_ROOT + "/adult_hierarchy_race.csv", 66,
        "df11abf41fa0669455adc9c9f9fa88663afa0cee8327684ecca861cd32dc4209", 2)),
    ("marital-status", (
        ARX_ROOT + "/adult_hierarchy_marital-status.csv", 239,
        "3e7ba2c4a5cd4fec059b4e3a2c57fce6e7c34a20daee1e624990ddd7beba85e5", 3)),
    ("education", (
        ARX_ROOT + "/adult_hierarchy_education.csv", 692,
        "f22e5ee519c28b05538d4e5ddea0fbee5f0017fefb3abab3fa02272325bf9ce5", 4)),
    ("native-country", (
        ARX_ROOT + "/adult_hierarchy_native-country.csv", 840,
        "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023", 3)),
    ("workclass", (
        ARX_ROOT + "/adult_hierarchy_workclass.csv", 211,
        "106f420349bf0071dbb25371795a78799edf24a64c3424619d563c3990ee8d02", 3)),
    ("occupation", (
        ARX_ROOT + "/adult_hierarchy_occupation.csv", 353,
        "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126", 3)),
))

DEPENDENCY_HASHES = {
    "configurations.csv": "ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e",
    "manifest/adult_sources_and_hierarchy_preflight.json": "3e86f3ea2532214cc6fe6072743e69bee5ae7cbd00b30aa79891c66e587e4cc8",
    "manifest/python_lock_manifest.txt": "4855a2ebb5f1b451ba965dd89c57271ee36d61148387f9562d44b509121fe6b2",
    "manifest/protocol_effective_v1_2_4.txt": "77ef91e9691eef8f271598b357f27f14650b52ea0f9bb6ebe5c1f4a0e4fd78e5",
    "manifest/section_12_1_locked_environment_control_806be110.json": "11d73d15bb6a82a2451af39762a83bb2db2348b80af73165ce23b0374181a7b5",
    "manifest/section_12_1_locked_environment_evidence_806be110.json": "f81365eb26056ff291a3dd1a3d61af633dd350e5f2badacfa1c59b162f1570f1",
    "manifest/section_12_1_step_7_implementation_contract_v1_2_3.json": "1294015f3f9fc39bce0b1606d5a97b7143f5069e1ac12a8bfc57d4011687b7b5",
    "python/requirements-lock-win-py312.txt": "5fa81d547b32a189a3a12a20cdc526c305f3f7f9deac291e5785b09990004964",
    "python/section_12_1_step_7_common.py": "2c77c6e9822a587fd5fe55ac47e504777e392b79f69e1989006069b840b87967",
    "python/section_12_1_step_7_dummy_baseline.py": "c64497f6cc1044a9f126dc1cfb6c18b80b13f6d5ea7d0ed1cc14a7cb2b334c0e",
    "python/section_12_1_step_7_encoder_diagnostics.py": "2ff614e762bade995eb3e2246f5a338229e185eb4b2cbafe147e729e3dc565fa",
    "python/section_12_1_step_7_model_consumer_diagnostics.py": "f584ace436a1bb92c9a9cd7600413b86458648f827c1ab8d1693ad4bf1113eab",
    "python/section_12_1_step_7_model_driver_diagnostics.py": "390e8d8c2880e1297384266692ebcadffa4e5df3c1bf828ef34ddf5d59ac1d19",
    "python/section_12_1_step_7_privacy.py": "6a8b25ccc3c0498ef2f737b753fcb802f387506a09a72746b0e276349c78ce28",
    "python/section_12_1_step_7_release_consumer.py": "443c8a7243f204ef5f57f9ffe82f382526309e9167e80286b5f5140297a43637",
    "python/section_12_1_step_7_transformation_bridge.py": "e479ee2802b9379c357599c1728a5f453d2ae79148607e24d601dc367bbe4c94",
    "python/section_12_1_step_7_utility.py": "6ad14473cf5b3d907aa815dfdf71ad2863833442ea8828075017d951e9796e3b",
}

AUTHORIZATION_KEYS = {
    "record_schema", "effective_protocol", "authorization_id",
    "authorized_at_utc", "authorized_by", "authorized_source_commit",
    "bound_producer_commit", "bound_producer_tree",
    "bound_gate_b_verification_receipt_sha256",
    "bound_gate_c_verification_receipt_sha256", "authorized_stage",
    "authorized_configurations", "holdout_access_authorized",
    "model_fits_authorized", "dummy_baseline_descriptive_metrics_authorized",
    "primary_utility_metrics_authorized",
    "utility_bootstrap_authorized", "sensitivity_scenarios_authorized",
    "single_use",
}
PRIVATE_KEYS = {
    "record_schema", "effective_protocol", "repository_head",
    "repository_tree", "producer_head", "producer_tree",
    "authorization_record_sha256", "source_context", "selected_C",
    "holdout_row_ids", "holdout_labels", "final_models", "prior_baseline",
    "model_fit_count", "prediction_model_count", "visibility",
}
PUBLIC_FORBIDDEN_KEYS = {
    "X", "y", "labels", "training_X", "holdout_X",
    "training_row_ids", "holdout_row_ids", "prediction_row_ids",
    "prediction_probabilities", "target_indices", "target_rids",
    "training_indices", "validation_indices", "fold_plan",
}

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_AUTH_ID = re.compile(r"AUTH-[0-9]{4}-[0-9]{2}-[0-9]{2}-[A-Z0-9_-]+\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _artifact(data):
    return {"bytes": len(data), "sha256": _sha256(data)}


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _unique_json(data, name, *, canonical=False):
    require(type(data) is bytes and data and not data.startswith(b"\xef\xbb\xbf")
            and b"\x00" not in data, "MODEL_JSON_BYTES", name + " has invalid bytes")

    def pairs(items):
        result = {}
        for key, value in items:
            require(type(key) is str and key not in result,
                    "MODEL_JSON_DUPLICATE", name + " contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("MODEL_JSON_PARSE: invalid " + name) from error
    if canonical:
        require(data == _json_bytes(value), "MODEL_JSON_CANONICAL",
                name + " must use canonical ASCII JSON with one final LF")
    return value


def parse_authorization(data, current_head):
    record = _unique_json(data, "model execution authorization", canonical=True)
    require(type(record) is dict and set(record) == AUTHORIZATION_KEYS,
            "MODEL_AUTH_SCHEMA", "authorization fields differ")
    require(record["record_schema"] == AUTHORIZATION_SCHEMA
            and record["effective_protocol"] == PROTOCOL_VERSION,
            "MODEL_AUTH_SCHEMA", 'authorization schema or execution specification differs')
    require(type(record["authorization_id"]) is str
            and _AUTH_ID.fullmatch(record["authorization_id"]) is not None,
            "MODEL_AUTH_ID", "authorization ID is invalid")
    require(type(record["authorized_at_utc"]) is str
            and _UTC.fullmatch(record["authorized_at_utc"]) is not None,
            "MODEL_AUTH_TIME", "authorization time must be whole-second UTC")
    require(record["authorized_by"] == "researcher"
            and record["authorized_source_commit"] == current_head,
            "MODEL_AUTH_SOURCE", "authorization does not bind current HEAD")
    require(_COMMIT.fullmatch(current_head) is not None
            and record["bound_producer_commit"] == PRODUCER_HEAD
            and record["bound_producer_tree"] == PRODUCER_TREE,
            "MODEL_AUTH_PRODUCER", "authorization producer binding differs")
    require(record["bound_gate_b_verification_receipt_sha256"] == GATE_B_RECEIPT_SHA256
            and record["bound_gate_c_verification_receipt_sha256"] == GATE_C_RECEIPT_SHA256,
            "MODEL_AUTH_EVIDENCE", "authorization evidence binding differs")
    require(record["authorized_stage"]
            == "MODEL_PREDICTIONS_AND_DESCRIPTIVE_PRIOR_BASELINE_ONLY"
            and record["authorized_configurations"] == list(CONFIGURATIONS),
            "MODEL_AUTH_SCOPE", "authorization stage/configuration scope differs")
    require(record["holdout_access_authorized"] is True
            and record["model_fits_authorized"] is True
            and record["dummy_baseline_descriptive_metrics_authorized"] is True
            and record["primary_utility_metrics_authorized"] is False
            and record["utility_bootstrap_authorized"] is False
            and record["sensitivity_scenarios_authorized"] is False
            and record["single_use"] is True,
            "MODEL_AUTH_BOUNDARY", "authorization execution boundary differs")
    return record


def _read_stable(path):
    require(path.is_file(), "MODEL_INPUT_FILE", "missing regular file: " + str(path))
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    require(before.st_size == after.st_size == len(data)
            and before.st_mtime_ns == after.st_mtime_ns,
            "MODEL_INPUT_CHANGED", "file changed while read: " + str(path))
    return data


def _read_exact(path, expected_bytes, expected_hash, name):
    data = _read_stable(path)
    require(len(data) == expected_bytes and _sha256(data) == expected_hash,
            "MODEL_INPUT_IDENTITY", name + " identity differs")
    return data


def _safe_zip(path, expected_bytes, expected_hash):
    data = _read_exact(path, expected_bytes, expected_hash, path.name)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and archive.testzip() is None,
                "MODEL_EVIDENCE_ZIP", "evidence ZIP duplicate or CRC failure")
        result = {}
        for info in archive.infolist():
            member = PurePosixPath(info.filename)
            mode = (info.external_attr >> 16) & 0xFFFF
            require(not member.is_absolute() and ".." not in member.parts
                    and not stat.S_ISLNK(mode) and not (info.flag_bits & 1),
                    "MODEL_EVIDENCE_ZIP", "unsafe evidence ZIP member")
            result[info.filename] = archive.read(info.filename)
    return result


def _inventory(rows, name):
    require(type(rows) is list and rows, "MODEL_INVENTORY", name + " must be a list")
    result = {}
    for row in rows:
        require(type(row) is dict and set(row) == {"path", "bytes", "sha256"},
                "MODEL_INVENTORY", name + " entry fields differ")
        path = row["path"]
        member = PurePosixPath(path) if type(path) is str else None
        require(type(path) is str and path and path not in result
                and member is not None and not member.is_absolute()
                and ".." not in member.parts and "\\" not in path
                and member.as_posix() == path
                and type(row["bytes"]) is int and row["bytes"] >= 0
                and type(row["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
                "MODEL_INVENTORY", name + " entry identity differs")
        result[path] = {"bytes": row["bytes"], "sha256": row["sha256"]}
    return result


def validate_gate_evidence(gate_b_path, gate_c_path):
    gate_b_zip = _safe_zip(gate_b_path, GATE_B_RECEIPT_BYTES, GATE_B_RECEIPT_SHA256)
    gate_c_zip = _safe_zip(gate_c_path, GATE_C_RECEIPT_BYTES, GATE_C_RECEIPT_SHA256)
    require({"GATE_B_INDEPENDENT_VERIFICATION.json", "gate_b_artifact_inventory.json"}
            .issubset(gate_b_zip), "MODEL_GATE_B_EVIDENCE", 'Anonymization validation members are missing')
    require("GATE_C_COMPLETED_RUN_INDEPENDENT_VERIFICATION.json" in gate_c_zip,
            "MODEL_GATE_C_EVIDENCE", 'Record-linkage evaluation verification member is missing')
    gate_b = _unique_json(gate_b_zip["GATE_B_INDEPENDENT_VERIFICATION.json"], 'Anonymization validation receipt')
    inventories = _unique_json(gate_b_zip["gate_b_artifact_inventory.json"], 'Anonymization validation inventory')
    gate_c = _unique_json(gate_c_zip["GATE_C_COMPLETED_RUN_INDEPENDENT_VERIFICATION.json"], 'Record-linkage evaluation receipt')
    require(gate_b.get("result") == "PASS"
            and gate_b.get("source", {}).get("head") == PRODUCER_HEAD
            and gate_b.get("source", {}).get("tree") == PRODUCER_TREE
            and gate_b.get("stage_status", {}).get("gate_b") == "PASS"
            and gate_b.get("stage_status", {}).get("configurations") == "16/16_PASS"
            and gate_b.get("stage_status", {}).get("gate_b_rerun_performed") is False,
            "MODEL_GATE_B_EVIDENCE", 'Anonymization validation verification is not the bound PASS')
    require(gate_b.get("authorization", {}).get("record", {}).get("sha256")
            == PRODUCER_AUTHORIZATION_SHA256
            and gate_b.get("authorization", {}).get("reusable_for_rerun") is False,
            "MODEL_GATE_B_AUTHORIZATION", 'Anonymization validation authorization binding differs')
    require(gate_c.get("record_schema")
            == "gate-c-completed-run-independent-verification-v1.2.4/1.0"
            and gate_c.get("result") == "PASS" and gate_c.get("gate_c") == "PASS"
            and gate_c.get("repository_head") == PRODUCER_HEAD
            and gate_c.get("repository_tree") == PRODUCER_TREE
            and gate_c.get("configurations") == "17/17_PASS"
            and gate_c.get("independent_post_execution_verification_completed") is True
            and gate_c.get("gate_b") == "PASS_PRESERVED_NOT_RERUN"
            and gate_c.get("gate_b_rerun") is False
            and gate_c.get("gate_c_rerun") is False,
            "MODEL_GATE_C_EVIDENCE", 'Record-linkage evaluation verification is not the bound PASS')
    for record, label in ((gate_b["stage_status"], 'Anonymization validation'), (gate_c, 'Record-linkage evaluation')):
        for field in ("holdout_accessed", "bootstrap_executed",
                      "sensitivity_scenarios_executed", "model_fits_executed"):
            require(record[field] is False, "MODEL_EVIDENCE_BOUNDARY",
                    label + " unexpectedly reports " + field)
        require(record["raw_to_model_end_to_end_verified"] is False
                and record["production_pipeline_verified"] is False,
                "MODEL_EVIDENCE_BOUNDARY", label + " overstates downstream completion")
    require(gate_c.get("numeric_risk_pass_fail_criterion") is None
            and gate_c.get("risk_values_descriptive_not_gate_thresholds") is True,
            "MODEL_RISK_SCOPE", 'Record-linkage evaluation risk-threshold scope differs')
    require(type(inventories) is dict and set(inventories) == {"public", "private"},
            "MODEL_GATE_B_INVENTORY", 'Anonymization validation inventory groups differ')
    public = _inventory(inventories["public"], 'Anonymization validation public inventory')
    private = _inventory(inventories["private"], 'Anonymization validation private inventory')
    require(len(public) == 65 and len(private) == 1,
            "MODEL_GATE_B_INVENTORY", 'Anonymization validation inventory counts differ')
    return {"public": public, "private": private}


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


def _git(repository, *arguments, allow_status=0):
    executable = shutil.which("git")
    require(executable is not None, "MODEL_GIT", "Git executable is unavailable")
    result = _run([executable, "-c", "core.quotepath=false", "-C", str(repository), *arguments])
    require(result.returncode == allow_status, "MODEL_GIT",
            "Git command failed: " + " ".join(arguments))
    return result.stdout


def _runtime_guard(repository):
    require(sys.implementation.name == "cpython" and sys.platform == "win32"
            and platform.system() == "Windows" and sys.version_info[:3] == EXPECTED_PYTHON
            and struct.calcsize("P") * 8 == EXPECTED_BITS,
            "MODEL_RUNTIME", "64-bit CPython 3.12.10 on Windows is required")
    require(sys.flags.isolated and sys.dont_write_bytecode,
            "MODEL_RUNTIME", "invoke the runner with -I -B")
    expected = repository / ".venv" / "Scripts" / "python.exe"
    require(Path(sys.executable).resolve() == expected.resolve(),
            "MODEL_RUNTIME", "interpreter is not the repository .venv Python")


def _repository_guard(repository, authorization_data):
    require(repository.is_absolute() and repository.is_dir(),
            "MODEL_REPOSITORY", "repository must be an existing absolute directory")
    root = Path(_git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve()
    require(root == repository.resolve(), "MODEL_REPOSITORY", "path is not the Git root")
    head = _git(repository, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    tree = _git(repository, "rev-parse", "--verify", "HEAD^{tree}").decode("ascii").strip()
    authorization = parse_authorization(authorization_data, head)
    ancestry = _run([shutil.which("git"), "-C", str(repository), "merge-base",
                     "--is-ancestor", PRODUCER_HEAD, head])
    require(ancestry.returncode == 0, "MODEL_REPOSITORY",
            "current HEAD does not descend from the verified producer commit")
    require(_git(repository, "rev-parse", PRODUCER_HEAD + "^{tree}").decode("ascii").strip()
            == PRODUCER_TREE, "MODEL_REPOSITORY", "producer tree identity differs")
    tracked_status = _git(repository, "status", "--porcelain=v1", "-z", "--untracked-files=no")
    require(tracked_status == b"", "MODEL_REPOSITORY", "tracked repository state is not clean")
    tracked = [item for item in _git(repository, "ls-files", "-z").split(b"\0") if item]
    require(len(tracked) == len(set(tracked)) == 142,
            "MODEL_REPOSITORY", "tracked path set is incomplete or contains duplicates")
    for relative, digest in DEPENDENCY_HASHES.items():
        data = _read_stable(repository / relative)
        require(_sha256(data) == digest
                and _git(repository, "show", "HEAD:" + relative) == data,
                "MODEL_DEPENDENCY", "dependency identity differs: " + relative)
    own_relative = "python/section_12_3_raw_to_model_model_runner_v1_2_4.py"
    own_data = _read_stable(repository / own_relative)
    require(_git(repository, "show", "HEAD:" + own_relative) == own_data,
            "MODEL_RUNNER_IDENTITY", "runner working bytes differ from HEAD")
    return head, tree, authorization


def _parse_table(data, delimiter, expected_header, name):
    require(type(data) is bytes and data and b"\x00" not in data,
            "MODEL_TABLE_BYTES", name + " has invalid bytes")
    try:
        text = data.decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError("MODEL_TABLE_PARSE: invalid " + name) from error
    require(rows and tuple(rows[0]) == tuple(expected_header),
            "MODEL_TABLE_SCHEMA", name + " header differs")
    body = rows[1:]
    require(body and all(len(row) == len(expected_header) for row in body),
            "MODEL_TABLE_RECTANGLE", name + " is empty or nonrectangular")
    require(all(cell and cell == cell.strip()
                and not any(mark in cell for mark in ("\x00", "\r", "\n", "\t"))
                for row in body for cell in row),
            "MODEL_TABLE_CELL", name + " contains an invalid cell")
    return [dict(zip(expected_header, row)) for row in body]


def _canonical_projected(records):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(PHYSICAL_SCHEMA)
    writer.writerows([[record["row"][name] for name in PHYSICAL_SCHEMA] for record in records])
    return stream.getvalue().encode("utf-8")


def _parse_uci_source(data, *, member, test, operational=True):
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("MODEL_UCI_ASCII: non-ASCII " + member) from error
    physical = text.splitlines()
    require(physical and physical[-1] == "",
            "MODEL_UCI_TERMINATOR", member + " trailing physical blank line differs")
    require(all(line for line in physical[:-1]),
            "MODEL_UCI_BLANK", member + " contains an internal blank line")
    if test:
        require(physical[0] == "|1x3 Cross validator",
                "MODEL_UCI_METADATA", "adult.test metadata line differs")
        lines = physical[1:-1]
        first_line = 2
    else:
        lines = physical[:-1]
        first_line = 1
    raw_count = len(lines)
    records = []
    missing = Counter()
    raw_targets = Counter()
    for physical_line, line in enumerate(lines, first_line):
        try:
            row = next(csv.reader([line], delimiter=",", skipinitialspace=True, strict=True))
        except csv.Error as error:
            raise ValueError("MODEL_UCI_CSV: invalid " + member) from error
        require(len(row) == 15, "MODEL_UCI_FIELDS", member + " field count differs")
        row = [cell.strip() for cell in row]
        require(all(row), "MODEL_UCI_CELL", member + " contains an empty field")
        raw_targets[row[14]] += 1
        missing_fields = [UCI_COLUMNS[index] for index, value in enumerate(row) if value == "?"]
        missing.update(missing_fields)
        if missing_fields:
            continue
        if test:
            require(row[14] in ("<=50K.", ">50K."),
                    "MODEL_UCI_TARGET", "adult.test target differs")
            row[14] = row[14][:-1]
        else:
            require(row[14] in ("<=50K", ">50K"),
                    "MODEL_UCI_TARGET", "adult.data target differs")
        projected = [row[index] for index in PROJECTION]
        rid = member + ":" + str(physical_line)
        records.append({"row_id": rid, "row": dict(zip(PHYSICAL_SCHEMA, projected))})
    canonical = _canonical_projected(records)
    metrics = {
        "raw_records": raw_count,
        "complete_records": len(records),
        "rejected_incomplete_records": raw_count - len(records),
        "missing_occurrences_by_field": dict(sorted(missing.items())),
        "target_counts_complete": dict(sorted(Counter(
            record["row"]["salary-class"] for record in records).items())),
    }
    if operational:
        expected_raw = 16281 if test else 32561
        expected_complete = 15060 if test else 30162
        expected_identity = HOLDOUT_CANONICAL_IDENTITY if test else TRAINING_CANONICAL_IDENTITY
        expected_targets = ({"<=50K": 11360, ">50K": 3700} if test
                            else {"<=50K": 22654, ">50K": 7508})
        expected_raw_target_set = ({"<=50K.", ">50K."} if test
                                   else {"<=50K", ">50K"})
        expected_missing = ({"native-country": 274, "occupation": 966,
                             "workclass": 963} if test
                            else {"native-country": 583, "occupation": 1843,
                                  "workclass": 1836})
        require(raw_count == expected_raw and len(records) == expected_complete,
                "MODEL_UCI_COUNTS", member + " population count differs")
        require(_artifact(canonical) == {"bytes": expected_identity[0],
                                        "sha256": expected_identity[1]},
                "MODEL_UCI_CANONICAL", member + " canonical projection differs")
        require(metrics["target_counts_complete"] == expected_targets,
                "MODEL_UCI_TARGET_COUNTS", member + " target counts differ")
        require(set(raw_targets) == expected_raw_target_set
                and metrics["missing_occurrences_by_field"] == expected_missing,
                "MODEL_UCI_CLEANING", member + " raw labels or missingness differ")
    return {"records": records, "canonical": canonical, "metrics": metrics,
            "raw_target_counts": dict(sorted(raw_targets.items()))}


def _strict_lines(data, name, *, integer=False):
    require(data and not data.startswith(b"\xef\xbb\xbf") and data.endswith(b"\n")
            and b"\r" not in data and b"\x00" not in data,
            "MODEL_LINE_BYTES", name + " must be BOM-free strict LF text")
    try:
        lines = data[:-1].decode("ascii").split("\n")
        return [int(value) for value in lines] if integer else lines
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("MODEL_LINE_PARSE: invalid " + name) from error


def _parse_hierarchy(data, attribute, width):
    require(data and b"\x00" not in data, "MODEL_HIERARCHY_BYTES",
            attribute + " hierarchy has invalid bytes")
    try:
        text = data.decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=";", strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise ValueError("MODEL_HIERARCHY_PARSE: invalid " + attribute) from error
    require(rows and all(len(row) == width for row in rows),
            "MODEL_HIERARCHY_RECTANGLE", attribute + " hierarchy width differs")
    require(all(cell and cell == cell.strip() for row in rows for cell in row),
            "MODEL_HIERARCHY_CELL", attribute + " hierarchy contains invalid cells")
    return {"levels": list(range(width)), "rows": rows}


def _validate_inventory_artifact(run_root, public_inventory, relative):
    require(relative in public_inventory, "MODEL_GATE_B_ARTIFACT",
            'Anonymization validation inventory omits ' + relative)
    expected = public_inventory[relative]
    data = _read_exact(run_root / relative, expected["bytes"], expected["sha256"], relative)
    return data


def _load_gate_b_configurations(run_root, public_inventory):
    transformations = {}
    transcripts = {}
    captures = {}
    artifacts = {}
    for config_id in OUTPUT_CONFIGURATIONS:
        prefix = config_id + "/" + config_id
        full_data = _validate_inventory_artifact(run_root, public_inventory, prefix + ".full.tsv")
        report_data = _validate_inventory_artifact(run_root, public_inventory, prefix + ".java-report.json")
        gate_data = _validate_inventory_artifact(run_root, public_inventory, prefix + ".gate-b.json")
        full_rows = _parse_table(full_data, "\t", PHYSICAL_SCHEMA, config_id + " full output")
        report = _unique_json(report_data, config_id + " Java report")
        gate = _unique_json(gate_data, config_id + ' anonymization validation receipt')
        require(len(full_rows) == 30162 and report.get("record_schema") == "arx-main-cfg-v1.2.4/1.0"
                and report.get("result") == "PASS" and report.get("config_id") == config_id
                and report.get("input_rows") == 30162 and report.get("main_runs_executed") is True
                and report.get("anonymization_invoked") is True
                and report.get("no_sort_or_permutation") is True
                and report.get("target_index_binding") is True
                and report.get("retained_transformation_equality") is True,
                "MODEL_JAVA_REPORT", config_id + " Java execution binding differs")
        authorization = report.get("authorization")
        require(type(authorization) is dict
                and authorization.get("authorized_source_commit") == PRODUCER_HEAD
                and authorization.get("record_sha256") == PRODUCER_AUTHORIZATION_SHA256
                and authorization.get("main_runs_authorized") is True,
                "MODEL_JAVA_AUTHORIZATION", config_id + " Java authorization differs")
        mask = report.get("outlier_mask")
        vector = report.get("transformation_by_name")
        require(type(mask) is dict and mask.get("source") == "DataHandle.isOutlier"
                and type(mask.get("values")) is list and len(mask["values"]) == 30162
                and all(type(value) is bool for value in mask["values"])
                and mask.get("count") == sum(mask["values"]),
                "MODEL_OUTLIER_MASK", config_id + " outlier mask differs")
        require(type(vector) is dict and set(vector) == set(QIS)
                and all(type(value) is int and value >= 0 for value in vector.values()),
                "MODEL_TRANSFORMATION", config_id + " named transformation differs")
        require(report.get("full_output") == {
                    "filename": config_id + ".full.tsv", "bytes": len(full_data),
                    "sha256": _sha256(full_data)}
                and gate.get("record_schema") == "section-12-1-gate-b-v1.2.4/1.0"
                and gate.get("result") == "PASS" and gate.get("config_id") == config_id
                and gate.get("n_input") == 30162
                and gate.get("n_retained") == 30162 - sum(mask["values"])
                and gate.get("outlier_count") == sum(mask["values"])
                and gate.get("outlier_source") == "captured_DataHandle.isOutlier"
                and gate.get("full_output_sha256") == _sha256(full_data)
                and gate.get("java_report_sha256") == _sha256(report_data)
                and gate.get("u_qi") == 0.0,
                "MODEL_GATE_B_RECEIPT", config_id + ' anonymization validation receipt differs')
        transformations[config_id] = dict(vector)
        transcript = []
        capture = []
        for index, (row, is_outlier) in enumerate(zip(full_rows, mask["values"])):
            own_row = dict(row)
            transcript.append({"original_index": index, "row": own_row,
                               "is_outlier": is_outlier})
            capture.append({"original_index": index, "row_id": None,
                            "transformed_row_sha256": json_digest(own_row),
                            "is_outlier": is_outlier})
        transcripts[config_id] = transcript
        captures[config_id] = capture
        artifacts[config_id] = {
            "full_output": _artifact(full_data), "java_report": _artifact(report_data),
            "gate_b_receipt": _artifact(gate_data),
            "outlier_count": sum(mask["values"]),
            "transformation_by_name": dict(vector),
        }
    return transformations, transcripts, captures, artifacts


def _bind_capture_rids(captures, canonical_rids, *, operational=True):
    require(type(operational) is bool, "MODEL_CAPTURE_RIDS", "operational must be Boolean")
    if operational:
        require(len(canonical_rids) == 30162, "MODEL_CAPTURE_RIDS",
                "canonical RID count differs")
    for config_id in OUTPUT_CONFIGURATIONS:
        require(len(captures[config_id]) == len(canonical_rids),
                "MODEL_CAPTURE_RIDS", config_id + " capture count differs")
        for index, item in enumerate(captures[config_id]):
            require(item["original_index"] == index and item["row_id"] is None,
                    "MODEL_CAPTURE_RIDS", config_id + " capture index differs")
            item["row_id"] = canonical_rids[index]


def load_operational_inputs(repository, gate_b_inventory, progress):
    training_source_data = _read_exact(repository / UCI_TRAINING, *UCI_TRAINING_IDENTITY,
                                       "UCI adult.data")
    training = _parse_uci_source(training_source_data, member="adult.data", test=False)
    arx_data = _read_exact(repository / ARX_TRAINING, *ARX_TRAINING_IDENTITY,
                           "ARX Adult training table")
    arx_rows = _parse_table(arx_data, ";", PHYSICAL_SCHEMA, "ARX Adult training table")
    require([record["row"] for record in training["records"]] == arx_rows,
            "MODEL_TRAINING_CROSS_SOURCE", "ARX and UCI complete training rows differ")
    rid_data = _read_stable(repository / RID_ORDER)
    require(_sha256(rid_data) == RID_ORDER_SHA256,
            "MODEL_RID_IDENTITY", "canonical RID order hash differs")
    canonical_rids = _strict_lines(rid_data, "canonical RID order")
    require(canonical_rids == [record["row_id"] for record in training["records"]],
            "MODEL_RID_ASSOCIATION", "canonical RID file differs from physical complete-case lines")
    master_data = _read_stable(repository / MASTER_PERMUTATION)
    require(_sha256(master_data) == MASTER_PERMUTATION_SHA256,
            "MODEL_MASTER_IDENTITY", "master permutation hash differs")
    master = _strict_lines(master_data, "master permutation", integer=True)
    require(sorted(master) == list(range(30162)),
            "MODEL_MASTER_BIJECTION", "master permutation is not a bijection")

    progress["holdout_accessed"] = True
    holdout_source_data = _read_exact(repository / UCI_HOLDOUT, *UCI_HOLDOUT_IDENTITY,
                                      "UCI adult.test")
    holdout = _parse_uci_source(holdout_source_data, member="adult.test", test=True)

    hierarchies = OrderedDict()
    hierarchy_artifacts = OrderedDict()
    for attribute, (relative, byte_count, digest, width) in HIERARCHIES.items():
        data = _read_exact(repository / relative, byte_count, digest,
                           attribute + " hierarchy")
        hierarchies[attribute] = _parse_hierarchy(data, attribute, width)
        hierarchy_artifacts[attribute] = {
            "relative_path": relative, "bytes": byte_count, "sha256": digest,
        }
    run_root = repository / RUN_ROOT
    require(run_root.is_dir(), "MODEL_RUN_ROOT", 'Anonymization validation main run root is missing')
    summary_data = _validate_inventory_artifact(run_root, gate_b_inventory,
                                                "gate_b_matrix_summary.json")
    target_data = _validate_inventory_artifact(run_root, gate_b_inventory,
                                               "pre_output_target_sample_receipt.json")
    summary = _unique_json(summary_data, 'Anonymization validation matrix summary')
    target = _unique_json(target_data, "target sample receipt")
    require(summary.get("record_schema") == "gate-b-matrix-v1.2.4/1.0"
            and summary.get("result") == "PASS" and summary.get("gate_b") == "PASS"
            and summary.get("repository_head") == PRODUCER_HEAD
            and summary.get("authorization_record_sha256") == PRODUCER_AUTHORIZATION_SHA256
            and summary.get("configuration_count") == 16
            and summary.get("configurations") == list(OUTPUT_CONFIGURATIONS),
            "MODEL_GATE_B_SUMMARY", 'Anonymization validation summary differs')
    require(target.get("record_schema") == "pre-output-target-sample-receipt-v1.2.4/1.0"
            and target.get("result") == "PASS" and target.get("repository_head") == PRODUCER_HEAD
            and target.get("authorization_record_sha256") == PRODUCER_AUTHORIZATION_SHA256,
            "MODEL_TARGET_RECEIPT", "target-sample receipt differs")
    vectors, transcripts, captures, cfg_artifacts = _load_gate_b_configurations(
        run_root, gate_b_inventory)
    _bind_capture_rids(captures, canonical_rids, operational=True)
    context = {
        "uci_training": _artifact(training_source_data),
        "uci_training_canonical": _artifact(training["canonical"]),
        "arx_training": _artifact(arx_data),
        "uci_holdout": _artifact(holdout_source_data),
        "uci_holdout_canonical": _artifact(holdout["canonical"]),
        "rid_order": _artifact(rid_data), "master_permutation": _artifact(master_data),
        "hierarchies": hierarchy_artifacts,
        "gate_b_matrix_summary": _artifact(summary_data),
        "target_sample_receipt": _artifact(target_data),
        "configurations": cfg_artifacts,
        "training_metrics": training["metrics"], "holdout_metrics": holdout["metrics"],
    }
    return {
        "raw_training_records": training["records"],
        "raw_holdout_records": holdout["records"],
        "hierarchy_tables": hierarchies,
        "transformations_by_cfg": vectors,
        "java_transcripts_by_cfg": transcripts,
        "captured_associations_by_cfg": captures,
        "master_permutation": master,
        "source_context": context,
    }


def dispatch_model_components(inputs, *, expected_executable, mode="operational",
                              progress=None):
    bridge = build_guarded_transformation_inputs(
        raw_training_records=inputs["raw_training_records"],
        raw_holdout_records=inputs["raw_holdout_records"],
        hierarchy_tables=inputs["hierarchy_tables"],
        transformations_by_cfg=inputs["transformations_by_cfg"],
        java_transcripts_by_cfg=inputs["java_transcripts_by_cfg"],
        captured_associations_by_cfg=inputs["captured_associations_by_cfg"],
        mode=mode,
    )
    model_inputs = bridge["model_driver_inputs"]
    if progress is not None:
        progress["stage"] = "MODEL_WORKFLOW_DISPATCH"
        progress["model_fits_attempted"] = True
        progress["model_fits_executed"] = None
    workflow = run_guarded_utility_models(
        **model_inputs, master_permutation=inputs["master_permutation"],
        expected_executable=expected_executable, mode=mode)
    if progress is not None:
        progress["model_fits_executed"] = True
        progress["stage"] = "PRIOR_BASELINE_DISPATCH"
    raw_training = model_inputs["raw_training"]
    raw_holdout = model_inputs["raw_holdout"]
    sources = model_inputs["independent_sources"]
    baseline = fit_prior_baseline_guarded(
        fit_id="final/prior-baseline", feature_names=model_inputs["feature_names"],
        training_X=raw_training["X"], training_row_ids=raw_training["x_row_ids"],
        training_y=raw_training["y"], training_y_row_ids=raw_training["y_row_ids"],
        prediction_X=raw_holdout["X"], prediction_row_ids=raw_holdout["x_row_ids"],
        prediction_y=raw_holdout["y"], prediction_y_row_ids=raw_holdout["y_row_ids"],
        expected_training_row_ids=model_inputs["canonical_rids"],
        expected_prediction_row_ids=model_inputs["independent_holdout_row_ids"],
        source_training_rows=sources["training"]["CFG00"]["rows"],
        source_training_labels=sources["training"]["CFG00"]["labels"],
        source_prediction_rows=sources["holdout"]["CFG00"]["rows"],
        source_prediction_labels=sources["holdout"]["CFG00"]["labels"],
        expected_executable=expected_executable, training_role="raw_training", mode=mode)
    return {"bridge": bridge, "workflow": workflow, "baseline": baseline}


def _validate_native_fit_receipt(receipt, name):
    require(type(receipt) is dict and receipt.get("result") == "PASS"
            and receipt.get("execution_kind") == "NATIVE_SKLEARN"
            and receipt.get("actual_native_fit_count") == 1
            and receipt.get("synthetic_double_fit_count") == 0,
            "MODEL_NATIVE_FIT_RECEIPT", name + " is not one successful native fit")
    runtime = receipt.get("runtime")
    require(type(runtime) is dict
            and runtime.get("backend_kind") == "NATIVE_SKLEARN"
            and runtime.get("python_version") == ".".join(map(str, EXPECTED_PYTHON))
            and runtime.get("python_platform") == "win32"
            and runtime.get("python_implementation") == "cpython"
            and runtime.get("isolated") is True
            and runtime.get("dont_write_bytecode") is True
            and runtime.get("numpy_version") == EXPECTED_NUMPY
            and runtime.get("sklearn_version") == EXPECTED_SKLEARN
            and ("pointer_bits" not in runtime or runtime["pointer_bits"] == EXPECTED_BITS),
            "MODEL_NATIVE_RUNTIME", name + " locked runtime receipt differs")
    require(type(receipt.get("fit_id")) is str and receipt["fit_id"],
            "MODEL_NATIVE_FIT_ID", name + " fit identity is missing")
    return receipt["fit_id"]


def build_private_record(*, components, source_context, head, tree, authorization_hash):
    workflow = components["workflow"]
    baseline = components["baseline"]
    model_inputs = components["bridge"]["model_driver_inputs"]
    final = workflow["final_models"]
    cv = workflow["cv"]
    require(components["bridge"]["receipt"].get("scope")
            == "SUPPLIED_OPERATIONAL_SOURCE_ARTIFACTS",
            "MODEL_EXECUTION_CLASS", "transformation bridge is not operational")
    require(workflow["receipt"].get("execution_classification") == "actual_native_fits"
            and workflow["receipt"].get("actual_model_fit_count") == 48
            and workflow["receipt"].get("synthetic_test_double_fit_count") == 0
            and workflow["receipt"].get("cv_fit_count") == 15
            and workflow["receipt"].get("final_fit_count") == 33,
            "MODEL_EXECUTION_CLASS", "model workflow is not 48 actual native fits")
    require(baseline["receipt"].get("execution_kind") == "NATIVE_SKLEARN"
            and baseline["receipt"].get("actual_native_fit_count") == 1
            and baseline["receipt"].get("synthetic_double_fit_count") == 0,
            "MODEL_EXECUTION_CLASS", "prior baseline is not one actual native fit")
    require(workflow["selected_C"] in (0.1, 1.0, 10.0)
            and cv.get("selected_C") == workflow["selected_C"]
            and cv.get("fit_count") == 15
            and cv.get("selection_scope") == "raw_training_only"
            and cv.get("holdout_used_for_selection") is False
            and cv.get("selection_rule")
            == "mean_five_fold_AUROC_then_smaller_C_on_exact_tie",
            "MODEL_C_SELECTION", "raw-training-only C selection receipt differs")
    scores = cv.get("candidate_scores")
    require(type(scores) is list and [item.get("C") for item in scores] == [0.1, 1.0, 10.0]
            and all(type(item.get("fold_aurocs")) is list
                    and len(item["fold_aurocs"]) == 5
                    and all(type(value) is float and math.isfinite(value)
                            and 0.0 <= value <= 1.0 for value in item["fold_aurocs"])
                    and type(item.get("mean_auroc")) is float
                    and math.isfinite(item["mean_auroc"])
                    and item["mean_auroc"] == sum(item["fold_aurocs"]) / 5.0
                    for item in scores),
            "MODEL_C_SCORES", "raw-CV candidate scores differ")
    expected_keys = {"CFG00"} | {
        config_id + suffix for config_id in OUTPUT_CONFIGURATIONS
        for suffix in ("/release", "/counterfactual")
    }
    require(set(final) == expected_keys, "MODEL_PRIVATE_FINALS",
            "final model result set differs")
    cv_receipts = cv.get("fit_receipts")
    require(type(cv_receipts) is list and len(cv_receipts) == 15
            and all(type(item) is dict for item in cv_receipts),
            "MODEL_CV_RECEIPTS", "raw-CV fit receipts differ")
    fit_ids = [
        _validate_native_fit_receipt(item.get("fit_receipt"), "raw CV fit")
        for item in cv_receipts
    ]
    fit_ids.extend(
        _validate_native_fit_receipt(final[key].get("fit_receipt"), "final fit " + key)
        for key in sorted(final)
    )
    fit_ids.append(_validate_native_fit_receipt(baseline.get("receipt"), "prior baseline"))
    require(len(fit_ids) == len(set(fit_ids)) == 49,
            "MODEL_FIT_IDENTITIES", "fit identities are incomplete or duplicated")
    holdout_ids = model_inputs["independent_holdout_row_ids"]
    holdout_labels = model_inputs["raw_holdout"]["y"]
    stored_models = OrderedDict()
    for key in sorted(final):
        record = final[key]
        require(record["prediction_row_ids"] == holdout_ids
                and len(record["prediction_probabilities"]) == len(holdout_ids),
                "MODEL_PRIVATE_PREDICTION", key + " prediction association differs")
        computed_prediction_hash = _sha256(prediction_bytes(
            holdout_ids, record["prediction_probabilities"]))
        require(computed_prediction_hash == record["fit_receipt"]["prediction_sha256"],
                "MODEL_PRIVATE_PREDICTION_HASH", key + " prediction hash differs")
        stored_models[key] = {
            "cfg_id": record["cfg_id"], "training_role": record["training_role"],
            "C": record["C"], "prediction_row_ids": list(record["prediction_row_ids"]),
            "prediction_probabilities": record["prediction_probabilities"],
            "prediction_sha256": record["fit_receipt"]["prediction_sha256"],
        }
    base_private = baseline["private_baseline_receipt"]
    require(base_private["holdout_row_ids"] == holdout_ids
            and len(base_private["prediction_probabilities"]) == len(holdout_ids),
            "MODEL_PRIVATE_BASELINE", "baseline prediction association differs")
    require(_sha256(prediction_bytes(
                holdout_ids, base_private["prediction_probabilities"]))
            == baseline["receipt"]["prediction_sha256"],
            "MODEL_PRIVATE_BASELINE_HASH", "baseline prediction hash differs")
    result = {
        "record_schema": PRIVATE_SCHEMA, "effective_protocol": PROTOCOL_VERSION,
        "repository_head": head, "repository_tree": tree,
        "producer_head": PRODUCER_HEAD, "producer_tree": PRODUCER_TREE,
        "authorization_record_sha256": authorization_hash,
        "source_context": source_context, "selected_C": workflow["selected_C"],
        "holdout_row_ids": list(holdout_ids), "holdout_labels": list(holdout_labels),
        "final_models": stored_models,
        "prior_baseline": {
            "prediction_row_ids": list(base_private["holdout_row_ids"]),
            "prediction_probabilities": base_private["prediction_probabilities"],
            "prediction_sha256": baseline["receipt"]["prediction_sha256"],
            "class_prior": base_private["class_prior"],
        },
        "model_fit_count": 49, "prediction_model_count": 34,
        "visibility": "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
    }
    require(set(result) == PRIVATE_KEYS, "MODEL_PRIVATE_SCHEMA", "private record fields differ")
    return result


def _assert_public(value, path="$"):
    if type(value) is dict:
        for key, item in value.items():
            require(key not in PUBLIC_FORBIDDEN_KEYS, "MODEL_PUBLIC_PRIVATE_KEY",
                    "private key in public receipt at " + path + "." + key)
            if key == "rows":
                require(type(item) is int and item >= 0,
                        "MODEL_PUBLIC_PRIVATE_ROWS",
                        "rows must be an aggregate nonnegative count at "
                        + path + "." + key)
            _assert_public(item, path + "." + key)
    elif type(value) is list:
        for index, item in enumerate(value):
            _assert_public(item, path + "[" + str(index) + "]")
    elif type(value) is str:
        require(re.search(r"adult\.(?:data|test):[0-9]", value) is None,
                "MODEL_PUBLIC_PRIVATE_RID", "private RID in public receipt")


def build_public_receipt(*, components, private_identity, head, tree,
                         authorization, authorization_hash, source_context):
    workflow = components["workflow"]
    bridge = components["bridge"]
    baseline = components["baseline"]
    cv = workflow["cv"]
    final_receipts = {
        key: workflow["final_models"][key]["fit_receipt"]
        for key in sorted(workflow["final_models"])
    }
    result = {
        "record_schema": PUBLIC_SCHEMA, "tool_revision": TOOL_REVISION,
        "effective_protocol": PROTOCOL_VERSION, "result": "PASS",
        "classification": "MODEL_PREDICTIONS_PASS_PENDING_INDEPENDENT_VERIFICATION",
        "repository_head": head, "repository_tree": tree,
        "producer_head": PRODUCER_HEAD, "producer_tree": PRODUCER_TREE,
        "authorization": {
            "authorization_id": authorization["authorization_id"],
            "record_sha256": authorization_hash,
            "authorized_stage": authorization["authorized_stage"],
            "dummy_baseline_descriptive_metrics_authorized": True,
            "single_use": True,
        },
        "bound_evidence": {
            "gate_b_verification_receipt": {"bytes": GATE_B_RECEIPT_BYTES,
                                             "sha256": GATE_B_RECEIPT_SHA256},
            "gate_c_verification_receipt": {"bytes": GATE_C_RECEIPT_BYTES,
                                             "sha256": GATE_C_RECEIPT_SHA256},
        },
        "source_context_sha256": json_digest(source_context),
        "transformation_bridge_receipt": bridge["receipt"],
        "model_workflow_receipt": workflow["receipt"],
        "raw_cv": {
            "selected_C": workflow["selected_C"],
            "candidate_scores": cv["candidate_scores"],
            "fold_plan_sha256": cv["fold_plan_sha256"],
            "fit_count": cv["fit_count"], "splitter": cv["splitter"],
            "splitter_parameters": cv["splitter_parameters"],
            "selection_scope": cv["selection_scope"],
            "holdout_used_for_selection": cv["holdout_used_for_selection"],
            "selection_rule": cv["selection_rule"],
            "fit_receipts": cv["fit_receipts"],
        },
        "final_fit_receipts": final_receipts,
        "prior_baseline_receipt": baseline["receipt"],
        "private_model_artifact": private_identity,
        "configuration_count": 17, "final_model_fit_count": 33,
        "raw_cv_fit_count": 15, "prior_baseline_fit_count": 1,
        "total_actual_model_fit_count": 49,
        "prediction_model_count": 34,
        "holdout_accessed": True, "model_fits_executed": True,
        "predictions_generated": True,
        "primary_utility_metrics_executed": False,
        "dummy_baseline_descriptive_metrics_computed": True,
        "utility_bootstrap_executed": False,
        "bootstrap_indices_generated": False,
        "sensitivity_scenarios_executed": False,
        "gate_b_rerun": False, "gate_c_rerun": False,
        "arx_anonymization_invoked": False,
        "numeric_risk_pass_fail_criterion": None,
        "raw_to_model_model_stage_verified": False,
        "raw_to_model_end_to_end_verified": False,
        "production_pipeline_verified": False,
        "next_required_control": (
            "INDEPENDENTLY_VERIFY_EXACT_PRIVATE_AND_PUBLIC_MODEL_ARTIFACTS_BEFORE_"
            "ANY_PRIMARY_UTILITY_METRIC_BOOTSTRAP_OR_SENSITIVITY_EXECUTION"
        ),
        "remaining_static_obligation": "RTM-IMPL-05",
        "private_payloads_in_public_receipt": False,
    }
    _assert_public(result)
    return result


def _write_new(path, data):
    require(not path.exists(), "MODEL_OUTPUT_EXISTS", "refusing to overwrite " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    require(not temporary.exists(), "MODEL_OUTPUT_TEMP", "temporary output already exists")
    temporary.write_bytes(data)
    temporary.replace(path)


def _failure_code(error):
    code = getattr(error, "code", None)
    if type(code) is str and 0 < len(code) <= 128:
        return code
    return type(error).__name__


def _bounded_component_failures(error):
    result = {}
    attributes = (
        "step7_transformation_partial_receipt",
        "step7_model_workflow_partial_receipt",
        "step7_model_fit_partial_receipt",
        "step7_dummy_baseline_partial_receipt",
    )
    for attribute in attributes:
        value = getattr(error, attribute, None)
        if value is None:
            continue
        try:
            bounded = _unique_json(_json_bytes(value), attribute, canonical=True)
            _assert_public(bounded)
            result[attribute] = bounded
        except Exception:
            result[attribute] = {"capture_status": "REJECTED_NON_BOUNDED"}
    return result


def run_operational(repository, authorization_path, gate_b_receipt_path, gate_c_receipt_path):
    repository = repository.resolve()
    _runtime_guard(repository)
    authorization_data = _read_stable(authorization_path.resolve())
    head, tree, authorization = _repository_guard(repository, authorization_data)
    authorization_hash = _sha256(authorization_data)
    inventories = validate_gate_evidence(gate_b_receipt_path.resolve(), gate_c_receipt_path.resolve())

    private_root = repository / PRIVATE_ROOT / "raw_to_model_model"
    private_pending = repository / PRIVATE_ROOT / "raw_to_model_model.pending"
    public_root = repository / RUN_ROOT / "raw_to_model_model"
    public_pending = repository / RUN_ROOT / "raw_to_model_model.pending"
    failure_path = repository / RUN_ROOT / (
        "raw_to_model_model_failure_" + authorization["authorization_id"] + ".json")
    require(not private_root.exists() and not private_pending.exists()
            and not public_root.exists() and not public_pending.exists()
            and not failure_path.exists(),
            "MODEL_SINGLE_USE", "model stage or prior attempt already exists")

    progress = {
        "record_schema": FAILURE_SCHEMA, "result": "IN_PROGRESS",
        "repository_head": head, "repository_tree": tree,
        "producer_head": PRODUCER_HEAD,
        "authorization_id": authorization["authorization_id"],
        "authorization_record_sha256": authorization_hash,
        "stage": "AUTHORIZED_BEFORE_HOLDOUT_ACCESS",
        "holdout_accessed": False, "model_fits_attempted": False,
        "model_fits_executed": False,
        "predictions_generated": False, "primary_utility_metrics_executed": False,
        "utility_bootstrap_executed": False, "bootstrap_indices_generated": False,
        "sensitivity_scenarios_executed": False,
        "gate_b_rerun": False, "gate_c_rerun": False,
        "arx_anonymization_invoked": False,
    }
    private_pending.mkdir(parents=True, exist_ok=False)
    session = {
        "record_schema": SESSION_SCHEMA, "effective_protocol": PROTOCOL_VERSION,
        "repository_head": head, "repository_tree": tree,
        "producer_head": PRODUCER_HEAD, "producer_tree": PRODUCER_TREE,
        "authorization_record": _artifact(authorization_data),
        "gate_b_verification_receipt": {"bytes": GATE_B_RECEIPT_BYTES,
                                         "sha256": GATE_B_RECEIPT_SHA256},
        "gate_c_verification_receipt": {"bytes": GATE_C_RECEIPT_BYTES,
                                         "sha256": GATE_C_RECEIPT_SHA256},
        "authorized_stage": "MODEL_PREDICTIONS_AND_DESCRIPTIVE_PRIOR_BASELINE_ONLY",
        "dummy_baseline_descriptive_metrics_authorized": True,
        "primary_utility_metrics_authorized": False,
        "utility_bootstrap_authorized": False,
        "sensitivity_scenarios_authorized": False,
    }
    _write_new(private_pending / "SESSION.json", _json_bytes(session))
    started_at = _utc_now()
    started_clock = time.perf_counter()
    try:
        progress["stage"] = "LOAD_AND_BIND_OPERATIONAL_INPUTS"
        inputs = load_operational_inputs(repository, inventories["public"], progress)
        progress["stage"] = "TRANSFORMATION_BRIDGE_AND_MODEL_DISPATCH"
        components = dispatch_model_components(
            inputs, expected_executable=str(Path(sys.executable).resolve()), mode="operational",
            progress=progress)
        progress["model_fits_executed"] = True
        progress["predictions_generated"] = True
        progress["stage"] = "WRITE_PRIVATE_AND_BOUNDED_PUBLIC_ARTIFACTS"
        private = build_private_record(
            components=components, source_context=inputs["source_context"],
            head=head, tree=tree, authorization_hash=authorization_hash)
        private_data = _json_bytes(private)
        _write_new(private_pending / "model_predictions.private.json", private_data)
        private_identity = _artifact(private_data)
        public = build_public_receipt(
            components=components, private_identity=private_identity,
            head=head, tree=tree, authorization=authorization,
            authorization_hash=authorization_hash,
            source_context=inputs["source_context"])
        public.update(
            execution_started_at_utc=started_at,
            execution_completed_at_utc=_utc_now(),
            wall_clock_seconds=time.perf_counter() - started_clock,
        )
        public_data = _json_bytes(public)
        _assert_public(_unique_json(public_data, "public model receipt", canonical=True))
        public_pending.mkdir(parents=True, exist_ok=False)
        _write_new(public_pending / "model_execution_receipt.json", public_data)
        private_pending.replace(private_root)
        public_pending.replace(public_root)
        return public, private_identity, public_root
    except Exception as error:
        component_failures = _bounded_component_failures(error)
        progress.update(
            result="FAIL", stage_status="STOP_PRESERVE_ALL_ARTIFACTS",
            error_type=type(error).__name__, error_code=_failure_code(error),
            component_partial_receipts=component_failures,
            failed_at_utc=_utc_now(),
        )
        if private_pending.is_dir() and not (private_pending / "FAILURE.json").exists():
            _write_new(private_pending / "FAILURE.json", _json_bytes(progress))
        if not failure_path.exists():
            public_failure = dict(progress)
            public_failure["holdout_accessed"] = bool(progress["holdout_accessed"])
            _assert_public(public_failure)
            _write_new(failure_path, _json_bytes(public_failure))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--authorization-record", required=True, type=Path)
    parser.add_argument("--gate-b-verification-receipt", required=True, type=Path)
    parser.add_argument("--gate-c-verification-receipt", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print("RESULT=RAW_TO_MODEL_MODEL_AUTHORIZED_EXECUTION_STARTING", flush=True)
        public, private_identity, output = run_operational(
            args.repository, args.authorization_record,
            args.gate_b_verification_receipt, args.gate_c_verification_receipt)
        print("RESULT=RAW_TO_MODEL_MODEL_AUTHORIZED_EXECUTION_PASS", flush=True)
        print("TOOL_REVISION=" + TOOL_REVISION, flush=True)
        print("REPOSITORY_HEAD=" + public["repository_head"], flush=True)
        print("SELECTED_C=" + str(public["raw_cv"]["selected_C"]), flush=True)
        print("RAW_CV_FITS=15", flush=True)
        print("FINAL_MODEL_FITS=33", flush=True)
        print("PRIOR_BASELINE_FITS=1", flush=True)
        print("PRIVATE_MODEL_ARTIFACT_BYTES=" + str(private_identity["bytes"]), flush=True)
        print("PRIVATE_MODEL_ARTIFACT_SHA256=" + private_identity["sha256"], flush=True)
        print("PUBLIC_OUTPUT=" + str(output), flush=True)
        print("HOLDOUT_ACCESSED=true", flush=True)
        print("MODEL_FITS_EXECUTED=true", flush=True)
        print("PRIMARY_UTILITY_METRICS_EXECUTED=false", flush=True)
        print("UTILITY_BOOTSTRAP_EXECUTED=false", flush=True)
        print("SENSITIVITY_SCENARIOS_EXECUTED=false", flush=True)
        print("RESULT=STOP_AFTER_MODEL_PREDICTIONS_PENDING_INDEPENDENT_VERIFICATION", flush=True)
        return 0
    except Exception as error:
        print("RESULT=RAW_TO_MODEL_MODEL_AUTHORIZED_EXECUTION_FAIL", flush=True)
        print("ERROR_TYPE=" + type(error).__name__, flush=True)
        print("ERROR_CODE=" + _failure_code(error), flush=True)
        print("RESULT=STOP_PRESERVE_ALL_ARTIFACTS", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
