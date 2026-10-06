from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from math import fsum
import hashlib
import importlib
import json
import re

from common import (
    POPULATION_SIZE,
    QIS,
    RID_ORDER_SHA256,
    cfg_contract,
    exact_keys,
    integer,
    json_digest,
    require,
)
from attack_scorer import (
    observe_age,
    scenario_attributes,
    scenario_pmf,
    score_candidates,
    select_best,
)
from pre_output_targets import (
    PRIVATE_SCHEMA as TARGET_PRIVATE_SCHEMA,
    RECEIPT_SCHEMA as TARGET_RECEIPT_SCHEMA,
)
from permutation_control import (
    MASTER_PERMUTATION_SHA256,
    PRIVATE_SCHEMA as PERMUTATION_PRIVATE_SCHEMA,
    RAW_CONTROL_SCHEMA,
    RECEIPT_SCHEMA as PERMUTATION_RECEIPT_SCHEMA,
    SCORE_PHASE,
    SCORE_STATE_SCHEMA,
)


PROTOCOL_VERSION = "v1.2.4"
NUMPY_VERSION = "2.0.2"
TARGET_COUNT = 5000
DRAW_COUNT = 30
NOISE_SEED = 11003
S4_STREAM_TAG = 4
SOURCE_INPUT_SHA256 = (
    "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5"
)
PHYSICAL_SCHEMA = (
    "sex", "age", "race", "marital-status", "education",
    "native-country", "workclass", "occupation", "salary-class",
)
TARGET = "salary-class"
TARGET_LABELS = frozenset(("<=50K", ">50K"))

NOISE_PRIVATE_SCHEMA = "attack-noise-matrices-private-v1.2.4/1.0"
NOISE_RECEIPT_SCHEMA = "attack-noise-matrices-receipt-v1.2.4/1.0"
SCORE_PAYLOAD_SCHEMA = "attack-score-payload-v1.2.4/1.0"
SCORE_RECEIPT_SCHEMA = "attack-score-receipt-v1.2.4/1.0"
EVALUATION_PRIVATE_SCHEMA = "attack-evaluation-private-v1.2.4/1.0"
EVALUATION_RECEIPT_SCHEMA = "attack-evaluation-receipt-v1.2.4/1.0"
ORACLE_RECEIPT_SCHEMA = "attack-oracle-receipt-v1.2.4/1.0"

_RID = re.compile(r"adult\.data:([1-9][0-9]*)\Z")
_AGE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCORE_PAYLOAD_KEYS = {
    "record_schema", "effective_protocol", "result", "phase",
    "config_id", "scenario", "candidate_row_count",
    "candidate_group_count", "target_count", "draw_count",
    "score_record_count", "candidate_group_id_by_position",
    "candidate_group_sizes", "records", "scores_complete",
    "ground_truth_joined", "rid_exposed_to_scorer",
}


def _sequence(value, name, *, nonempty=False):
    require(isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray)),
            "ATTACK_ADAPTER_SEQUENCE", name + " must be an ordered sequence")
    result = list(value)
    require(not nonempty or bool(result), "ATTACK_ADAPTER_EMPTY_SEQUENCE",
            name + " must not be empty")
    return result


def _sha256(value, name):
    require(type(value) is str and _SHA256.fullmatch(value) is not None,
            "ATTACK_ADAPTER_SHA256", name + " must be a lowercase SHA-256")
    return value


def _artifact(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _json_bytes(value):
    try:
        return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, indent=2) + "\n").encode("ascii")
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(
            "ATTACK_ADAPTER_JSON: value is not canonical ASCII JSON"
        ) from error


def _line_bytes(values, *, encoding="ascii"):
    return ("\n".join(str(value) for value in values) + "\n").encode(encoding)


def _cell(value, name):
    require(type(value) is str and value and value == value.strip()
            and value != "?" and not any(mark in value for mark in ("\0", "\r", "\n", "\t")),
            "ATTACK_ADAPTER_CELL", name + " must be a nonmissing trimmed string")
    return value


def _row(value, name, *, raw_age=False):
    exact_keys(value, PHYSICAL_SCHEMA, name)
    result = {key: _cell(value[key], name + "." + key) for key in PHYSICAL_SCHEMA}
    if raw_age:
        require(_AGE.fullmatch(result["age"]) is not None,
                "ATTACK_ADAPTER_AGE",
                name + ".age must be a canonical nonnegative integer")
    require(result[TARGET] in TARGET_LABELS, "ATTACK_ADAPTER_TARGET",
            name + " has an unknown target label")
    return result


def _rows(values, name, *, raw_age=False):
    return [_row(value, name + "[" + str(index) + "]", raw_age=raw_age)
            for index, value in enumerate(_sequence(values, name, nonempty=True))]


def _population(canonical_rids, source_rows, fixture_mode):
    require(type(fixture_mode) is bool, "ATTACK_ADAPTER_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    rids = _sequence(canonical_rids, "canonical_rids", nonempty=True)
    rows = _rows(source_rows, "source_rows", raw_age=True)
    require(len(rids) == len(rows), "ATTACK_ADAPTER_POPULATION_ALIGNMENT",
            "Canonical RIDs and source rows must align")
    physical = []
    for rid in rids:
        match = _RID.fullmatch(rid) if type(rid) is str else None
        require(match is not None, "ATTACK_ADAPTER_RID",
                "Every RID must use adult.data:<physical-line>")
        physical.append(int(match.group(1)))
    require(all(left < right for left, right in zip(physical, physical[1:])),
            "ATTACK_ADAPTER_RID_ORDER",
            "Canonical RIDs must be unique and in increasing physical-line order")
    if not fixture_mode:
        require(len(rids) == POPULATION_SIZE, "ATTACK_ADAPTER_OPERATIONAL_POPULATION",
                "Operational attack preparation requires exactly 30162 rows")
        require(hashlib.sha256(_line_bytes(rids, encoding="utf-8")).hexdigest()
                == RID_ORDER_SHA256, "ATTACK_ADAPTER_RID_IDENTITY",
                "Canonical RID order differs from the authoritative freeze")
    return rids, rows


def _permutation(values, population_count, fixture_mode):
    permutation = _sequence(values, "master_permutation", nonempty=True)
    require(len(permutation) == population_count
            and all(type(value) is int for value in permutation)
            and sorted(permutation) == list(range(population_count)),
            "ATTACK_ADAPTER_MASTER_PERMUTATION",
            "Master Pi must be a complete zero-based population bijection")
    digest = hashlib.sha256(_line_bytes(permutation)).hexdigest()
    if not fixture_mode:
        require(digest == MASTER_PERMUTATION_SHA256,
                "ATTACK_ADAPTER_MASTER_IDENTITY",
                "Master Pi differs from the authoritative freeze")
    return permutation, digest


def _tsv_bytes(rows):
    lines = ["\t".join(PHYSICAL_SCHEMA)]
    for row in rows:
        lines.append("\t".join(row[column] for column in PHYSICAL_SCHEMA))
    return ("\n".join(lines) + "\n").encode("utf-8")


def raw_control_receipt_bytes(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == RAW_CONTROL_SCHEMA,
            "ATTACK_ADAPTER_RAW_SCHEMA", "Unexpected CFG00 receipt schema")
    payload = _json_bytes(receipt)
    require(b"adult.data:" not in payload and b'"rows"' not in payload,
            "ATTACK_ADAPTER_RAW_PRIVATE_LEAK",
            "CFG00 bounded receipt contains private identities or rows")
    return payload


def prepare_cfg00_raw_control(*, canonical_rids, source_rows,
                              master_permutation, source_input_sha256,
                              fixture_mode=False):

    rids, rows = _population(canonical_rids, source_rows, fixture_mode)
    permutation, permutation_hash = _permutation(
        master_permutation, len(rows), fixture_mode)
    source_hash = _sha256(source_input_sha256, "source_input_sha256")
    if not fixture_mode:
        require(source_hash == SOURCE_INPUT_SHA256,
                "ATTACK_ADAPTER_SOURCE_IDENTITY",
                "CFG00 source differs from the frozen Adult training input")
    before = json_digest([rids, rows, permutation])
    published_rows = [deepcopy(rows[index]) for index in permutation]
    output_bytes = _tsv_bytes(published_rows)
    receipt = {
        "record_schema": RAW_CONTROL_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "config_id": "CFG00",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_RAW_CONTROL",
        "n_input": len(rows),
        "n_retained": len(rows),
        "outlier_count": 0,
        "outlier_source": "NOT_APPLICABLE_RAW_CONTROL",
        "source_input_sha256": source_hash,
        "release_output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "release_output_bytes": len(output_bytes),
        "release_order": "MASTER_PI_FULL",
        "master_permutation_sha256": permutation_hash,
        "private_rows_in_receipt": False,
        "numeric_risk_pass_fail_criterion": None,
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "anonymization_invoked": False,
        "model_fit_executed": False,
    }
    raw_control_receipt_bytes(receipt)
    require(json_digest([rids, rows, permutation]) == before,
            "ATTACK_ADAPTER_INPUT_MUTATION",
            "CFG00 inputs changed during preparation")
    return {
        "release_rows": published_rows,
        "release_tsv_bytes": output_bytes,
        "bounded_receipt": receipt,
    }


def noise_private_bytes(record):
    require(isinstance(record, Mapping)
            and record.get("record_schema") == NOISE_PRIVATE_SCHEMA,
            "ATTACK_ADAPTER_NOISE_PRIVATE_SCHEMA",
            "Unexpected private noise schema")
    return _json_bytes(record)


def noise_receipt_bytes(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == NOISE_RECEIPT_SCHEMA,
            "ATTACK_ADAPTER_NOISE_RECEIPT_SCHEMA",
            "Unexpected bounded noise receipt schema")
    payload = _json_bytes(receipt)
    require(b'"base_matrix"' not in payload and b'"s4_matrix"' not in payload,
            "ATTACK_ADAPTER_NOISE_PRIVATE_LEAK",
            "Bounded noise receipt contains a realized noise matrix")
    return payload


def _numpy(module, fixture_mode):
    result = importlib.import_module("numpy") if module is None else module
    require(hasattr(result, "random"), "ATTACK_ADAPTER_NUMPY_API",
            "NumPy random API is unavailable")
    if not fixture_mode:
        require(getattr(result, "__version__", None) == NUMPY_VERSION,
                "ATTACK_ADAPTER_NUMPY_VERSION",
                "Operational attack preparation requires NumPy 2.0.2")
    return result


def _base_noise(module, target_count, draw_count):
    generator = module.random.Generator(module.random.PCG64(NOISE_SEED))
    support = module.array([-2, -1, 0, 1, 2], dtype=module.int64)
    probabilities = module.array([0.1, 0.2, 0.4, 0.2, 0.1], dtype=module.float64)
    raw = generator.choice(support, size=(target_count, draw_count),
                           replace=True, p=probabilities, axis=0, shuffle=True)
    return [[int(value) for value in row] for row in raw.tolist()]


def _s4_noise(module, target_count, draw_count):
    seed_sequence = module.random.SeedSequence([NOISE_SEED, S4_STREAM_TAG])
    generator = module.random.Generator(module.random.PCG64(seed_sequence))
    raw = generator.integers(-5, 6, size=(target_count, draw_count),
                             dtype=module.int64, endpoint=False)
    return [[int(value) for value in row] for row in raw.tolist()]


def prepare_noise_matrices(*, fixture_mode=False, fixture_target_count=None,
                           fixture_draw_count=None, numpy_module=None):

    require(type(fixture_mode) is bool, "ATTACK_ADAPTER_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    if fixture_mode:
        target_count = integer(fixture_target_count, "fixture_target_count", 1)
        draw_count = integer(fixture_draw_count, "fixture_draw_count", 1)
    else:
        require(fixture_target_count is None and fixture_draw_count is None,
                "ATTACK_ADAPTER_OPERATIONAL_NOISE_OVERRIDE",
                "Operational noise shape cannot be overridden")
        target_count, draw_count = TARGET_COUNT, DRAW_COUNT
    module = _numpy(numpy_module, fixture_mode)
    base = _base_noise(module, target_count, draw_count)
    s4 = _s4_noise(module, target_count, draw_count)
    require(base == _base_noise(module, target_count, draw_count)
            and s4 == _s4_noise(module, target_count, draw_count),
            "ATTACK_ADAPTER_NOISE_REPRODUCIBILITY",
            "Fresh scenario-noise regeneration differs")
    private = {
        "record_schema": NOISE_PRIVATE_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_MAIN_RUN",
        "target_count": target_count,
        "draw_count": draw_count,
        "matrix_order": "TARGET_MAJOR_DRAW_MINOR_C_ORDER",
        "base_seed_derivation": "Generator(PCG64(11003))",
        "s4_seed_derivation": "Generator(PCG64(SeedSequence([11003,4])))",
        "base_matrix": base,
        "s4_matrix": s4,
        "s3_noise": "DETERMINISTIC_ZERO_NOT_STORED_AS_A_MATRIX",
        "s1_s2_reuse": "EXACT_BASE_MATRIX",
        "visibility": "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
    }
    private_data = noise_private_bytes(private)
    receipt = {
        "record_schema": NOISE_RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_MAIN_RUN",
        "numpy_version": getattr(module, "__version__", "test-double"),
        "target_count": target_count,
        "draw_count": draw_count,
        "matrix_order": "TARGET_MAJOR_DRAW_MINOR_C_ORDER",
        "base_seed_derivation": "Generator(PCG64(11003))",
        "s4_seed_derivation": "Generator(PCG64(SeedSequence([11003,4])))",
        "base_matrix_sha256": json_digest(base),
        "s4_matrix_sha256": json_digest(s4),
        "private_record_json": _artifact(private_data),
        "base_matrix_shared_by": ["BASE", "S1", "S2"],
        "s3_deterministic_zero": True,
        "fresh_generation_count_per_random_matrix": 2,
        "noise_generated": True,
        "main_run_authorization_granted_by_this_artifact": False,
        "anonymization_invoked": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
    }
    noise_receipt_bytes(receipt)
    return {"private_record": private, "bounded_receipt": receipt}


def _noise(noise_private, noise_receipt, scenario, target_count, fixture_mode):
    exact_keys(noise_private, {
        "record_schema", "effective_protocol", "scope", "target_count",
        "draw_count", "matrix_order", "base_seed_derivation",
        "s4_seed_derivation", "base_matrix", "s4_matrix", "s3_noise",
        "s1_s2_reuse", "visibility",
    }, "noise_private")
    require(noise_private["record_schema"] == NOISE_PRIVATE_SCHEMA
            and noise_private["effective_protocol"] == PROTOCOL_VERSION,
            "ATTACK_ADAPTER_NOISE_BINDING", "Private noise record is not v1.2.4")
    require(isinstance(noise_receipt, Mapping)
            and noise_receipt.get("record_schema") == NOISE_RECEIPT_SCHEMA
            and noise_receipt.get("result") == "PASS",
            "ATTACK_ADAPTER_NOISE_RECEIPT_BINDING",
            "A passing bounded noise receipt is required")
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_MAIN_RUN"
    require(noise_private["scope"] == noise_receipt.get("scope") == expected_scope,
            "ATTACK_ADAPTER_NOISE_SCOPE", "Noise scope differs from execution mode")
    require(noise_private["target_count"] == noise_receipt.get("target_count") == target_count,
            "ATTACK_ADAPTER_NOISE_TARGETS", "Noise and target counts differ")
    draw_count = integer(noise_private["draw_count"], "noise draw_count", 1)
    require(draw_count == noise_receipt.get("draw_count"),
            "ATTACK_ADAPTER_NOISE_DRAWS", "Noise draw counts differ")
    if not fixture_mode:
        require(draw_count == DRAW_COUNT, "ATTACK_ADAPTER_OPERATIONAL_DRAWS",
                "Operational attack scoring requires 30 draws")
    base = _sequence(noise_private["base_matrix"], "base_matrix")
    s4 = _sequence(noise_private["s4_matrix"], "s4_matrix")
    for matrix, support, name in ((base, set(range(-2, 3)), "base_matrix"),
                                  (s4, set(range(-5, 6)), "s4_matrix")):
        require(len(matrix) == target_count, "ATTACK_ADAPTER_NOISE_SHAPE",
                name + " has the wrong target axis")
        for row in matrix:
            values = _sequence(row, name + " row")
            require(len(values) == draw_count and all(type(value) is int
                    and value in support for value in values),
                    "ATTACK_ADAPTER_NOISE_DOMAIN",
                    name + " has the wrong draw shape or support")
    private_data = noise_private_bytes(noise_private)
    artifact = noise_receipt.get("private_record_json")
    require(isinstance(artifact, Mapping)
            and artifact.get("bytes") == len(private_data)
            and artifact.get("sha256") == hashlib.sha256(private_data).hexdigest()
            and noise_receipt.get("base_matrix_sha256") == json_digest(base)
            and noise_receipt.get("s4_matrix_sha256") == json_digest(s4),
            "ATTACK_ADAPTER_NOISE_HASH", "Noise matrices are not hash-bound")
    if scenario in ("BASE", "S1", "S2"):
        return base, draw_count
    if scenario == "S3":
        return [[0] * draw_count for _ in range(target_count)], draw_count
    return s4, draw_count


def _targets(target_private, target_receipt, canonical_rids, fixture_mode):
    require(isinstance(target_private, Mapping)
            and target_private.get("record_schema") == TARGET_PRIVATE_SCHEMA,
            "ATTACK_ADAPTER_TARGET_PRIVATE",
            "The frozen private target-sample record is required")
    require(isinstance(target_receipt, Mapping)
            and target_receipt.get("record_schema") == TARGET_RECEIPT_SCHEMA
            and target_receipt.get("result") == "PASS",
            "ATTACK_ADAPTER_TARGET_RECEIPT",
            "A passing bounded target-sample receipt is required")
    indices = _sequence(target_private.get("target_indices"),
                        "target_indices", nonempty=True)
    rids = _sequence(target_private.get("target_rids"), "target_rids", nonempty=True)
    count = integer(target_private.get("target_count"), "target_count", 1)
    require(len(indices) == len(rids) == count
            and all(type(value) is int and 0 <= value < len(canonical_rids)
                    for value in indices)
            and len(set(indices)) == count
            and rids == [canonical_rids[index] for index in indices],
            "ATTACK_ADAPTER_TARGET_ALIGNMENT",
            "Private target indices/RIDs do not align with the population")
    if not fixture_mode:
        require(count == TARGET_COUNT, "ATTACK_ADAPTER_OPERATIONAL_TARGETS",
                "Operational attack scoring requires 5000 targets")
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_PRE_OUTPUT"
    private_data = _json_bytes(target_private)
    private_artifact = target_receipt.get("private_record_json")
    require(target_receipt.get("scope") == expected_scope
            and target_receipt.get("target_count") == count
            and target_receipt.get("population_count") == len(canonical_rids)
            and target_receipt.get("target_index_order_sha256")
                == hashlib.sha256(_line_bytes(indices)).hexdigest()
            and target_receipt.get("target_rid_order_sha256")
                == hashlib.sha256(_line_bytes(rids, encoding="utf-8")).hexdigest()
            and isinstance(private_artifact, Mapping)
            and private_artifact.get("bytes") == len(private_data)
            and private_artifact.get("sha256")
                == hashlib.sha256(private_data).hexdigest(),
            "ATTACK_ADAPTER_TARGET_HASH",
            "Target sample differs from its bounded receipt")
    return indices, rids, target_receipt["target_rid_order_sha256"]


def _hierarchies(tables, source_rows, transformation):
    exact_keys(tables, QIS, "hierarchy_tables")
    exact_keys(transformation, QIS, "transformation_by_name")
    result = {}
    for attribute in QIS:
        table = tables[attribute]
        exact_keys(table, {"levels", "rows"}, "hierarchy " + attribute)
        levels = _sequence(table["levels"], attribute + " levels", nonempty=True)
        require(levels == list(range(len(levels))),
                "ATTACK_ADAPTER_HIERARCHY_LEVELS",
                attribute + " hierarchy levels must be contiguous and zero based")
        level = integer(transformation[attribute], attribute + " level")
        require(level < len(levels), "ATTACK_ADAPTER_TRANSFORMATION_LEVEL",
                attribute + " transformation level is outside the hierarchy")
        paths = _sequence(table["rows"], attribute + " hierarchy rows", nonempty=True)
        by_leaf = {}
        by_level = [OrderedDict() for _ in levels]
        child_to_parent = [dict() for _ in range(len(levels) - 1)]
        for row_index, path in enumerate(paths):
            cells = _sequence(path, attribute + " hierarchy path", nonempty=True)
            require(len(cells) == len(levels), "ATTACK_ADAPTER_HIERARCHY_WIDTH",
                    attribute + " hierarchy is not rectangular")
            cells = [_cell(value, attribute + " hierarchy cell") for value in cells]
            leaf = cells[0]
            require(leaf not in by_leaf, "ATTACK_ADAPTER_HIERARCHY_LEAF",
                    attribute + " hierarchy repeats a leaf")
            by_leaf[leaf] = tuple(cells)
            for level_index, label in enumerate(cells):
                by_level[level_index].setdefault(label, set()).add(leaf)
            for level_index, parents in enumerate(child_to_parent):
                child, parent = cells[level_index:level_index + 2]
                require(child not in parents or parents[child] == parent,
                        "ATTACK_ADAPTER_HIERARCHY_NESTING",
                        attribute + " hierarchy node splits at the next level")
                parents[child] = parent
        require(all(row[attribute] in by_leaf for row in source_rows),
                "ATTACK_ADAPTER_HIERARCHY_COVERAGE",
                attribute + " hierarchy does not cover every source leaf")
        result[attribute] = {
            "level": level,
            "by_leaf": by_leaf,
            "selected_leafsets": {
                label: frozenset(values)
                for label, values in by_level[level].items()
            },
        }
    return result


def _release(config_id, source_rows, release_rows, flags, master,
             hierarchy_index, transformation, release_receipt,
             producer_report_bytes, fixture_mode):
    rows = _rows(release_rows, "release_rows")
    outliers = _sequence(flags, "is_outlier", nonempty=True)
    require(len(rows) == len(source_rows) == len(outliers)
            and all(type(value) is bool for value in outliers),
            "ATTACK_ADAPTER_RELEASE_ALIGNMENT",
            "Release rows and Boolean outlier mask must cover the population")
    if config_id == "CFG00":
        require(not any(outliers) and rows == source_rows,
                "ATTACK_ADAPTER_CFG00_ROWS",
                "CFG00 must use every unchanged source row in original order")
        require(producer_report_bytes is None,
                "ATTACK_ADAPTER_CFG00_JAVA_REPORT",
                "CFG00 has no ARX producer report")
        expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_RAW_CONTROL"
        require(isinstance(release_receipt, Mapping)
                and release_receipt.get("record_schema") == RAW_CONTROL_SCHEMA
                and release_receipt.get("result") == "PASS"
                and release_receipt.get("config_id") == "CFG00"
                and release_receipt.get("scope") == expected_scope
                and release_receipt.get("outlier_source")
                    == "NOT_APPLICABLE_RAW_CONTROL"
                and release_receipt.get("private_rows_in_receipt") is False,
                "ATTACK_ADAPTER_CFG00_RECEIPT",
                "CFG00 requires its passing raw-control receipt")
        published_indices = list(master)
        published_rows = [rows[index] for index in published_indices]
        payload = _tsv_bytes(published_rows)
        require(release_receipt.get("n_input") == len(rows)
                and release_receipt.get("n_retained") == len(rows)
                and release_receipt.get("outlier_count") == 0
                and release_receipt.get("release_output_sha256")
                    == hashlib.sha256(payload).hexdigest(),
                "ATTACK_ADAPTER_CFG00_RELEASE_HASH",
                "CFG00 published rows differ from the raw-control receipt")
        return published_indices, published_rows, None

    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_OUTPUT"
    require(isinstance(release_receipt, Mapping)
            and release_receipt.get("record_schema")
                == "section-12-1-gate-b-v1.2.4/1.0"
            and release_receipt.get("result") == "PASS"
            and release_receipt.get("config_id") == config_id
            and release_receipt.get("scope") == expected_scope,
            "ATTACK_ADAPTER_GATE_B_RECEIPT",
            'A matching anonymization validation PASS receipt is required')
    full_bytes = _tsv_bytes(rows)
    require(release_receipt.get("n_input") == len(rows)
            and release_receipt.get("n_retained") == sum(not flag for flag in outliers)
            and release_receipt.get("outlier_count") == sum(outliers)
            and release_receipt.get("outlier_source") == "captured_DataHandle.isOutlier"
            and release_receipt.get("private_rows_in_receipt") is False
            and release_receipt.get("full_output_sha256")
                == hashlib.sha256(full_bytes).hexdigest(),
            "ATTACK_ADAPTER_GATE_B_BINDING",
            'Anonymization validation counts or full-output identity differ')
    require(isinstance(producer_report_bytes, bytes) and producer_report_bytes,
            "ATTACK_ADAPTER_JAVA_REPORT", "ARX CFGs require exact Java-report bytes")
    require(hashlib.sha256(producer_report_bytes).hexdigest()
            == release_receipt.get("java_report_sha256"),
            "ATTACK_ADAPTER_JAVA_REPORT_HASH",
            'Java report differs from the anonymization validation receipt')
    try:
        report = json.loads(producer_report_bytes.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("ATTACK_ADAPTER_JAVA_REPORT_JSON: invalid Java report") from error
    require(isinstance(report, Mapping)
            and report.get("record_schema") == "arx-main-cfg-v1.2.4/1.0"
            and report.get("result") == "PASS"
            and report.get("config_id") == config_id
            and report.get("effective_protocol") == PROTOCOL_VERSION,
            "ATTACK_ADAPTER_JAVA_REPORT_BINDING",
            'Java report does not bind the requested CFG and execution specification')
    mask = report.get("outlier_mask")
    require(isinstance(mask, Mapping)
            and mask.get("source") == "DataHandle.isOutlier"
            and mask.get("values") == outliers
            and mask.get("count") == sum(outliers),
            "ATTACK_ADAPTER_JAVA_MASK",
            "Java report outlier mask differs from the supplied mask")
    artifact = report.get("full_output")
    require(isinstance(artifact, Mapping)
            and artifact.get("bytes") == len(full_bytes)
            and artifact.get("sha256") == hashlib.sha256(full_bytes).hexdigest(),
            "ATTACK_ADAPTER_JAVA_OUTPUT",
            "Java report does not bind the supplied full output")
    require(report.get("transformation_by_name") == transformation
            and report.get("retained_transformation_equality") is True
            and report.get("target_index_binding") is True
            and report.get("no_sort_or_permutation") is True,
            "ATTACK_ADAPTER_JAVA_TRANSFORMATION",
            "Java report lacks the required named transformation assertions")
    if not fixture_mode:
        require(report.get("main_runs_authorized") is True
                and report.get("main_runs_executed") is True
                and report.get("anonymization_invoked") is True,
                "ATTACK_ADAPTER_JAVA_OPERATIONAL_STATUS",
                "Operational score preparation requires an authorized ARX run")

    for index, (source, output, outlier) in enumerate(zip(source_rows, rows, outliers)):
        require(output[TARGET] == source[TARGET],
                "ATTACK_ADAPTER_TARGET_BINDING",
                "Release target differs at original index " + str(index))
        if outlier:
            continue
        for attribute in QIS:
            expected = hierarchy_index[attribute]["by_leaf"][source[attribute]][
                transformation[attribute]
            ]
            require(output[attribute] == expected,
                    "ATTACK_ADAPTER_RETAINED_TRANSFORMATION",
                    "Retained output differs from its hierarchy path")
    published_indices = [index for index in master if not outliers[index]]
    published_rows = [rows[index] for index in published_indices]
    return published_indices, published_rows, report


def _groups(published_rows, hierarchy_index, scenario):
    attributes = scenario_attributes(scenario)
    categorical = tuple(value for value in attributes if value != "age")
    keyed = OrderedDict()
    for position, row in enumerate(published_rows):
        key = tuple(row[attribute] for attribute in attributes)
        keyed.setdefault(key, []).append(position)
    groups = []
    by_category = OrderedDict()
    position_to_group = [None] * len(published_rows)
    for group_id, (labels, positions) in enumerate(keyed.items()):
        leafsets = {}
        for attribute, label in zip(attributes, labels):
            selected = hierarchy_index[attribute]["selected_leafsets"]
            require(label in selected, "ATTACK_ADAPTER_CANDIDATE_NODE",
                    "Candidate label is absent at its selected hierarchy level")
            leaves = selected[label]
            if attribute == "age":
                require(all(_AGE.fullmatch(value) is not None for value in leaves),
                        "ATTACK_ADAPTER_AGE_LEAF",
                        "Age hierarchy leaves must be canonical integers")
                leafsets[attribute] = frozenset(int(value) for value in leaves)
            else:
                leafsets[attribute] = leaves
        for position in positions:
            position_to_group[position] = group_id
        category_key = tuple(labels[attributes.index(attribute)]
                             for attribute in categorical)
        by_category.setdefault(category_key, []).append(group_id)
        groups.append({
            "leafsets": leafsets,
            "positions": tuple(positions),
            "size": len(positions),
        })
    require(all(type(value) is int for value in position_to_group),
            "ATTACK_ADAPTER_GROUP_COVERAGE",
            "Candidate groups do not cover every published position")
    return attributes, categorical, groups, by_category, position_to_group


def _score_payload_bytes(payload):
    exact_keys(payload, _SCORE_PAYLOAD_KEYS, "score_payload")
    data = _json_bytes(payload)
    require(b"adult.data:" not in data
            and b'"target_indices"' not in data
            and b'"target_rids"' not in data
            and b'"realized_error"' not in data
            and b'"true_row"' not in data,
            "ATTACK_ADAPTER_SCORE_PRIVATE_LEAK",
            "Score payload exposes a prohibited scorer input or ground truth")
    return data


def score_receipt_bytes(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == SCORE_RECEIPT_SCHEMA,
            "ATTACK_ADAPTER_SCORE_RECEIPT_SCHEMA",
            "Unexpected score receipt schema")
    data = _json_bytes(receipt)
    require(b"adult.data:" not in data and b'"records"' not in data,
            "ATTACK_ADAPTER_SCORE_RECEIPT_LEAK",
            "Bounded score receipt contains private records or RIDs")
    return data


def prepare_attack_score_state(*, config_id, scenario, canonical_rids,
                               source_rows, release_rows, is_outlier,
                               master_permutation, hierarchy_tables,
                               transformation_by_name, target_private,
                               target_receipt, noise_private, noise_receipt,
                               release_validation_receipt,
                               source_input_sha256,
                               producer_report_bytes=None,
                               fixture_mode=False):
    """Score before joining ground truth; duplicate row positions retain their tie weight."""
    cfg_contract(config_id)
    scenario_attributes(scenario)
    rids, source = _population(canonical_rids, source_rows, fixture_mode)
    source_hash = _sha256(source_input_sha256, "source_input_sha256")
    if not fixture_mode:
        require(source_hash == SOURCE_INPUT_SHA256,
                "ATTACK_ADAPTER_SOURCE_IDENTITY",
                "Source rows must originate from the frozen Adult training table")
    master, master_hash = _permutation(master_permutation, len(rids), fixture_mode)
    transformation = dict(transformation_by_name)
    if config_id == "CFG00":
        require(transformation == {attribute: 0 for attribute in QIS},
                "ATTACK_ADAPTER_CFG00_TRANSFORMATION",
                "CFG00 requires hierarchy level zero for every QI")
    hierarchy = _hierarchies(hierarchy_tables, source, transformation)
    target_indices, target_rids, target_hash = _targets(
        target_private, target_receipt, rids, fixture_mode)
    noise, draw_count = _noise(
        noise_private, noise_receipt, scenario, len(target_indices), fixture_mode)
    published_indices, published_rows, producer_report = _release(
        config_id, source, release_rows, is_outlier, master, hierarchy,
        transformation, release_validation_receipt,
        producer_report_bytes, fixture_mode)
    if config_id == "CFG00":
        require(release_validation_receipt.get("source_input_sha256") == source_hash,
                "ATTACK_ADAPTER_SOURCE_BINDING",
                "CFG00 receipt and supplied source identity differ")
    else:
        pinned = producer_report.get("pinned_inputs")
        require(isinstance(pinned, Sequence)
                and any(isinstance(item, Mapping)
                        and item.get("role") == "training_input"
                        and item.get("sha256") == source_hash for item in pinned),
                "ATTACK_ADAPTER_SOURCE_BINDING",
                "Java report does not bind the supplied training-source identity")
    require(published_rows, "ATTACK_ADAPTER_EMPTY_CANDIDATES",
            "At least one candidate row is required")
    before = json_digest({
        "canonical_rids": rids,
        "source_rows": source,
        "release_rows": release_rows,
        "is_outlier": is_outlier,
        "master_permutation": master,
        "hierarchy_tables": hierarchy_tables,
        "transformation_by_name": transformation,
        "target_private": target_private,
        "target_receipt": target_receipt,
        "noise_private": noise_private,
        "noise_receipt": noise_receipt,
        "release_validation_receipt": release_validation_receipt,
        "source_input_sha256": source_hash,
    })

    attributes, categorical, groups, category_index, group_by_position = _groups(
        published_rows, hierarchy, scenario)
    records = []
    for target_position, source_index in enumerate(target_indices):
        raw = source[source_index]
        known = {attribute: raw[attribute] for attribute in categorical}
        category_key = tuple(
            hierarchy[attribute]["by_leaf"][raw[attribute]][transformation[attribute]]
            for attribute in categorical
        )
        relevant_ids = category_index.get(category_key, ())
        relevant_candidates = [groups[group_id]["leafsets"]
                               for group_id in relevant_ids]
        for draw_index, error in enumerate(noise[target_position]):
            observed_age = observe_age(int(raw["age"]), error, scenario)
            if relevant_candidates:
                scores = score_candidates(observed_age, known,
                                          relevant_candidates, scenario)
                local_best = select_best(scores)
                winners = [relevant_ids[index] for index in local_best]
                maximum = max(scores)
            else:
                winners = []
                maximum = 0.0
            tie_size = sum(groups[group_id]["size"] for group_id in winners)
            require((not winners and tie_size == 0 and maximum == 0.0)
                    or (winners and tie_size > 0 and maximum > 0.0),
                    "ATTACK_ADAPTER_SELECTION_STATE",
                    "Winner groups, tie size and maximum score are inconsistent")
            records.append({
                "target_position": target_position,
                "draw_index": draw_index,
                "maximum_score_float_hex": float(maximum).hex(),
                "winner_group_ids": winners,
                "tie_size": tie_size,
                "attempted": bool(winners),
            })
    expected_records = len(target_indices) * draw_count
    require(len(records) == expected_records,
            "ATTACK_ADAPTER_SCORE_COMPLETENESS",
            "Scoring did not create one record per target/draw pair")
    payload = {
        "record_schema": SCORE_PAYLOAD_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "phase": SCORE_PHASE,
        "config_id": config_id,
        "scenario": scenario,
        "candidate_row_count": len(published_rows),
        "candidate_group_count": len(groups),
        "target_count": len(target_indices),
        "draw_count": draw_count,
        "score_record_count": expected_records,
        "candidate_group_id_by_position": group_by_position,
        "candidate_group_sizes": [group["size"] for group in groups],
        "records": records,
        "scores_complete": True,
        "ground_truth_joined": False,
        "rid_exposed_to_scorer": False,
    }
    payload_data = _score_payload_bytes(payload)
    candidate_hash = json_digest(published_rows)
    score_state = {
        "record_schema": SCORE_STATE_SCHEMA,
        "result": "PASS",
        "phase": SCORE_PHASE,
        "config_id": config_id,
        "scenario": scenario,
        "candidate_row_count": len(published_rows),
        "target_count": len(target_indices),
        "draw_count": draw_count,
        "score_record_count": expected_records,
        "candidate_order_sha256": candidate_hash,
        "target_order_sha256": target_hash,
        "score_payload_sha256": hashlib.sha256(payload_data).hexdigest(),
        "scores_complete": True,
        "ground_truth_joined": False,
        "rid_exposed_to_scorer": False,
    }
    score_state_hash = json_digest(score_state)
    receipt = {
        "record_schema": SCORE_RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG_SCENARIO",
        "config_id": config_id,
        "scenario": scenario,
        "scenario_attributes": list(attributes),
        "scenario_pmf": [[error, mass] for error, mass in scenario_pmf(scenario)],
        "candidate_row_count": len(published_rows),
        "candidate_group_count": len(groups),
        "target_count": len(target_indices),
        "draw_count": draw_count,
        "score_record_count": expected_records,
        "publication_order": "MASTER_PI_FULL" if config_id == "CFG00"
                             else "MASTER_PI_RESTRICTED_TO_NOT_OUTLIER",
        "published_source_indices_sha256": json_digest(published_indices),
        "master_permutation_sha256": master_hash,
        "candidate_order_sha256": candidate_hash,
        "target_order_sha256": target_hash,
        "noise_private_record_sha256": hashlib.sha256(
            noise_private_bytes(noise_private)).hexdigest(),
        "release_validation_receipt_sha256": json_digest(
            release_validation_receipt),
        "source_input_sha256": source_hash,
        "producer_report_sha256": (None if producer_report is None else
                                    hashlib.sha256(producer_report_bytes).hexdigest()),
        "score_payload_json": _artifact(payload_data),
        "score_state_json_sha256": score_state_hash,
        "grouping_is_lossless_for_scores": True,
        "duplicate_rows_counted_by_group_size": True,
        "categorically_incompatible_groups_have_exact_zero": True,
        "scores_complete_before_ground_truth": True,
        "ground_truth_joined": False,
        "rid_exposed_to_scorer": False,
        "private_values_in_receipt": False,
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
    }
    score_receipt_bytes(receipt)
    require(json_digest({
        "canonical_rids": rids,
        "source_rows": source,
        "release_rows": release_rows,
        "is_outlier": is_outlier,
        "master_permutation": master,
        "hierarchy_tables": hierarchy_tables,
        "transformation_by_name": transformation,
        "target_private": target_private,
        "target_receipt": target_receipt,
        "noise_private": noise_private,
        "noise_receipt": noise_receipt,
        "release_validation_receipt": release_validation_receipt,
        "source_input_sha256": source_hash,
    }) == before, "ATTACK_ADAPTER_INPUT_MUTATION",
            "Attack-scoring inputs changed")
    return {
        "score_payload": payload,
        "score_state": score_state,
        "bounded_receipt": receipt,
    }


def _validate_score_bundle(score_payload, score_state, score_receipt):
    data = _score_payload_bytes(score_payload)
    require(isinstance(score_state, Mapping)
            and score_state.get("record_schema") == SCORE_STATE_SCHEMA
            and score_state.get("result") == "PASS"
            and score_state.get("phase") == SCORE_PHASE,
            "ATTACK_ADAPTER_SCORE_STATE", "Complete score state is required")
    require(isinstance(score_receipt, Mapping)
            and score_receipt.get("record_schema") == SCORE_RECEIPT_SCHEMA
            and score_receipt.get("result") == "PASS",
            "ATTACK_ADAPTER_SCORE_RECEIPT", "Passing score receipt is required")
    require(score_payload["config_id"] == score_state.get("config_id")
            == score_receipt.get("config_id")
            and score_payload["scenario"] == score_state.get("scenario")
            == score_receipt.get("scenario"),
            "ATTACK_ADAPTER_SCORE_BUNDLE", "Score bundle CFG/scenario differs")
    require(hashlib.sha256(data).hexdigest()
            == score_state.get("score_payload_sha256")
            == score_receipt.get("score_payload_json", {}).get("sha256")
            and len(data) == score_receipt.get("score_payload_json", {}).get("bytes")
            and json_digest(score_state) == score_receipt.get("score_state_json_sha256"),
            "ATTACK_ADAPTER_SCORE_HASH", "Score payload/state is not hash-bound")
    for key in ("candidate_row_count", "target_count", "draw_count",
                "score_record_count"):
        require(score_payload[key] == score_state.get(key)
                == score_receipt.get(key),
                "ATTACK_ADAPTER_SCORE_COUNTS",
                "Score payload/state/receipt counts differ")
    require(score_payload["scores_complete"] is True
            and score_payload["ground_truth_joined"] is False
            and score_payload["rid_exposed_to_scorer"] is False
            and score_state.get("scores_complete") is True
            and score_state.get("ground_truth_joined") is False
            and score_state.get("rid_exposed_to_scorer") is False,
            "ATTACK_ADAPTER_SCORE_SEPARATION",
            "Ground truth separation was not preserved")
    return data


def evaluation_private_bytes(record):
    require(isinstance(record, Mapping)
            and record.get("record_schema") == EVALUATION_PRIVATE_SCHEMA,
            "ATTACK_ADAPTER_EVALUATION_PRIVATE_SCHEMA",
            "Unexpected private evaluation schema")
    return _json_bytes(record)


def evaluation_receipt_bytes(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == EVALUATION_RECEIPT_SCHEMA,
            "ATTACK_ADAPTER_EVALUATION_RECEIPT_SCHEMA",
            "Unexpected evaluation receipt schema")
    data = _json_bytes(receipt)
    require(b"adult.data:" not in data
            and b'"success_draws"' not in data
            and b'"release_ids"' not in data
            and b'"target_ids"' not in data,
            "ATTACK_ADAPTER_EVALUATION_LEAK",
            "Bounded evaluation receipt contains private identities or draws")
    return data


def evaluate_attack_score_payload(*, score_payload, score_state, score_receipt,
                                  target_private, target_receipt,
                                  canonical_rids, source_rows,
                                  permutation_private,
                                  permutation_receipt,
                                  mapping_role, fixture_mode=False):

    require(mapping_role in ("ACTUAL", "PERMUTED"),
            "ATTACK_ADAPTER_MAPPING_ROLE",
            "mapping_role must be ACTUAL or PERMUTED")
    score_data = _validate_score_bundle(score_payload, score_state, score_receipt)
    rids, source = _population(canonical_rids, source_rows, fixture_mode)
    target_indices, target_rids, target_hash = _targets(
        target_private, target_receipt, rids, fixture_mode)
    require(score_state["target_order_sha256"] == target_hash,
            "ATTACK_ADAPTER_EVALUATION_TARGET_HASH",
            "Score state and target sample order differ")
    require(isinstance(permutation_private, Mapping)
            and permutation_private.get("record_schema") == PERMUTATION_PRIVATE_SCHEMA
            and permutation_private.get("config_id") == score_state["config_id"],
            "ATTACK_ADAPTER_PERMUTATION_PRIVATE",
            "Matching private permutation record is required")
    require(isinstance(permutation_receipt, Mapping)
            and permutation_receipt.get("record_schema") == PERMUTATION_RECEIPT_SCHEMA
            and permutation_receipt.get("result") == "PASS"
            and permutation_receipt.get("config_id") == score_state["config_id"]
            and permutation_receipt.get("permutation_subgate") == "PASS",
            "ATTACK_ADAPTER_PERMUTATION_RECEIPT",
            "Matching passing permutation receipt is required")
    private_data = (json.dumps(permutation_private, ensure_ascii=True,
                               allow_nan=False, sort_keys=True, indent=2)
                    + "\n").encode("ascii")
    require(permutation_receipt.get("private_record_json", {}).get("bytes")
            == len(private_data)
            and permutation_receipt.get("private_record_json", {}).get("sha256")
            == hashlib.sha256(private_data).hexdigest()
            and permutation_receipt.get("score_state_json_sha256")
            == json_digest(score_state)
            and permutation_receipt.get("score_payload_sha256")
            == score_state["score_payload_sha256"],
            "ATTACK_ADAPTER_PERMUTATION_HASH",
            "Permutation control does not bind the complete score state")
    mapping_key = "actual_row_to_rid" if mapping_role == "ACTUAL" else "permuted_row_to_rid"
    row_to_rid = _sequence(permutation_private.get(mapping_key), mapping_key, nonempty=True)
    require(len(row_to_rid) == score_payload["candidate_row_count"]
            and len(set(row_to_rid)) == len(row_to_rid)
            and set(row_to_rid) <= set(rids),
            "ATTACK_ADAPTER_GROUND_TRUTH_MAPPING",
            "Private row-to-RID mapping is not a release bijection")
    group_by_position = _sequence(
        score_payload["candidate_group_id_by_position"],
        "candidate_group_id_by_position", nonempty=True)
    group_sizes = _sequence(score_payload["candidate_group_sizes"],
                            "candidate_group_sizes", nonempty=True)
    require(len(group_by_position) == len(row_to_rid)
            and all(type(value) is int and 0 <= value < len(group_sizes)
                    for value in group_by_position)
            and all(type(value) is int and value >= 1 for value in group_sizes),
            "ATTACK_ADAPTER_GROUP_MAPPING",
            "Candidate group mapping is invalid")
    require([group_by_position.count(index) for index in range(len(group_sizes))]
            == group_sizes, "ATTACK_ADAPTER_GROUP_SIZE",
            "Candidate group sizes differ from position membership")
    records = _sequence(score_payload["records"], "score records")
    require(len(records) == len(target_rids) * score_payload["draw_count"],
            "ATTACK_ADAPTER_EVALUATION_RECORDS",
            "Score records do not cover all targets and draws")
    position_by_rid = {rid: index for index, rid in enumerate(row_to_rid)}
    success_draws = [[] for _ in target_rids]
    attempted = 0
    true_in_best = 0
    ambiguity = []
    coverage_counts = {bound: 0 for bound in (1, 2, 5, 10)}
    coverage_success = {bound: 0.0 for bound in (1, 2, 5, 10)}
    for offset, record in enumerate(records):
        target_position, draw_index = divmod(offset, score_payload["draw_count"])
        exact_keys(record, {
            "target_position", "draw_index", "maximum_score_float_hex",
            "winner_group_ids", "tie_size", "attempted",
        }, "score record")
        require(record["target_position"] == target_position
                and record["draw_index"] == draw_index,
                "ATTACK_ADAPTER_SCORE_ORDER",
                "Scores must be target-major and draw-minor")
        winners = _sequence(record["winner_group_ids"], "winner_group_ids")
        require(len(set(winners)) == len(winners)
                and all(type(value) is int and 0 <= value < len(group_sizes)
                        for value in winners),
                "ATTACK_ADAPTER_WINNER_GROUPS", "Winner group IDs are invalid")
        tie_size = integer(record["tie_size"], "tie_size")
        require(tie_size == sum(group_sizes[value] for value in winners)
                and record["attempted"] is bool(winners),
                "ATTACK_ADAPTER_TIE_SIZE",
                "Winner groups and row-level tie denominator differ")
        if winners:
            attempted += 1
            ambiguity.append(tie_size)
        target_rid = target_rids[target_position]
        true_position = position_by_rid.get(target_rid)
        success = 0.0
        if true_position is not None and group_by_position[true_position] in winners:
            success = 1.0 / tie_size
            true_in_best += 1
        success_draws[target_position].append(success)
        for bound in coverage_counts:
            if 1 <= tie_size <= bound:
                coverage_counts[bound] += 1
                coverage_success[bound] += success
    total_pairs = len(records)
    target_means = [fsum(row) / len(row) for row in success_draws]
    retained_targets = sum(rid in position_by_rid for rid in target_rids)
    success_total = fsum(target_means)
    risk_all = success_total / len(target_rids)
    risk_released = (success_total / retained_targets
                     if retained_targets else None)
    private = {
        "record_schema": EVALUATION_PRIVATE_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "config_id": score_state["config_id"],
        "scenario": score_state["scenario"],
        "mapping_role": mapping_role,
        "target_ids": list(target_rids),
        "release_ids": list(row_to_rid),
        "success_draws": success_draws,
        "cluster_keys": [[source[index][attribute] for attribute in
                          ("age", "sex", "education", "marital-status")]
                         for index in target_indices],
        "visibility": "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
    }
    private_bytes = evaluation_private_bytes(private)
    receipt = {
        "record_schema": EVALUATION_RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG_SCENARIO",
        "config_id": score_state["config_id"],
        "scenario": score_state["scenario"],
        "mapping_role": mapping_role,
        "candidate_row_count": len(row_to_rid),
        "target_count": len(target_rids),
        "draw_count": score_payload["draw_count"],
        "pair_count": total_pairs,
        "retained_target_count": retained_targets,
        "attempt_count": attempted,
        "abstention_count": total_pairs - attempted,
        "true_row_in_best_count": true_in_best,
        "risk_all_estimate": risk_all,
        "risk_released_estimate": risk_released,
        "risk_estimate_interpretation": (
            "MONTE_CARLO_MEAN_OF_CONDITIONAL_TIE_SUCCESS_NOT_REALIZED_BERNOULLI"
        ),
        "coverage_by_maximum_tie_size": {
            str(bound): {
                "attempt_count": coverage_counts[bound],
                "coverage": coverage_counts[bound] / total_pairs,
                "conditional_success": (coverage_success[bound] / coverage_counts[bound]
                                        if coverage_counts[bound] else None),
            } for bound in (1, 2, 5, 10)
        },
        "score_payload_sha256_before_join": hashlib.sha256(score_data).hexdigest(),
        "score_payload_sha256_after_join": hashlib.sha256(
            _score_payload_bytes(score_payload)).hexdigest(),
        "score_state_json_sha256": json_digest(score_state),
        "target_order_sha256": target_hash,
        "row_to_rid_sha256": json_digest(row_to_rid),
        "permutation_private_record_sha256": hashlib.sha256(private_data).hexdigest(),
        "permutation_receipt_sha256": json_digest(permutation_receipt),
        "private_evaluation_json": _artifact(private_bytes),
        "scores_unchanged_during_ground_truth_join": True,
        "suppressed_target_success_exact_zero": True,
        "duplicate_rows_retained_in_tie_denominator": True,
        "numeric_risk_pass_fail_criterion": None,
        "private_values_in_receipt": False,
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
    }
    require(receipt["score_payload_sha256_before_join"]
            == receipt["score_payload_sha256_after_join"],
            "ATTACK_ADAPTER_SCORE_CHANGED",
            "Score payload changed during private evaluation")
    evaluation_receipt_bytes(receipt)
    return {"private_record": private, "bounded_receipt": receipt}


def run_attack_oracle():

    known = {"sex": "F", "education": "E", "marital-status": "M"}
    first = {
        "age": frozenset(range(30, 35)),
        "sex": frozenset({"F"}),
        "education": frozenset({"E"}),
        "marital-status": frozenset({"M"}),
    }
    second = dict(first, age=frozenset(range(35, 40)))
    scores = score_candidates(33, known, [first, second], "BASE")
    duplicate_scores = score_candidates(33, known, [first, first, second], "BASE")
    winners = select_best(duplicate_scores)
    success = 1.0 / len(winners) if 0 in winners else 0.0
    require(len(scores) == 2
            and abs(scores[0] - 0.4) <= 1e-15
            and abs(scores[1] - 0.1) <= 1e-15,
            "ATTACK_ADAPTER_ORACLE_SCORES",
            'Attack fixture did not produce 0.40/0.10')
    require(winners == (0, 1) and success == 0.5,
            "ATTACK_ADAPTER_ORACLE_TIE",
            "Duplicate-candidate oracle did not produce |B|=2 and e=0.5")
    return {
        "record_schema": ORACLE_RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_PROTOCOL_ORACLE",
        "observed_age": 33,
        "candidate_age_leaf_sets": [[30, 31, 32, 33, 34],
                                    [35, 36, 37, 38, 39]],
        "scores_float_hex": [value.hex() for value in scores],
        "scores_decimal": [format(value, ".17g") for value in scores],
        "duplicate_winner_positions": list(winners),
        "duplicate_tie_size": len(winners),
        "fractional_success": success,
        "expected_scores": [0.4, 0.1],
        "expected_duplicate_tie_size": 2,
        "expected_fractional_success": 0.5,
        "rng_invoked": False,
        "adult_data_accessed": False,
        "holdout_accessed": False,
        "main_run_authorization_granted_by_this_artifact": False,
    }
