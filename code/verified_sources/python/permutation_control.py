from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
import hashlib
import importlib
import json
import re

from common import (
    POPULATION_SIZE,
    RID_ORDER_SHA256,
    cfg_contract,
    exact_keys,
    integer,
    json_digest,
    require,
)


PROTOCOL_VERSION = "v1.2.4"
NUMPY_VERSION = "2.0.2"
PERMUTATION_SEED = 11007
MASTER_PERMUTATION_SEED = 11002
MASTER_PERMUTATION_SHA256 = (
    "4e1f8403536e0016645e42663763fd8551ca2f6babdd8185a1f30b7a6a017066"
)
SCORE_STATE_SCHEMA = "attack-score-state-v1.2.4/1.0"
RAW_CONTROL_SCHEMA = "cfg00-raw-release-control-v1.2.4/1.0"
PRIVATE_SCHEMA = "permutation-negative-control-private-v1.2.4/1.0"
RECEIPT_SCHEMA = "permutation-negative-control-receipt-v1.2.4/1.0"
SCORE_PHASE = "COMPLETE_BEFORE_GROUND_TRUTH_ASSIGNMENT"
SCORE_SCENARIO = "BASE"
OPERATIONAL_TARGET_COUNT = 5000
OPERATIONAL_DRAW_COUNT = 30
SOURCE_INPUT_SHA256 = "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5"

_RID = re.compile(r"adult\.data:([1-9][0-9]*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCORE_KEYS = {
    "record_schema",
    "result",
    "phase",
    "config_id",
    "scenario",
    "candidate_row_count",
    "target_count",
    "draw_count",
    "score_record_count",
    "candidate_order_sha256",
    "target_order_sha256",
    "score_payload_sha256",
    "scores_complete",
    "ground_truth_joined",
    "rid_exposed_to_scorer",
}


def _sequence(value, name, *, nonempty=False):
    require(isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray)),
            "PERMUTATION_SEQUENCE", name + " must be an ordered sequence")
    result = list(value)
    require(not nonempty or bool(result), "PERMUTATION_EMPTY_SEQUENCE",
            name + " must not be empty")
    return result


def _sha256(value, name):
    require(type(value) is str and _SHA256.fullmatch(value) is not None,
            "PERMUTATION_SHA256", name + " must be a lowercase SHA-256")
    return value


def _line_bytes(values, *, encoding="ascii"):
    return ("\n".join(str(value) for value in values) + "\n").encode(encoding)


def _artifact(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _cfg_numeric_id(config_id):
    cfg_contract(config_id)
    numeric = int(config_id[3:])
    require(config_id == "CFG" + format(numeric, "02d") and 0 <= numeric <= 16,
            "PERMUTATION_CFG_ID", "CFG numeric suffix is not canonical")
    return numeric


def _population(canonical_rids, master_permutation, is_outlier, fixture_mode):
    require(type(fixture_mode) is bool, "PERMUTATION_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    rids = _sequence(canonical_rids, "canonical_rids", nonempty=True)
    require(all(type(value) is str and value == value.strip() and value
                and not any(mark in value for mark in ("\0", "\r", "\n", "\t"))
                for value in rids),
            "PERMUTATION_RID_TYPE", "RIDs must be nonempty, trimmed safe strings")
    require(len(set(rids)) == len(rids), "PERMUTATION_RID_BIJECTION",
            "Canonical RIDs must be unique")

    permutation = _sequence(master_permutation, "master_permutation", nonempty=True)
    require(len(permutation) == len(rids)
            and all(type(value) is int for value in permutation)
            and sorted(permutation) == list(range(len(rids))),
            "PERMUTATION_MASTER_BIJECTION",
            "Master permutation must be a bijection of the canonical indices")
    flags = _sequence(is_outlier, "is_outlier", nonempty=True)
    require(len(flags) == len(rids) and all(type(value) is bool for value in flags),
            "PERMUTATION_OUTLIER_ALIGNMENT",
            "Outlier mask must contain one exact Boolean per canonical row")
    require(any(not value for value in flags), "PERMUTATION_EMPTY_RELEASE",
            "At least one retained row is required")

    if not fixture_mode:
        require(len(rids) == POPULATION_SIZE, "PERMUTATION_OPERATIONAL_SHAPE",
                "Operational control requires the complete 30162-row population")
        physical_lines = []
        for value in rids:
            match = _RID.fullmatch(value)
            require(match is not None, "PERMUTATION_OPERATIONAL_RID",
                    "Operational RIDs must use adult.data:<physical-line>")
            physical_lines.append(int(match.group(1)))
        require(all(left < right for left, right in zip(physical_lines, physical_lines[1:])),
                "PERMUTATION_OPERATIONAL_RID_ORDER",
                "Operational RIDs must preserve increasing physical-line order")
        require(hashlib.sha256(_line_bytes(rids, encoding="utf-8")).hexdigest()
                == RID_ORDER_SHA256,
                "PERMUTATION_RID_IDENTITY",
                "Canonical RID order differs from the authoritative freeze")
        require(hashlib.sha256(_line_bytes(permutation)).hexdigest()
                == MASTER_PERMUTATION_SHA256,
                "PERMUTATION_MASTER_IDENTITY",
                "Master Pi differs from the authoritative freeze")
    return rids, permutation, flags


def _release_gate(gate_b_receipt, config_id, population_count, retained_count, fixture_mode):
    require(isinstance(gate_b_receipt, Mapping), "PERMUTATION_GATE_B_RECORD",
            "Release-validation receipt must be a mapping")
    if config_id == "CFG00":
        required = {
            "record_schema", "result", "config_id", "scope", "n_input",
            "n_retained", "outlier_count", "outlier_source",
            "source_input_sha256", "release_output_sha256",
            "private_rows_in_receipt",
        }
        require(required <= set(gate_b_receipt), "PERMUTATION_RAW_CONTROL_KEYS",
                "CFG00 raw-control receipt lacks a required binding field")
        expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_RAW_CONTROL"
        require(gate_b_receipt["record_schema"] == RAW_CONTROL_SCHEMA
                and gate_b_receipt["result"] == "PASS"
                and gate_b_receipt["config_id"] == "CFG00"
                and gate_b_receipt["scope"] == expected_scope,
                "PERMUTATION_RAW_CONTROL_BINDING",
                "CFG00 raw-control PASS/config/scope binding failed")
        require(type(gate_b_receipt["n_input"]) is int
                and gate_b_receipt["n_input"] == population_count
                and type(gate_b_receipt["n_retained"]) is int
                and gate_b_receipt["n_retained"] == retained_count == population_count
                and gate_b_receipt["outlier_count"] == 0
                and gate_b_receipt["outlier_source"] == "NOT_APPLICABLE_RAW_CONTROL",
                "PERMUTATION_RAW_CONTROL_COUNTS",
                "CFG00 must retain the complete raw-control population")
        source_hash = _sha256(gate_b_receipt["source_input_sha256"],
                              "CFG00 source input")
        if not fixture_mode:
            require(source_hash == SOURCE_INPUT_SHA256,
                    "PERMUTATION_RAW_SOURCE_IDENTITY",
                    "CFG00 source differs from the frozen Adult training table")
        _sha256(gate_b_receipt["release_output_sha256"], "CFG00 release output")
        require(gate_b_receipt["private_rows_in_receipt"] is False,
                "PERMUTATION_RAW_CONTROL_PRIVATE",
                "CFG00 release receipt must not contain private rows")
        return {
            "schema": RAW_CONTROL_SCHEMA,
            "release_output_sha256": gate_b_receipt["release_output_sha256"],
            "producer_report_sha256": None,
        }

    required = {
        "record_schema", "result", "config_id", "scope", "n_input",
        "n_retained", "outlier_count", "outlier_source",
        "full_output_sha256", "java_report_sha256", "private_rows_in_receipt",
    }
    require(required <= set(gate_b_receipt), "PERMUTATION_GATE_B_KEYS",
            'Anonymization validation receipt lacks a required binding field')
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_OUTPUT"
    require(gate_b_receipt["record_schema"] == "section-12-1-gate-b-v1.2.4/1.0"
            and gate_b_receipt["result"] == "PASS"
            and gate_b_receipt["config_id"] == config_id
            and gate_b_receipt["scope"] == expected_scope,
            "PERMUTATION_GATE_B_BINDING",
            'Anonymization validation PASS/config/scope binding failed')
    require(type(gate_b_receipt["n_input"]) is int
            and gate_b_receipt["n_input"] == population_count
            and type(gate_b_receipt["n_retained"]) is int
            and gate_b_receipt["n_retained"] == retained_count
            and type(gate_b_receipt["outlier_count"]) is int
            and gate_b_receipt["outlier_count"] == population_count - retained_count,
            "PERMUTATION_GATE_B_COUNTS",
            'Anonymization validation counts do not bind the supplied release mask')
    require(gate_b_receipt["outlier_source"] == "captured_DataHandle.isOutlier"
            and gate_b_receipt["private_rows_in_receipt"] is False,
            "PERMUTATION_GATE_B_OUTLIER_SOURCE",
            'Anonymization validation must use DataHandle.isOutlier and a bounded receipt')
    _sha256(gate_b_receipt["full_output_sha256"], 'Anonymization validation full output')
    _sha256(gate_b_receipt["java_report_sha256"], 'Anonymization validation Java report')
    return {
        "schema": "section-12-1-gate-b-v1.2.4/1.0",
        "release_output_sha256": gate_b_receipt["full_output_sha256"],
        "producer_report_sha256": gate_b_receipt["java_report_sha256"],
    }


def _score_state(score_state, config_id, retained_count, fixture_mode):
    exact_keys(score_state, _SCORE_KEYS, "score_state")
    require(score_state["record_schema"] == SCORE_STATE_SCHEMA
            and score_state["result"] == "PASS"
            and score_state["phase"] == SCORE_PHASE
            and score_state["config_id"] == config_id
            and score_state["scenario"] == SCORE_SCENARIO,
            "PERMUTATION_SCORE_BINDING",
            "The complete pre-ground-truth BASE score state is required")
    require(type(score_state["candidate_row_count"]) is int
            and score_state["candidate_row_count"] == retained_count,
            "PERMUTATION_SCORE_CANDIDATES",
            "Score-state candidate count differs from retained output rows")
    target_count = integer(score_state["target_count"], "score_state.target_count", 1)
    draw_count = integer(score_state["draw_count"], "score_state.draw_count", 1)
    require(type(score_state["score_record_count"]) is int
            and score_state["score_record_count"] == target_count * draw_count,
            "PERMUTATION_SCORE_RECORD_COUNT",
            "Score state must contain one target-major/draw-minor record per pair")
    if not fixture_mode:
        require(target_count == OPERATIONAL_TARGET_COUNT
                and draw_count == OPERATIONAL_DRAW_COUNT,
                "PERMUTATION_SCORE_OPERATIONAL_SHAPE",
                "Operational BASE score state requires 5000 targets x 30 draws")
    for key in ("candidate_order_sha256", "target_order_sha256", "score_payload_sha256"):
        _sha256(score_state[key], "score_state." + key)
    require(score_state["scores_complete"] is True
            and score_state["ground_truth_joined"] is False
            and score_state["rid_exposed_to_scorer"] is False,
            "PERMUTATION_SCORE_SEPARATION",
            "Scores must be complete before any private ground-truth or RID join")


def _numpy(numpy_module, fixture_mode):
    module = numpy_module
    if module is None:
        module = importlib.import_module("numpy")
    require(hasattr(module, "random"), "PERMUTATION_NUMPY_API",
            "NumPy random API is unavailable")
    if not fixture_mode:
        require(getattr(module, "__version__", None) == NUMPY_VERSION,
                "PERMUTATION_NUMPY_VERSION",
                "Operational control requires pinned NumPy 2.0.2")
    return module


def _generate_sigma(numpy_module, config_numeric_id, retained_count):
    entropy = [PERMUTATION_SEED, config_numeric_id]
    require(MASTER_PERMUTATION_SEED not in entropy,
            "PERMUTATION_MASTER_STREAM_REUSE",
            "The 11002 master-permutation stream must not enter sigma derivation")
    seed_sequence = numpy_module.random.SeedSequence(entropy)
    bit_generator = numpy_module.random.PCG64(seed_sequence)
    generator = numpy_module.random.Generator(bit_generator)
    raw = generator.permutation(retained_count)
    try:
        values = raw.tolist()
    except AttributeError:
        values = list(raw)
    result = [int(value) for value in values]
    require(all(type(value) is int for value in result)
            and sorted(result) == list(range(retained_count)),
            "PERMUTATION_SIGMA_BIJECTION",
            "Generated sigma_c is not a complete index bijection")
    return result


def _mapping_bytes(private_record):
    lines = [
        "published_position\tsource_index\tactual_rid\t"
        "permutation_index\tpermuted_rid"
    ]
    for position, (source_index, actual_rid, permutation_index, permuted_rid) in enumerate(
        zip(
            private_record["published_source_indices"],
            private_record["actual_row_to_rid"],
            private_record["sigma_c"],
            private_record["permuted_row_to_rid"],
        )
    ):
        lines.append("\t".join((
            str(position), str(source_index), actual_rid,
            str(permutation_index), permuted_rid,
        )))
    return ("\n".join(lines) + "\n").encode("utf-8")


def private_record_bytes(private_record):

    require(isinstance(private_record, Mapping)
            and private_record.get("record_schema") == PRIVATE_SCHEMA,
            "PERMUTATION_PRIVATE_SCHEMA", "Unexpected private-record schema")
    try:
        return (json.dumps(private_record, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, indent=2) + "\n").encode("ascii")
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("PERMUTATION_PRIVATE_JSON: private record is not canonical JSON") from error


def bounded_receipt_bytes(receipt):

    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == RECEIPT_SCHEMA,
            "PERMUTATION_RECEIPT_SCHEMA", "Unexpected bounded-receipt schema")
    payload = (json.dumps(receipt, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, indent=2) + "\n").encode("ascii")
    require(b"adult.data:" not in payload
            and b'"sigma_c"' not in payload
            and b'"actual_row_to_rid"' not in payload
            and b'"permuted_row_to_rid"' not in payload,
            "PERMUTATION_RECEIPT_PRIVATE_LEAK",
            "Bounded receipt contains a private RID or vector")
    return payload


def prepare_permutation_control(*, config_id, canonical_rids, master_permutation,
                                is_outlier, gate_b_receipt, score_state,
                                fixture_mode=False, numpy_module=None):

    numeric_id = _cfg_numeric_id(config_id)
    rids, master, flags = _population(
        canonical_rids, master_permutation, is_outlier, fixture_mode)
    retained_count = sum(not value for value in flags)
    release_binding = _release_gate(
        gate_b_receipt, config_id, len(rids), retained_count, fixture_mode)
    _score_state(score_state, config_id, retained_count, fixture_mode)

    supplied_snapshot = deepcopy({
        "canonical_rids": rids,
        "master_permutation": master,
        "is_outlier": flags,
        "gate_b_receipt": gate_b_receipt,
        "score_state": score_state,
    })
    supplied_digest = json_digest(supplied_snapshot)
    score_digest_before = json_digest(score_state)

    published_indices = [index for index in master if not flags[index]]
    retained_rids = [rid for rid, flag in zip(rids, flags) if not flag]
    actual_rids = [rids[index] for index in published_indices]
    require(len(published_indices) == retained_count
            and set(actual_rids) == set(retained_rids)
            and len(set(actual_rids)) == retained_count,
            "PERMUTATION_ACTUAL_MAPPING_BIJECTION",
            "Pi restricted to retained indices is not a release bijection")

    module = _numpy(numpy_module, fixture_mode)
    sigma = _generate_sigma(module, numeric_id, retained_count)
    regenerated = _generate_sigma(module, numeric_id, retained_count)
    require(sigma == regenerated, "PERMUTATION_REPRODUCIBILITY",
            "Fresh regeneration from the same SeedSequence differs")
    permuted_rids = [retained_rids[index] for index in sigma]
    require(len(set(permuted_rids)) == retained_count
            and set(permuted_rids) == set(retained_rids),
            "PERMUTATION_CONTROL_MAPPING_BIJECTION",
            "Permuted row-to-rid labels are not a complete V_c bijection")

    fixed_points = sum(index == value for index, value in enumerate(sigma))
    unchanged_associations = sum(actual == permuted
                                 for actual, permuted in zip(actual_rids, permuted_rids))
    private_record = {
        "record_schema": PRIVATE_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "config_id": config_id,
        "cfg_numeric_id": numeric_id,
        "seed_derivation": {
            "seed_sequence_entropy": [PERMUTATION_SEED, numeric_id],
            "bit_generator": "numpy.random.PCG64",
            "generator": "numpy.random.Generator",
            "operation": "permutation(n_c)",
            "numpy_version": getattr(module, "__version__", "test-double"),
            "master_seed_11002_instantiated": False,
        },
        "canonical_rid_count": len(rids),
        "retained_count": retained_count,
        "canonical_rid_order_sha256": hashlib.sha256(
            _line_bytes(rids, encoding="utf-8")).hexdigest(),
        "master_permutation_sha256": hashlib.sha256(_line_bytes(master)).hexdigest(),
        "outlier_mask_sha256": hashlib.sha256(
            _line_bytes([int(value) for value in flags])).hexdigest(),
        "score_state_sha256_before_assignment": score_digest_before,
        "published_source_indices": published_indices,
        "retained_canonical_rids": retained_rids,
        "actual_row_to_rid": actual_rids,
        "sigma_c": sigma,
        "permuted_row_to_rid": permuted_rids,
        "sigma_index_fixed_point_count": fixed_points,
        "unchanged_row_to_rid_association_count": unchanged_associations,
        "risk_value": None,
        "risk_pass_fail_threshold": None,
        "visibility": "PRIVATE_DO_NOT_STAGE_OR_PUBLISH",
    }
    mapping_artifact = _artifact(_mapping_bytes(private_record))
    private_artifact = _artifact(private_record_bytes(private_record))

    require(json_digest(score_state) == score_digest_before,
            "PERMUTATION_SCORE_MUTATION",
            "Score state changed while the private mapping was assigned")
    require(json_digest(supplied_snapshot) == supplied_digest,
            "PERMUTATION_INPUT_MUTATION",
            'A supplied anonymization validation, score or population artifact changed')

    receipt = {
        "record_schema": RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG",
        "config_id": config_id,
        "cfg_numeric_id": numeric_id,
        "n_input": len(rids),
        "n_c": retained_count,
        "outlier_count": len(rids) - retained_count,
        "seed_derivation": "Generator(PCG64(SeedSequence([11007,cfg_numeric_id])))",
        "seed_sequence_entropy": [PERMUTATION_SEED, numeric_id],
        "master_permutation_rng_stream": MASTER_PERMUTATION_SEED,
        "master_rng_instantiated_or_reused": False,
        "fresh_sigma_generation_count": 2,
        "sigma_index_fixed_point_count": fixed_points,
        "unchanged_row_to_rid_association_count": unchanged_associations,
        "canonical_rid_order_sha256": private_record["canonical_rid_order_sha256"],
        "master_permutation_sha256": private_record["master_permutation_sha256"],
        "outlier_mask_sha256": private_record["outlier_mask_sha256"],
        "release_validation_schema": release_binding["schema"],
        "release_output_sha256": release_binding["release_output_sha256"],
        "producer_report_sha256": release_binding["producer_report_sha256"],
        "release_validation_receipt_json_sha256": json_digest(gate_b_receipt),
        "score_state_json_sha256": score_digest_before,
        "score_payload_sha256": score_state["score_payload_sha256"],
        "candidate_order_sha256": score_state["candidate_order_sha256"],
        "target_order_sha256": score_state["target_order_sha256"],
        "sigma_c_sha256": hashlib.sha256(_line_bytes(sigma)).hexdigest(),
        "full_mapping_tsv": mapping_artifact,
        "private_record_json": private_artifact,
        "structural_assertions": {
            "gate_b_or_cfg00_raw_control_pass_precedes_sigma": "PASS",
            "scores_complete_before_assignment": "PASS",
            "separate_seedsequence_from_11002": "PASS",
            "sigma_reproducible": "PASS",
            "sigma_bijection": "PASS",
            "actual_mapping_bijection": "PASS",
            "permuted_mapping_bijection": "PASS",
            "published_order_is_pi_restricted_to_boolean_retained_mask": "PASS",
            "score_state_unchanged_during_assignment": "PASS",
            "fixed_points_counted_without_numeric_acceptance_rule": "PASS",
            "full_private_logging_bound_by_hash": "PASS",
        },
        "private_vectors_in_receipt": False,
        "risk_value_computed": False,
        "numeric_risk_pass_fail_criterion": None,
        "permutation_subgate": "PASS",
        "gate_c_status": "PENDING_ATTACK_ORACLE_AND_OPERATIONAL_MATRIX_AGGREGATION",
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
    }
    bounded_receipt_bytes(receipt)
    return {"private_record": private_record, "bounded_receipt": receipt}
