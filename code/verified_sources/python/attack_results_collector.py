from __future__ import annotations

from collections.abc import Mapping, Sequence
from math import fsum
import hashlib
import json

from common import (
    POPULATION_SIZE,
    RID_ORDER_SHA256,
    cfg_contract,
    exact_keys,
    json_digest,
    require,
)
from risk_consumer import produce_point_risk
from attack_adapter import (
    EVALUATION_PRIVATE_SCHEMA,
    EVALUATION_RECEIPT_SCHEMA,
    ORACLE_RECEIPT_SCHEMA,
    PROTOCOL_VERSION,
    SCORE_RECEIPT_SCHEMA,
    evaluation_private_bytes,
    run_attack_oracle,
)
from permutation_control import (
    RECEIPT_SCHEMA as PERMUTATION_RECEIPT_SCHEMA,
    SCORE_PHASE,
    SCORE_STATE_SCHEMA,
)


GATE_C_RECEIPT_SCHEMA = "section-12-2-gate-c-v1.2.4/1.0"
ALL_CONFIGURATIONS = tuple("CFG" + format(index, "02d") for index in range(17))
_CONFIG_KEYS = {
    "score_state", "score_receipt", "permutation_receipt",
    "actual_private", "actual_receipt",
    "permuted_private", "permuted_receipt",
}


def _sequence(value, name, *, nonempty=False):
    require(isinstance(value, Sequence)
            and not isinstance(value, (str, bytes, bytearray)),
            "GATE_C_SEQUENCE", name + " must be an ordered sequence")
    result = list(value)
    require(not nonempty or bool(result), "GATE_C_EMPTY_SEQUENCE",
            name + " must not be empty")
    return result


def _canonical(canonical_rids, fixture_mode):
    require(type(fixture_mode) is bool, "GATE_C_FIXTURE_MODE",
            "fixture_mode must be Boolean")
    rids = _sequence(canonical_rids, "canonical_rids", nonempty=True)
    require(all(type(value) is str and value.startswith("adult.data:")
                and value == value.strip() for value in rids)
            and len(set(rids)) == len(rids),
            "GATE_C_RIDS", "Canonical RIDs must be unique Adult identities")
    if not fixture_mode:
        require(len(rids) == POPULATION_SIZE, "GATE_C_OPERATIONAL_POPULATION",
                'Operational record-linkage evaluation requires 30162 canonical RIDs')
        require(hashlib.sha256(("\n".join(rids) + "\n").encode("utf-8")).hexdigest()
                == RID_ORDER_SHA256, "GATE_C_RID_IDENTITY",
                "Canonical RID order differs from the authoritative freeze")
    return rids


def _oracle(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == ORACLE_RECEIPT_SCHEMA
            and receipt.get("result") == "PASS",
            "GATE_C_ORACLE", "The exact attack oracle PASS receipt is required")
    expected = run_attack_oracle()
    require(receipt == expected, "GATE_C_ORACLE_CONTENT",
            'Attack oracle receipt differs from the specified fixture')
    return json_digest(receipt)


def _score(config_id, state, receipt, fixture_mode):
    require(isinstance(state, Mapping)
            and state.get("record_schema") == SCORE_STATE_SCHEMA
            and state.get("result") == "PASS"
            and state.get("phase") == SCORE_PHASE
            and state.get("config_id") == config_id
            and state.get("scenario") == "BASE"
            and state.get("scores_complete") is True
            and state.get("ground_truth_joined") is False
            and state.get("rid_exposed_to_scorer") is False,
            "GATE_C_SCORE_STATE",
            'Record-linkage evaluation requires the complete pre-ground-truth BASE score state')
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == SCORE_RECEIPT_SCHEMA
            and receipt.get("result") == "PASS"
            and receipt.get("config_id") == config_id
            and receipt.get("scenario") == "BASE",
            "GATE_C_SCORE_RECEIPT", "Matching BASE score receipt is required")
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG_SCENARIO"
    require(receipt.get("scope") == expected_scope
            and receipt.get("score_state_json_sha256") == json_digest(state)
            and receipt.get("score_payload_json", {}).get("sha256")
                == state.get("score_payload_sha256")
            and receipt.get("scores_complete_before_ground_truth") is True
            and receipt.get("ground_truth_joined") is False
            and receipt.get("rid_exposed_to_scorer") is False,
            "GATE_C_SCORE_BINDING", "Score state is not bound before ground truth")
    return state["score_payload_sha256"]


def _permutation(config_id, receipt, state, score_hash, fixture_mode):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == PERMUTATION_RECEIPT_SCHEMA
            and receipt.get("result") == "PASS"
            and receipt.get("config_id") == config_id,
            "GATE_C_PERMUTATION_RECEIPT",
            "Matching passing permutation-control receipt is required")
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG"
    structural = receipt.get("structural_assertions")
    require(receipt.get("scope") == expected_scope
            and isinstance(structural, Mapping) and structural
            and all(value == "PASS" for value in structural.values())
            and receipt.get("permutation_subgate") == "PASS"
            and receipt.get("score_state_json_sha256") == json_digest(state)
            and receipt.get("score_payload_sha256") == score_hash
            and receipt.get("risk_value_computed") is False
            and receipt.get("numeric_risk_pass_fail_criterion") is None
            and receipt.get("master_rng_instantiated_or_reused") is False,
            "GATE_C_PERMUTATION_STRUCTURE",
            "Permutation structural assertions or score invariance are incomplete")
    return receipt.get("private_record_json", {}).get("sha256")


def _evaluation(config_id, role, private, receipt, state, score_hash,
                permutation_private_hash, fixture_mode):
    require(isinstance(private, Mapping)
            and private.get("record_schema") == EVALUATION_PRIVATE_SCHEMA
            and private.get("config_id") == config_id
            and private.get("scenario") == "BASE"
            and private.get("mapping_role") == role,
            "GATE_C_EVALUATION_PRIVATE",
            "Matching private BASE evaluation record is required")
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == EVALUATION_RECEIPT_SCHEMA
            and receipt.get("result") == "PASS"
            and receipt.get("config_id") == config_id
            and receipt.get("scenario") == "BASE"
            and receipt.get("mapping_role") == role,
            "GATE_C_EVALUATION_RECEIPT",
            "Matching bounded BASE evaluation receipt is required")
    expected_scope = "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_CFG_SCENARIO"
    private_data = evaluation_private_bytes(private)
    require(receipt.get("scope") == expected_scope
            and receipt.get("score_payload_sha256_before_join") == score_hash
            and receipt.get("score_payload_sha256_after_join") == score_hash
            and receipt.get("score_state_json_sha256") == json_digest(state)
            and receipt.get("permutation_private_record_sha256")
                == permutation_private_hash
            and receipt.get("private_evaluation_json", {}).get("bytes")
                == len(private_data)
            and receipt.get("private_evaluation_json", {}).get("sha256")
                == hashlib.sha256(private_data).hexdigest()
            and receipt.get("scores_unchanged_during_ground_truth_join") is True
            and receipt.get("suppressed_target_success_exact_zero") is True
            and receipt.get("numeric_risk_pass_fail_criterion") is None,
            "GATE_C_EVALUATION_BINDING",
            "Evaluation does not preserve and bind the pre-join scores")
    target_ids = _sequence(private.get("target_ids"), "target_ids", nonempty=True)
    release_ids = _sequence(private.get("release_ids"), "release_ids", nonempty=True)
    success_draws = _sequence(private.get("success_draws"), "success_draws")
    require(len(target_ids) == len(success_draws) == receipt.get("target_count")
            and len(release_ids) == receipt.get("candidate_row_count")
            and len(set(target_ids)) == len(target_ids)
            and len(set(release_ids)) == len(release_ids),
            "GATE_C_EVALUATION_COUNTS",
            "Private evaluation identity or draw counts are inconsistent")
    draw_count = receipt.get("draw_count")
    require(type(draw_count) is int and draw_count >= 1
            and receipt.get("pair_count") == len(target_ids) * draw_count,
            "GATE_C_EVALUATION_SHAPE",
            "Evaluation pair count or draw count is invalid")
    checked_draws = []
    for row in success_draws:
        values = _sequence(row, "success row", nonempty=True)
        require(len(values) == draw_count
                and all(isinstance(value, (int, float))
                        and not isinstance(value, bool)
                        and 0.0 <= float(value) <= 1.0 for value in values),
                "GATE_C_SUCCESS_DRAWS",
                "Success draws must be finite values in [0,1] with fixed width")
        checked_draws.append([float(value) for value in values])
    release_set = set(release_ids)
    retained = sum(value in release_set for value in target_ids)
    numerator = fsum(fsum(row) / draw_count for row in checked_draws)
    expected_all = numerator / len(target_ids)
    expected_released = numerator / retained if retained else None
    observed_all = receipt.get("risk_all_estimate")
    observed_released = receipt.get("risk_released_estimate")
    require(isinstance(observed_all, (int, float))
            and not isinstance(observed_all, bool)
            and abs(float(observed_all) - expected_all) <= 1e-12
            and ((observed_released is None and expected_released is None)
                 or (isinstance(observed_released, (int, float))
                     and not isinstance(observed_released, bool)
                     and abs(float(observed_released) - expected_released) <= 1e-12))
            and receipt.get("retained_target_count") == retained
            and receipt.get("row_to_rid_sha256") == json_digest(release_ids),
            "GATE_C_EVALUATION_AGGREGATE",
            "Evaluation receipt differs from its private success observations")
    return {
        "target_ids": target_ids,
        "release_ids": release_ids,
        "success_draws": success_draws,
    }


def _risk_inputs(configurations, role):
    key = "actual" if role == "ACTUAL" else "permuted"
    result = {}
    common_targets = None
    for config_id, record in configurations.items():
        observed = record[key]
        if common_targets is None:
            common_targets = observed["target_ids"]
        require(observed["target_ids"] == common_targets,
                "GATE_C_TARGET_ALIGNMENT",
                "Every CFG must use the exact common target order")
        result[config_id] = {
            "target_ids": observed["target_ids"],
            "release_ids": observed["release_ids"],
            "success_draws": observed["success_draws"],
        }
    return common_targets, result


def gate_c_receipt_bytes(receipt):
    require(isinstance(receipt, Mapping)
            and receipt.get("record_schema") == GATE_C_RECEIPT_SCHEMA,
            "GATE_C_RECEIPT_SCHEMA", 'Unexpected record-linkage evaluation receipt schema')
    try:
        data = (json.dumps(receipt, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, indent=2) + "\n").encode("ascii")
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("GATE_C_RECEIPT_JSON: noncanonical receipt") from error
    require(b"adult.data:" not in data
            and b'"target_ids"' not in data
            and b'"release_ids"' not in data
            and b'"success_draws"' not in data,
            "GATE_C_PRIVATE_LEAK",
            'Record-linkage evaluation bounded receipt contains private inputs')
    return data


def collect_gate_c(*, canonical_rids, oracle_receipt, configurations,
                   fixture_mode=False):

    canonical = _canonical(canonical_rids, fixture_mode)
    oracle_hash = _oracle(oracle_receipt)
    require(isinstance(configurations, Mapping) and configurations,
            "GATE_C_CONFIGURATIONS", "At least one CFG record is required")
    supplied_ids = tuple(configurations)
    require(all(config_id in ALL_CONFIGURATIONS for config_id in supplied_ids),
            "GATE_C_CFG_ID", 'Record-linkage evaluation records must use CFG00 through CFG16')
    if not fixture_mode:
        require(supplied_ids == ALL_CONFIGURATIONS,
                "GATE_C_OPERATIONAL_MATRIX",
                'Operational record-linkage evaluation requires ordered CFG00 through CFG16')
    prepared = {}
    matrix_summary = {}
    for config_id, supplied in configurations.items():
        cfg_contract(config_id)
        exact_keys(supplied, _CONFIG_KEYS, config_id)
        state = supplied["score_state"]
        score_hash = _score(
            config_id, state, supplied["score_receipt"], fixture_mode)
        permutation_hash = _permutation(
            config_id, supplied["permutation_receipt"], state,
            score_hash, fixture_mode)
        require(type(permutation_hash) is str and len(permutation_hash) == 64,
                "GATE_C_PERMUTATION_PRIVATE_HASH",
                "Permutation receipt lacks its private-record hash")
        actual = _evaluation(
            config_id, "ACTUAL", supplied["actual_private"],
            supplied["actual_receipt"], state, score_hash,
            permutation_hash, fixture_mode)
        permuted = _evaluation(
            config_id, "PERMUTED", supplied["permuted_private"],
            supplied["permuted_receipt"], state, score_hash,
            permutation_hash, fixture_mode)
        require(actual["target_ids"] == permuted["target_ids"]
                and set(actual["release_ids"]) == set(permuted["release_ids"]),
                "GATE_C_GROUND_TRUTH_ONLY",
                "Negative control must change only the private row-to-RID assignment")
        prepared[config_id] = {"actual": actual, "permuted": permuted}
        matrix_summary[config_id] = {
            "score_payload_sha256": score_hash,
            "score_state_json_sha256": json_digest(state),
            "permutation_receipt_sha256": json_digest(
                supplied["permutation_receipt"]),
            "actual_evaluation_receipt_sha256": json_digest(
                supplied["actual_receipt"]),
            "permuted_evaluation_receipt_sha256": json_digest(
                supplied["permuted_receipt"]),
            "candidate_row_count": state["candidate_row_count"],
            "target_count": state["target_count"],
            "draw_count": state["draw_count"],
            "structural_subgate": "PASS",
        }

    target_ids, actual_inputs = _risk_inputs(prepared, "ACTUAL")
    permuted_targets, permuted_inputs = _risk_inputs(prepared, "PERMUTED")
    require(target_ids == permuted_targets, "GATE_C_TARGET_ALIGNMENT",
            "Actual and permuted evaluations use different targets")
    actual_risk = produce_point_risk(
        canonical, target_ids, actual_inputs, fixture_mode=fixture_mode)
    permuted_risk = produce_point_risk(
        canonical, target_ids, permuted_inputs, fixture_mode=fixture_mode)
    actual_aggregates = actual_risk["payload"]["aggregates"]
    permuted_aggregates = permuted_risk["payload"]["aggregates"]
    descriptive = {}
    for config_id in configurations:
        descriptive[config_id] = {
            "actual_R_all": actual_aggregates[config_id]["R_all"],
            "actual_R_released": actual_aggregates[config_id]["R_released"],
            "permuted_R_all": permuted_aggregates[config_id]["R_all"],
            "permuted_R_released": permuted_aggregates[config_id]["R_released"],
            "uniform_R_all": actual_aggregates[config_id]["uniform_R_all"],
            "uniform_R_released": actual_aggregates[config_id]["uniform_R_released"],
            "numeric_acceptance_applied": False,
        }
    receipt = {
        "record_schema": GATE_C_RECEIPT_SCHEMA,
        "effective_protocol": PROTOCOL_VERSION,
        "result": "PASS",
        "scope": "SYNTHETIC_FIXTURE" if fixture_mode else "OPERATIONAL_FULL_MATRIX",
        "gate_c_status": ("SYNTHETIC_LOGIC_PASS_OPERATIONAL_PENDING"
                          if fixture_mode else "PASS"),
        "configuration_count": len(configurations),
        "configurations": list(configurations),
        "oracle_receipt_sha256": oracle_hash,
        "oracle": "PASS",
        "score_before_ground_truth": "PASS",
        "permutation_structural_assertions": "PASS",
        "score_invariance_actual_and_permuted": "PASS",
        "ground_truth_only_negative_control": "PASS",
        "point_risk_guard_actual": "PASS",
        "point_risk_guard_permuted": "PASS",
        "matrix_bindings": matrix_summary,
        "descriptive_risk_values": descriptive,
        "actual_point_risk_payload_sha256": actual_risk["output_payload_json_sha256"],
        "permuted_point_risk_payload_sha256": permuted_risk["output_payload_json_sha256"],
        "target_order_sha256": json_digest(target_ids),
        "canonical_rid_order_sha256": hashlib.sha256(
            ("\n".join(canonical) + "\n").encode("utf-8")).hexdigest(),
        "cfg00_numeric_acceptance_range": None,
        "permutation_numeric_acceptance_range": None,
        "risk_values_descriptive_not_gate_thresholds": True,
        "private_values_in_receipt": False,
        "main_run_authorization_granted_by_this_artifact": False,
        "holdout_accessed": False,
        "model_fit_executed": False,
        "raw_to_model_end_to_end_verified": False,
        "production_pipeline_verified": False,
    }
    gate_c_receipt_bytes(receipt)
    return receipt
