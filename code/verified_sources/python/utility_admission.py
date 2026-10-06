from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

import model_artifact_verifier as verifier


CONFIGURATIONS = tuple("CFG%02d" % index for index in range(17))
VERIFICATION_RECEIPT_IDENTITY = MappingProxyType({
    "bytes": 2929,
    "sha256": "584249f97a5368f8c29ce8d155d8a5636417a1ed5660d3858aab82e4e9a31525",
})
MODEL_SESSION_IDENTITY = MappingProxyType({
    "bytes": 934,
    "sha256": "1fa838820d9c29a062079d073683d1c198d4d8ba16fff4c7bb259ac216d53483",
})
VERIFIER_HEAD = "95e64d9ac796942eb9a528f44f8a2c68e8736b0d"
VERIFIER_TREE = "bd19ae08be438440730d4a89d02297643b22f4f6"
FIXTURE_MAX_ROWS = 64
FIXTURE_MAX_SNAPSHOT_BYTES = 1048576
AdmissionError = verifier.VerificationError


@dataclass(frozen=True, slots=True, repr=False)
class AcceptedPredictions:
    row_ids: tuple[str, ...]
    labels: tuple[int, ...]
    release: Mapping[str, tuple[tuple[float, float], ...]]
    counterfactual: Mapping[str, tuple[tuple[float, float], ...]]
    private_identity: Mapping[str, object]
    public_identity: Mapping[str, object]
    summary: Mapping[str, object]
    mode: str


def _strict_snapshot(value, name):
    verifier.require(type(value) is bytes and bool(value),
                     "UTILITY_ADMISSION_BYTES", name + " must be immutable nonempty bytes")


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _require_complete_summary(summary):
    expected_counts = {
        "final_model_count": 33,
        "prediction_model_count": 34,
        "prediction_hash_count": 34,
        "fit_identity_count": 49,
    }
    verifier.require(type(summary) is dict, "UTILITY_ADMISSION_SUMMARY",
                     "the full verifier did not return a bounded summary")
    for key, expected in expected_counts.items():
        verifier.require(type(summary.get(key)) is int and summary[key] == expected,
                         "UTILITY_ADMISSION_SUMMARY", key + " differs")
    for key in ("all_prediction_hashes_recomputed", "baseline_constant_prior_verified"):
        verifier.require(summary.get(key) is True,
                         "UTILITY_ADMISSION_SUMMARY", key + " must be true")


def _check_verification_receipt(receipt, summary):
    verifier.require(receipt.get("record_schema") == verifier.VERIFICATION_RECEIPT_SCHEMA
                     and receipt.get("result") == "PASS"
                     and receipt.get("effective_protocol") == "v1.2.4"
                     and receipt.get("verifier_repository_head") == VERIFIER_HEAD
                     and receipt.get("verifier_repository_tree") == VERIFIER_TREE
                     and receipt.get("model_execution_repository_head") == verifier.MODEL_HEAD
                     and receipt.get("model_execution_repository_tree") == verifier.MODEL_TREE
                     and receipt.get("raw_to_model_model_stage_verified") is True,
                     "UTILITY_ADMISSION_PRIOR_RECEIPT", "prior verification identity/status differs")
    for key in ("raw_holdout_source_accessed", "model_fits_executed", "predictions_generated",
                "dummy_baseline_metrics_recomputed", "primary_utility_metrics_executed",
                "utility_bootstrap_executed", "bootstrap_indices_generated",
                "sensitivity_scenarios_executed", "rtm_impl_05_executed", "network_accessed",
                "private_payloads_copied", "private_payloads_in_public_receipt",
                "raw_to_model_end_to_end_verified", "production_pipeline_verified"):
        verifier.require(receipt.get(key) is False,
                         "UTILITY_ADMISSION_PRIOR_RECEIPT", key + " differs")
    bindings = receipt.get("bound_artifacts")
    verifier.require(type(bindings) is dict
                     and bindings.get("private_model_artifact") == summary["private_artifact"]
                     and bindings.get("public_model_receipt") == summary["public_receipt"]
                     and bindings.get("private_model_session") == dict(MODEL_SESSION_IDENTITY)
                     and bindings.get("model_execution_review_zip") == verifier.MODEL_REVIEW_ZIP,
                     "UTILITY_ADMISSION_PRIOR_RECEIPT", "prior bound artifacts differ")
    checks = receipt.get("verification_checks")
    verifier.require(type(checks) is dict, "UTILITY_ADMISSION_PRIOR_RECEIPT",
                     "prior verification checks are missing")
    for key in ("source_context_sha256", "holdout_row_ids_sha256", "holdout_labels_sha256",
                "holdout_rows", "final_model_count", "prediction_model_count",
                "fit_identity_count", "prediction_hash_count",
                "prediction_serialization_bytes_per_model", "all_prediction_hashes_recomputed",
                "baseline_constant_prior_verified"):
        verifier.require(type(checks.get(key)) is type(summary[key])
                         and checks[key] == summary[key],
                         "UTILITY_ADMISSION_PRIOR_RECEIPT", key + " differs from current recheck")


def _detach_same_snapshot(private_data, public_data, summary, mode):

    _require_complete_summary(summary)
    private = verifier._unique_json(private_data, "admitted private snapshot", canonical=True)
    verifier.require(summary["private_artifact"] == verifier._artifact(private_data)
                     and summary["public_receipt"] == verifier._artifact(public_data),
                     "UTILITY_ADMISSION_SNAPSHOT", "verifier summary does not bind these bytes")
    row_ids = tuple(private["holdout_row_ids"])
    labels = tuple(private["holdout_labels"])
    verifier.require(set(labels) == {0, 1}, "UTILITY_ADMISSION_CLASSES",
                     "both holdout classes are required")
    if mode == "fixture":
        verifier.require(2 <= len(row_ids) <= FIXTURE_MAX_ROWS,
                         "UTILITY_ADMISSION_FIXTURE", "fixture row count is outside its bounded scope")
    final_models = private["final_models"]
    frozen_predictions = {
        key: tuple(tuple(row) for row in final_models[key]["prediction_probabilities"])
        for key in sorted(verifier.FINAL_MODEL_KEYS)
    }
    raw = frozen_predictions["CFG00"]
    release = {"CFG00": raw}
    counterfactual = {"CFG00": raw}
    for cfg in CONFIGURATIONS[1:]:
        release[cfg] = frozen_predictions[cfg + "/release"]
        counterfactual[cfg] = frozen_predictions[cfg + "/counterfactual"]
    return AcceptedPredictions(
        row_ids=row_ids, labels=labels,
        release=MappingProxyType(release), counterfactual=MappingProxyType(counterfactual),
        private_identity=_freeze(summary["private_artifact"]),
        public_identity=_freeze(summary["public_receipt"]),
        summary=_freeze(summary), mode=mode,
    )


def admit_operational_bytes(private_data, public_data, session_data, verification_receipt_data):

    for data, name in ((private_data, "private snapshot"), (public_data, "public snapshot"),
                       (session_data, "model session"),
                       (verification_receipt_data, "verification receipt")):
        _strict_snapshot(data, name)
    verifier.require(verifier._artifact(session_data) == dict(MODEL_SESSION_IDENTITY),
                     "UTILITY_ADMISSION_SESSION", "model session identity differs")
    verifier._validate_model_session(session_data, operational=True)
    verifier.require(verifier._artifact(verification_receipt_data)
                     == dict(VERIFICATION_RECEIPT_IDENTITY),
                     "UTILITY_ADMISSION_PRIOR_RECEIPT", "verification receipt identity differs")
    receipt = verifier._unique_json(verification_receipt_data,
                                    "prior verification receipt", canonical=True)
    summary = verifier.verify_model_records(private_data, public_data, operational=True)
    _require_complete_summary(summary)
    _check_verification_receipt(receipt, summary)
    return _detach_same_snapshot(private_data, public_data, summary, "operational")


def admit_fixture_bytes(private_data, public_data):

    for data, name in ((private_data, "fixture private snapshot"),
                       (public_data, "fixture public snapshot")):
        _strict_snapshot(data, name)
        verifier.require(len(data) <= FIXTURE_MAX_SNAPSHOT_BYTES,
                         "UTILITY_ADMISSION_FIXTURE", "fixture snapshot exceeds its size bound")
    summary = verifier.verify_model_records(private_data, public_data, operational=False)
    return _detach_same_snapshot(private_data, public_data, summary, "fixture")
