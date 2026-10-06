import hashlib
import json
import math

from common import json_digest
import risk_consumer as risk_consumer
import risk_admission as admission

CFGS = admission.CFGS
PAIRS = (("CFG02", "CFG11"), ("CFG03", "CFG12"), ("CFG05", "CFG13"),
         ("CFG06", "CFG14"), ("CFG08", "CFG15"), ("CFG10", "CFG16"))
SCHEMA = "rtm-base-risk-bootstrap-public/1.0"
AUDIT_SCHEMA = "rtm-base-risk-bootstrap-private-audit/1.0"
REPS = 2000
FLAGS = {k: False for k in ("raw_training_source_read", "raw_holdout_source_read", "model_fits_executed",
    "predictions_generated", "attack_scores_recomputed", "new_target_sample", "new_noise", "new_permutation",
    "utility_recomputed", "sensitivity_scenarios_executed", "execution_authorization_conferred",
    "raw_to_model_end_to_end_verified", "production_pipeline_verified")}


class ComputationError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise ComputationError(code)


def conventions():
    return {"scenario": "BASE", "seed": 11005,
        "cluster_key": ["age", "sex", "education", "marital-status"],
        "cluster_order": "first_appearance_in_frozen_target_order",
        "weighting": "record_weighted_common_cluster_multiplicities",
        "interval": "percentile_type_7_linear", "percentiles": [2.5, 97.5],
        "difference_vs_raw": "R_all_CFG_c_minus_R_all_CFG00",
        "suppression_difference": "s_max_0.05_minus_s_max_0",
        "interval_interpretation": "conditional_cluster_resampling_stability",
        "population_or_design_based_confidence_interval": False, "monte_carlo_uncertainty_covered": False,
        "simultaneous_or_multiplicity_adjusted": False}


def interval(values):
    require(type(values) is list and len(values) >= 2 and all(type(v) in (int, float)
            and math.isfinite(v) for v in values), "INTERVAL_FINITE_SAMPLE")
    ordered = sorted(values)
    result = []

    for numerator in (1, 39):
        lower, remainder = divmod((len(ordered)-1)*numerator, 40)
        a, b = ordered[lower], ordered[min(lower+1, len(ordered)-1)]
        result.append(a+(b-a)*(remainder/40.0))
    return result


def audit_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("ascii")


def _clusters(keys):
    order, membership, lookup = [], [], {}
    for row in keys:
        key = tuple(row)
        if key not in lookup:
            lookup[key] = len(order)
            order.append(list(row))
        membership.append(lookup[key])
    return order, membership


def _sample(K, count, mode):
    import numpy as np
    require(type(K) is int and 1 <= K <= 5000, "CLUSTER_COUNT")
    require(type(count) is int and 2 <= count <= REPS, "REPLICATE_COUNT")
    if mode == "operational":
        require(count == REPS and np.__version__ == "2.0.2", "FROZEN_OPERATIONAL_NUMPY")
    else:
        require(mode == "synthetic" and K <= 16, "SYNTHETIC_RNG_BOUNDARY")
    rng = np.random.Generator(np.random.PCG64(11005))
    state_before = json_digest(rng.bit_generator.state)
    draws = rng.integers(0, K, size=(count, K), dtype=np.int64, endpoint=False)
    require(type(draws) is np.ndarray and draws.dtype == np.dtype("int64") and draws.shape == (count,K)
            and bool(np.all((draws >= 0) & (draws < K))), "RNG_MATRIX_SHAPE_OR_RANGE")
    hashes = [hashlib.sha256(row.astype("<i8", copy=False).tobytes(order="C")).hexdigest() for row in draws]
    matrix_hash = hashlib.sha256(draws.astype("<i8", copy=False).tobytes(order="C")).hexdigest()
    plan = [np.bincount(row, minlength=K).tolist() for row in draws]
    require(all(len(row) == K and sum(row) == K and all(type(v) is int and v >= 0 for v in row)
                for row in plan), "MULTIPLICITIES_POSTCONSTRUCTION")
    return plan, {"numpy": np.__version__, "generator_constructors": 1, "draw_calls": 1,
        "draw_count": count*K, "draw_shape": [count,K], "draw_dtype_and_hash_encoding": "little_endian_int64_C_order",
        "draw_matrix_sha256": matrix_hash, "per_replicate_draw_sha256": hashes,
        "state_before_sha256": state_before, "state_after_sha256": json_digest(rng.bit_generator.state)}


def _compute(admitted, count, *, fixed_plan=None):
    require(type(count) is int and 2 <= count <= REPS, "REPLICATE_COUNT")
    order, membership = _clusters(admitted.cluster_keys)
    if fixed_plan is None:
        plan, sampling = _sample(len(order), count, admitted.mode)
    else:
        require(admitted.mode == "synthetic" and type(fixed_plan) is list and len(fixed_plan) == count,
                "FIXED_PLAN_SYNTHETIC_ONLY")
        plan = [list(row) for row in fixed_plan]
        sampling = {"numpy": None, "generator_constructors": 0, "draw_calls": 0,
                    "draw_count": 0, "draw_shape": None, "draw_dtype_and_hash_encoding": None,
                    "draw_matrix_sha256": None, "per_replicate_draw_sha256": [],
                    "state_before_sha256": None, "state_after_sha256": None}


    result = risk_consumer.produce_bootstrap_risk(admitted.canonical_rids, admitted.target_ids,
        admitted.cluster_keys, plan, admitted.configurations, fixture_mode=admitted.mode == "synthetic")
    require(result["aggregate_validation_status"] == "PASS", "RISK_CONSUMER_REJECTED")
    payload = result["payload"]
    require(result["output_payload_json_sha256"] == json_digest(payload)
            and payload["guard_receipt"]["status"] == "PASS"
            and payload["guard_receipt"]["replicate_count"] == count
            and payload["guard_receipt"]["cluster_order_sha256"] == json_digest(order)
            and payload["guard_receipt"]["cluster_multiplicities_sha256"] == json_digest(plan), "GUARD_PAYLOAD_BINDING")
    reports = payload["aggregates"]
    values = {c: [r["R_all"] for r in reports[c]["replicates"]] for c in CFGS}
    reference = values["CFG00"]
    intervals = {"R_all": {}, "difference_vs_raw": {}, "suppression_differences": {}}
    def entry(point, sample):
        return {"point_estimate": point, "stability_interval_95": interval(sample)}
    for cfg in CFGS:
        intervals["R_all"][cfg] = entry(admitted.bindings["configurations"][cfg]["R_all"], values[cfg])
        if cfg != "CFG00":
            intervals["difference_vs_raw"][cfg] = entry(
                admitted.bindings["configurations"][cfg]["R_all"] - admitted.bindings["configurations"]["CFG00"]["R_all"],
                [a-b for a,b in zip(values[cfg], reference)])
    for no_s, s in PAIRS:
        intervals["suppression_differences"][s+"_minus_"+no_s] = entry(
            admitted.bindings["configurations"][s]["R_all"] - admitted.bindings["configurations"][no_s]["R_all"],
            [a-b for a,b in zip(values[s], values[no_s])])
    audit = {"schema": AUDIT_SCHEMA, "mode": admitted.mode, "visibility": "PRIVATE_DO_NOT_UPLOAD",
        "public_input_binding": admitted.public_identity, "canonical_cluster_order": order,
        "target_cluster_membership": membership, "cluster_multiplicities": plan,
        "sampling": sampling, "risk_consumer_result": result}
    private_data = audit_bytes(audit)
    public = {"schema": SCHEMA, "result": "PASS", "mode": admitted.mode, "conventions": conventions(),
        "configuration_count": 17, "replicates": count, "cluster_count": len(order),
        "target_count": len(admitted.target_ids), "draws_per_target": len(admitted.configurations["CFG00"]["success_draws"][0]),
        "interval_count": 39, "intervals": intervals, "public_input_binding": admitted.public_identity,
        "private_audit": admission.identity(private_data), "cluster_order_sha256": json_digest(order),
        "cluster_multiplicities_sha256": json_digest(plan), "draw_matrix_sha256": sampling["draw_matrix_sha256"],
        "generator_constructors": sampling["generator_constructors"], "rng_draw_calls": sampling["draw_calls"],
        "resampled_cluster_draws": sampling["draw_count"], "numpy": sampling["numpy"],
        "zero_retained_replicates": {c: sum(r["N_ret"] == 0 for r in reports[c]["replicates"]) for c in CFGS},
        "stored_observation_point_aggregates_revalidated": True, "point_guard_calls": 1, "bootstrap_guard_calls": 1,
        "operational_risk_bootstrap_executed": admitted.mode == "operational", "scope_boundaries": dict(FLAGS)}
    raw = admission.canonical(public)
    validate_public_bytes(raw)
    return raw, private_data


def compute_operational_from_bytes(canonical_rid_bytes, snapshots, public_bytes):
    return _compute(admission.admit_operational_bytes(canonical_rid_bytes, snapshots, public_bytes), REPS)


def compute_synthetic_from_bytes(canonical_rid_bytes, snapshots, public_bytes, *, replicates=8):
    return _compute(admission.admit_synthetic_bytes(canonical_rid_bytes, snapshots, public_bytes), replicates)


def compute_synthetic_fixed_plan(canonical_rid_bytes, snapshots, public_bytes, *, plan):
    require(type(plan) is list and 2 <= len(plan) <= 64, "SYNTHETIC_FIXED_PLAN_BOUNDARY")
    return _compute(admission.admit_synthetic_bytes(canonical_rid_bytes, snapshots, public_bytes), len(plan), fixed_plan=plan)


def _id(value):
    require(type(value) is dict and set(value) == {"bytes","sha256"} and type(value["bytes"]) is int
            and value["bytes"] > 0, "ARTIFACT_IDENTITY")
    _hash(value["sha256"])


def _hash(value):
    require(type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "SHA256")


def validate_public_bytes(raw):
    value = admission.strict_json(raw, maximum=100000)
    keys = {"schema", "result", "mode", "conventions", "configuration_count", "replicates", "cluster_count",
        "target_count", "draws_per_target", "interval_count", "intervals", "public_input_binding", "private_audit",
        "cluster_order_sha256", "cluster_multiplicities_sha256", "draw_matrix_sha256", "generator_constructors",
        "rng_draw_calls", "resampled_cluster_draws", "numpy", "zero_retained_replicates",
        "stored_observation_point_aggregates_revalidated", "point_guard_calls", "bootstrap_guard_calls",
        "operational_risk_bootstrap_executed", "scope_boundaries"}
    require(type(value) is dict and set(value) == keys and value["schema"] == SCHEMA and value["result"] == "PASS"
            and value["mode"] in ("synthetic", "operational"), "PUBLIC_SCHEMA")
    require(value["conventions"] == conventions() and value["scope_boundaries"] == FLAGS
            and all(v is False for v in value["scope_boundaries"].values()), "PUBLIC_SCOPE")
    for k in ("configuration_count", "replicates", "cluster_count", "target_count", "draws_per_target", "interval_count",
              "generator_constructors", "rng_draw_calls", "resampled_cluster_draws", "point_guard_calls", "bootstrap_guard_calls"):
        require(type(value[k]) is int and value[k] >= 0, "PUBLIC_INTEGER_COUNTS")
    n, K, nt = value["replicates"], value["cluster_count"], value["target_count"]
    require(2 <= n <= 2000 and 1 <= K <= nt and value["configuration_count"] == 17 and value["interval_count"] == 39
            and value["point_guard_calls"] == value["bootstrap_guard_calls"] == 1
            and value["stored_observation_point_aggregates_revalidated"] is True, "PUBLIC_COUNTS_OR_GUARDS")
    require(value["operational_risk_bootstrap_executed"] is (value["mode"] == "operational"), "PUBLIC_EXECUTION_MODE")
    if value["mode"] == "operational":
        require((n, nt, value["draws_per_target"]) == (2000, 5000, 30)
                and value["public_input_binding"] == admission.PUBLIC_BINDING and value["numpy"] == "2.0.2"
                and value["generator_constructors"] == value["rng_draw_calls"] == 1, "PUBLIC_OPERATIONAL_SCOPE")
    else:
        require(2 <= nt <= 16 and 1 <= value["draws_per_target"] <= 8, "PUBLIC_FIXTURE_SHAPE")
    _id(value["public_input_binding"]); _id(value["private_audit"])
    _hash(value["cluster_order_sha256"]); _hash(value["cluster_multiplicities_sha256"])
    if value["rng_draw_calls"]:
        require(value["generator_constructors"] == value["rng_draw_calls"] == 1
                and value["resampled_cluster_draws"] == n*K and type(value["numpy"]) is str, "PUBLIC_RNG_COUNTS")
        _hash(value["draw_matrix_sha256"])
    else:
        require(value["mode"] == "synthetic" and value["generator_constructors"] == value["resampled_cluster_draws"] == 0
                and value["draw_matrix_sha256"] is None and value["numpy"] is None, "PUBLIC_FIXED_PLAN_SCOPE")
    z = value["zero_retained_replicates"]
    require(type(z) is dict and set(z) == set(CFGS) and all(type(v) is int and 0 <= v <= n for v in z.values()), "ZERO_RETAINED_COUNTS")
    families = value["intervals"]
    require(type(families) is dict and set(families) == {"R_all", "difference_vs_raw", "suppression_differences"}, "INTERVAL_FAMILIES")
    for family, cfgs in [("R_all", CFGS), ("difference_vs_raw", CFGS[1:]),
                         ("suppression_differences", tuple(s+"_minus_"+c for c,s in PAIRS))]:
        require(type(families[family]) is dict and set(families[family]) == set(cfgs), "INTERVAL_CFG_KEYS")
        for item in families[family].values():
            require(type(item) is dict and set(item) == {"point_estimate", "stability_interval_95"}, "INTERVAL_ENTRY")
            bounds = item["stability_interval_95"]
            require(type(bounds) is list and len(bounds) == 2 and all(type(v) in (int,float) and math.isfinite(v)
                    and (0 if family == "R_all" else -1) <= v <= 1 for v in [item["point_estimate"], *bounds])
                    and bounds[0] <= bounds[1], "FINITE_ORDERED_INTERVAL")
    return value
