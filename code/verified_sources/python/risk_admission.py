from dataclasses import dataclass
from math import fsum, isfinite
import hashlib
import json
import re

from common import json_digest
from risk_metrics import assert_point_risk

CFGS = tuple(f"CFG{i:02}" for i in range(17))
PUBLIC_BINDING = {"bytes": 10405, "sha256": "fc8dc5aebbd2915be17ee6939e1983111680b6e101d669effd2b4e512d6c7c62"}
PRIVATE_SCHEMA = "attack-evaluation-private-v1.2.4/1.0"
PUBLIC_SCHEMA = "rtm-risk-bootstrap-public-input-bindings/1.0"
PRIVATE_KEYS = {"record_schema", "effective_protocol", "config_id", "scenario", "mapping_role",
                "target_ids", "release_ids", "success_draws", "cluster_keys", "visibility"}


class AdmissionError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise AdmissionError(code)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")


def strict_json(raw, *, maximum=12000000):
    require(type(raw) is bytes and 0 < len(raw) <= maximum, "IMMUTABLE_BOUNDED_BYTES_REQUIRED")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    def invalid(_):
        raise AdmissionError("NONFINITE_JSON")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs, parse_constant=invalid)
        require(canonical(value) == raw, "CANONICAL_JSON_BYTES_REQUIRED")
        return value
    except AdmissionError:
        raise
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise AdmissionError("INVALID_JSON") from None


def _ids(value):
    require(type(value) is list and value and all(type(v) is str and v and v == v.strip()
            and "\n" not in v and "\r" not in v for v in value), "INVALID_ID_LIST")
    require(len(value) == len(set(value)), "DUPLICATE_ID")
    return value


def _hash_lines(value):
    return hashlib.sha256(("\n".join(value) + "\n").encode("utf-8")).hexdigest()


@dataclass(frozen=True, repr=False, slots=True)
class _Admitted:
    canonical_rids: list
    target_ids: list
    cluster_keys: list
    configurations: dict
    point_reports: dict
    bindings: dict
    public_identity: dict
    mode: str


def _admit(canonical_rid_bytes, snapshots, public_bytes, *, fixture):
    require(type(fixture) is bool, "FIXTURE_MODE_TYPE")
    require(type(canonical_rid_bytes) is bytes and 0 < len(canonical_rid_bytes) <= 600000,
            "CANONICAL_RID_BYTES")
    require(type(snapshots) is dict and tuple(snapshots) == CFGS
            and all(type(v) is bytes for v in snapshots.values()), "ORDERED_EXACT_CFG_SNAPSHOTS")
    require(type(public_bytes) is bytes and 0 < len(public_bytes) <= 250000, "PUBLIC_BINDING_BYTES")
    if not fixture:
        require(identity(public_bytes) == PUBLIC_BINDING, "OPERATIONAL_PUBLIC_BINDING")
    bound = strict_json(public_bytes, maximum=250000)
    require(type(bound) is dict and set(bound) == {"schema", "synthetic_fixture", "canonical_rids",
            "population_count", "target_count", "draw_count", "target_rid_order_sha256",
            "collector_target_order_sha256", "gate_c_independent_receipt", "gate_c_receipt", "configurations"},
            "PUBLIC_BINDING_SCHEMA")
    require(bound["schema"] == PUBLIC_SCHEMA and bound["synthetic_fixture"] is fixture
            and type(bound["configurations"]) is dict and tuple(bound["configurations"]) == CFGS,
            "PUBLIC_BINDING_SCOPE")
    require(identity(canonical_rid_bytes) == bound["canonical_rids"], "CANONICAL_RID_IDENTITY")
    try:
        canonical_rids = _ids(canonical_rid_bytes.decode("utf-8").splitlines())
    except UnicodeError:
        raise AdmissionError("CANONICAL_RID_ENCODING") from None
    require(("\n".join(canonical_rids) + "\n").encode("utf-8") == canonical_rid_bytes, "CANONICAL_RID_SERIALIZATION")
    n, nt, nd = (bound[k] for k in ("population_count", "target_count", "draw_count"))
    require(all(type(v) is int for v in (n, nt, nd)) and len(canonical_rids) == n, "POPULATION_COUNTS")
    if fixture:
        require(2 <= n <= 64 and 2 <= nt <= min(n, 16) and 1 <= nd <= 8
                and all(v.startswith("synthetic:") for v in canonical_rids)
                and all(len(v) <= 100000 for v in snapshots.values()), "FIXTURE_BOUNDARY")
    else:
        require((n, nt, nd) == (30162, 5000, 30), "OPERATIONAL_SHAPE")
    configs, reports, common_targets, common_keys = {}, {}, None, None
    for cfg in CFGS:
        raw, expected = snapshots[cfg], bound["configurations"][cfg]
        require(type(expected) is dict and set(expected) == {"private_identity", "release_count", "retained_target_count",
                "release_rid_order_sha256", "R_all", "R_released", "evaluation_receipt"}, "CFG_PUBLIC_BINDING_SCHEMA")
        require(identity(raw) == expected["private_identity"], "PRIVATE_SNAPSHOT_HASH:" + cfg)
        data = strict_json(raw)
        require(type(data) is dict and set(data) == PRIVATE_KEYS and data["record_schema"] == PRIVATE_SCHEMA
                and data["effective_protocol"] == "v1.2.4" and data["config_id"] == cfg
                and data["scenario"] == "BASE" and data["mapping_role"] == "ACTUAL"
                and data["visibility"] == "PRIVATE_DO_NOT_STAGE_OR_PUBLISH", "PRIVATE_SCHEMA_OR_ROLE:" + cfg)
        targets, released = _ids(data["target_ids"]), _ids(data["release_ids"])
        require(len(targets) == nt and len(released) == expected["release_count"]
                and json_digest(released) == expected["release_rid_order_sha256"], "RELEASE_TARGET_COUNTS:" + cfg)
        require(_hash_lines(targets) == bound["target_rid_order_sha256"]
                and json_digest(targets) == bound["collector_target_order_sha256"], "TARGET_HASH_REPRESENTATIONS:" + cfg)
        keys = data["cluster_keys"]
        require(type(keys) is list and len(keys) == nt, "CLUSTER_ALIGNMENT:" + cfg)
        for row in keys:
            require(type(row) is list and len(row) == 4 and all(type(v) is str and v and v == v.strip()
                    and len(v) <= 256 and "\n" not in v and "\r" not in v for v in row), "RAW_CLUSTER_FIELDS")
            require(re.fullmatch(r"(?:0|[1-9][0-9]*)", row[0]) is not None, "RAW_CLUSTER_AGE")
        if common_targets is None:
            common_targets, common_keys = targets, keys
        require(targets == common_targets and keys == common_keys, "COMMON_FROZEN_CLUSTER_KEYS:" + cfg)
        draws = data["success_draws"]
        require(type(draws) is list and len(draws) == nt and all(type(row) is list and len(row) == nd for row in draws),
                "SUCCESS_DRAW_SHAPE:" + cfg)
        require(all(type(v) in (int, float) and isfinite(v) and 0 <= v <= 1 for row in draws for v in row),
                "SUCCESS_VALUE:" + cfg)
        released_set = set(released)
        retained = sum(t in released_set for t in targets)
        require(retained == expected["retained_target_count"], "RETAINED_TARGET_COUNT:" + cfg)
        total = fsum(fsum(row) / nd for row in draws)
        r_all, r_released = total / nt, total / retained if retained else None
        require(type(expected["R_all"]) in (int, float) and abs(r_all - expected["R_all"]) <= 1e-12
                and ((r_released is None and expected["R_released"] is None) or
                     (r_released is not None and type(expected["R_released"]) in (int, float)
                      and abs(r_released - expected["R_released"]) <= 1e-12)), "STORED_POINT_AGGREGATE_BINDING:" + cfg)
        report = dict(n_c=len(released), n_ret=retained, R_all=r_all, R_released=r_released,
            uniform_R_all=retained/(nt*len(released)), uniform_R_released=1/len(released),
            execution_anomaly=retained == 0, identity_status="PASS" if retained else "NOT_EVALUATED")
        configs[cfg] = {k: data[k] for k in ("target_ids", "release_ids", "success_draws")}
        reports[cfg] = report
    guarded = assert_point_risk(canonical_rids, common_targets,
        {c: dict(configs[c], reported=reports[c]) for c in CFGS}, fixture_mode=fixture)
    require(guarded["status"] == "PASS" and guarded["scope"] ==
            ("SYNTHETIC_FIXTURE" if fixture else "SUPPLIED_OPERATIONAL_OBSERVATIONS"), "POINT_GUARD_REJECTED")
    return _Admitted(canonical_rids, common_targets, common_keys, configs, reports,
                     bound, identity(public_bytes), "synthetic" if fixture else "operational")


def admit_operational_bytes(canonical_rid_bytes, snapshots, public_bytes):
    return _admit(canonical_rid_bytes, snapshots, public_bytes, fixture=False)


def admit_synthetic_bytes(canonical_rid_bytes, snapshots, public_bytes):
    return _admit(canonical_rid_bytes, snapshots, public_bytes, fixture=True)
