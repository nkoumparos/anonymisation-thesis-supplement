from collections.abc import Mapping, Sequence
from math import floor, fsum
import hashlib
import re

from common import (
    RID_ORDER_SHA256, cfg_contract, exact_keys, integer, json_digest, number, require,
)

_TOLERANCE = 1e-12
_POINT_KEYS = {
    'n_c', 'n_ret', 'R_all', 'R_released', 'uniform_R_all',
    'uniform_R_released', 'execution_anomaly', 'identity_status',
}
_REPLICATE_KEYS = {
    'N_b', 'N_ret', 'R_all', 'R_released', 'uniform_R_all',
    'uniform_R_released', 'execution_anomaly', 'identity_status',
}
_ALL_CONFIGURATIONS = {f'CFG{i:02d}' for i in range(17)}


def _sequence(value, name):
    require(isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
            'RISK_SEQUENCE', f'{name} must be an ordered sequence')
    return list(value)


def _ids(value, name):
    result = _sequence(value, name)
    require(bool(result), 'RISK_EMPTY_IDS', f'{name} must not be empty')
    require(all(isinstance(item, str) and item and item == item.strip() for item in result),
            'RISK_ID_TYPE', f'{name} must contain nonempty unpadded strings')
    require(len(set(result)) == len(result), 'RISK_DUPLICATE_ID', f'{name} must be unique')
    return result


def _population(canonical_rids, target_ids, configurations, fixture_mode):
    require(type(fixture_mode) is bool, 'RISK_FIXTURE_MODE', 'fixture_mode must be Boolean')
    canonical = _ids(canonical_rids, 'canonical_rids')
    targets = _ids(target_ids, 'target_ids')
    require(set(targets) <= set(canonical), 'RISK_TARGET_POPULATION',
            'Targets must belong to the canonical input population')
    require(isinstance(configurations, Mapping) and bool(configurations),
            'RISK_EMPTY_CONFIGURATIONS', 'At least one configuration is required')
    for cfg_id in configurations:
        cfg_contract(cfg_id)
    if not fixture_mode:
        require(len(canonical) == 30162 and len(targets) == 5000,
                'RISK_OPERATIONAL_SHAPE', 'Operational risk requires 30162 input rows and 5000 targets')
        require(hashlib.sha256(('\n'.join(canonical) + '\n').encode('utf-8')).hexdigest()
                == RID_ORDER_SHA256, 'RISK_CANONICAL_IDENTITY',
                'Operational canonical RID order differs from the authoritative freeze')
        require(set(configurations) == _ALL_CONFIGURATIONS, 'RISK_OPERATIONAL_MATRIX',
                'Operational risk requires CFG00 through CFG16')
    return canonical, targets


def _observations(cfg_id, data, canonical, targets, fixture_mode):
    contract = cfg_contract(cfg_id)
    own_targets = _ids(data['target_ids'], f'{cfg_id}.target_ids')
    require(own_targets == targets, 'RISK_TARGET_ALIGNMENT',
            f'{cfg_id}: exact frozen target order differs')
    release = _ids(data['release_ids'], f'{cfg_id}.release_ids')
    release_set = set(release)
    require(release_set <= set(canonical), 'RISK_RELEASE_POPULATION',
            f'{cfg_id}: release IDs are outside the input population')
    suppressed_count = len(canonical) - len(release)
    suppression_limit = contract['suppression_limit']
    maximum = 0 if suppression_limit is None else floor(suppression_limit * len(canonical))
    require(suppressed_count <= maximum, 'RISK_SUPPRESSION_CONTRACT',
            f'{cfg_id}: observed suppression exceeds the frozen CFG limit')
    retained = [target in release_set for target in targets]
    rows = _sequence(data['success_draws'], f'{cfg_id}.success_draws')
    require(len(rows) == len(targets), 'RISK_DRAW_ALIGNMENT',
            f'{cfg_id}: success rows must align exactly with targets')
    means = []
    draw_count = None
    for i, row in enumerate(rows):
        draws = _sequence(row, f'{cfg_id}.success_draws[{i}]')
        require(bool(draws), 'RISK_EMPTY_DRAWS', f'{cfg_id}: each target needs success draws')
        if draw_count is None:
            draw_count = len(draws)
        require(len(draws) == draw_count, 'RISK_DRAW_SHAPE',
                f'{cfg_id}: all targets require the same number of draws')
        if not fixture_mode:
            require(len(draws) == 30, 'RISK_OPERATIONAL_DRAWS',
                    f'{cfg_id}: operational risk requires exactly 30 draws per target')
        checked = [number(value, f'{cfg_id}.success_draws[{i}]') for value in draws]
        require(all(0 <= value <= 1 for value in checked), 'RISK_SUCCESS_RANGE',
                f'{cfg_id}: success values must lie in [0,1]')
        require(retained[i] or all(value == 0 for value in checked),
                'RISK_SUPPRESSED_SUCCESS', f'{cfg_id}: suppressed targets must have exactly zero success')
        means.append(fsum(checked) / len(checked))
    return release, retained, means, draw_count


def _close(actual, expected, name, code='RISK_REPORTED_VALUE'):
    observed = number(actual, name)
    require(0 <= observed <= 1, 'RISK_REPORTED_RANGE',
            f'{name}: a reported risk or baseline must lie in [0,1]')
    require(abs(observed - expected) <= _TOLERANCE, code,
            f'{name}: supplied value differs from independent recomputation')
    return observed


def _aggregates(reported, numerator, denominator, retained_denominator, n_c, name):
    expected_all = numerator / denominator
    expected_released = numerator / retained_denominator if retained_denominator else None
    observed_all = _close(reported['R_all'], expected_all, f'{name}.R_all')
    if retained_denominator:
        observed_released = _close(reported['R_released'], expected_released,
                                   f'{name}.R_released')
        require(reported['execution_anomaly'] is False, 'RISK_ANOMALY_STATUS',
                f'{name}: positive retained denominator must not be marked zero-retained')
        require(reported['identity_status'] == 'PASS', 'RISK_IDENTITY_STATUS',
                f'{name}: evaluated identity requires PASS')
        require(abs(observed_all - retained_denominator / denominator * observed_released)
                <= _TOLERANCE, 'RISK_IDENTITY', f'{name}: R_all/R_released identity fails')
    else:
        require(reported['R_released'] is None, 'RISK_ZERO_RETAINED_RELEASED',
                f'{name}: zero retained denominator requires R_released=None')
        require(observed_all == 0, 'RISK_ZERO_RETAINED_ALL',
                f'{name}: zero retained denominator requires exactly R_all=0')
        require(reported['execution_anomaly'] is True, 'RISK_ANOMALY_STATUS',
                f'{name}: zero retained denominator must be flagged as an anomaly')
        require(reported['identity_status'] == 'NOT_EVALUATED', 'RISK_IDENTITY_STATUS',
                f'{name}: identity must not be evaluated when no targets are retained')
    expected_uniform_all = retained_denominator / (denominator * n_c)
    expected_uniform_released = 1 / n_c
    _close(reported['uniform_R_all'], expected_uniform_all, f'{name}.uniform_R_all',
           'RISK_UNIFORM_BASELINE')
    _close(reported['uniform_R_released'], expected_uniform_released,
           f'{name}.uniform_R_released', 'RISK_UNIFORM_BASELINE')
    if retained_denominator == denominator:
        require(abs(observed_all - number(reported['R_released'], f'{name}.R_released'))
                <= _TOLERANCE, 'RISK_NO_SUPPRESSION_IDENTITY',
                f'{name}: all-retained risk equality fails')
    return {
        'success_numerator': numerator,
        'R_all': expected_all,
        'R_released': expected_released,
        'uniform_R_all': expected_uniform_all,
        'uniform_R_released': expected_uniform_released,
        'execution_anomaly': retained_denominator == 0,
        'identity_status': 'PASS' if retained_denominator else 'NOT_EVALUATED',
    }


def _receipt(family, fixture_mode, targets, results):
    return {
        'assertion_family': family,
        'status': 'PASS',
        'scope': 'SYNTHETIC_FIXTURE' if fixture_mode else 'SUPPLIED_OPERATIONAL_OBSERVATIONS',
        'target_count': len(targets),
        'target_order_sha256': json_digest(targets),
        'configurations': results,
        'section_12_1_step_7_status': 'pending',
        'main_runs_authorized': False,
        'rng_invoked': False,
    }


def assert_point_risk(canonical_rids, target_ids, configurations, *, fixture_mode=False):

    canonical, targets = _population(canonical_rids, target_ids, configurations, fixture_mode)
    results = {}
    common_draw_count = None
    for cfg_id, data in configurations.items():
        exact_keys(data, {'target_ids', 'release_ids', 'success_draws', 'reported'}, cfg_id)
        release, retained, means, draw_count = _observations(
            cfg_id, data, canonical, targets, fixture_mode)
        if common_draw_count is None:
            common_draw_count = draw_count
        require(draw_count == common_draw_count, 'RISK_PAIRED_DRAW_SHAPE',
                'Every CFG must use the same draw count')
        report = data['reported']
        exact_keys(report, _POINT_KEYS, f'{cfg_id}.reported')
        n_c, n_ret = len(release), sum(retained)
        require(integer(report['n_c'], f'{cfg_id}.n_c') == n_c, 'RISK_RELEASE_COUNT',
                f'{cfg_id}: n_c must count output rows, not retained targets')
        require(integer(report['n_ret'], f'{cfg_id}.n_ret') == n_ret, 'RISK_TARGET_COUNT',
                f'{cfg_id}: n_ret must count retained targets')
        checked = _aggregates(report, fsum(means), len(targets), n_ret, n_c, cfg_id)
        results[cfg_id] = dict(checked, n_c=n_c, n_ret=n_ret, draw_count=draw_count,
                              release_id_order_sha256=json_digest(release))
    return _receipt('point_risk_identity', fixture_mode, targets, results)


def _clusters(cluster_keys, targets):
    supplied = _sequence(cluster_keys, 'cluster_keys')
    require(len(supplied) == len(targets), 'BOOTSTRAP_CLUSTER_ALIGNMENT',
            'Cluster keys must align exactly with the target order')
    canonical_order, membership, lookup = [], [], {}
    for index, supplied_key in enumerate(supplied):
        key = _sequence(supplied_key, f'cluster_keys[{index}]')
        require(len(key) == 4 and all(isinstance(value, str) and value
                and value == value.strip() for value in key), 'BOOTSTRAP_CLUSTER_KEY',
                'Cluster keys must be exact nonempty trimmed raw age/sex/education/marital-status strings')
        require(re.fullmatch(r'(?:0|[1-9][0-9]*)', key[0]) is not None,
                'BOOTSTRAP_CLUSTER_AGE', 'Raw age must use its canonical decimal string')
        key_tuple = tuple(key)
        if key_tuple not in lookup:
            lookup[key_tuple] = len(canonical_order)
            canonical_order.append(key)
        membership.append(lookup[key_tuple])
    return canonical_order, membership


def assert_bootstrap_risk(canonical_rids, target_ids, cluster_keys,
                          cluster_multiplicities, configurations, *, fixture_mode=False):

    canonical, targets = _population(canonical_rids, target_ids, configurations, fixture_mode)
    cluster_order, membership = _clusters(cluster_keys, targets)
    supplied_plan = _sequence(cluster_multiplicities, 'cluster_multiplicities')
    require(bool(supplied_plan), 'BOOTSTRAP_EMPTY_PLAN', 'At least one replicate is required')
    if not fixture_mode:
        require(len(supplied_plan) == 2000, 'BOOTSTRAP_OPERATIONAL_REPLICATES',
                'Operational bootstrap requires exactly 2000 replicates')
    cluster_count = len(cluster_order)
    plan = []
    for index, supplied_row in enumerate(supplied_plan):
        row = _sequence(supplied_row, f'cluster_multiplicities[{index}]')
        require(len(row) == cluster_count, 'BOOTSTRAP_MULTIPLICITY_SHAPE',
                'Multiplicity vectors must include every canonical cluster')
        checked = [integer(value, f'cluster_multiplicities[{index}]') for value in row]
        require(sum(checked) == cluster_count, 'BOOTSTRAP_MULTIPLICITY_TOTAL',
                'Each replicate must resample exactly K clusters with replacement')
        plan.append(checked)
    cluster_hash, plan_hash = json_digest(cluster_order), json_digest(plan)
    sizes = [0] * cluster_count
    for cluster in membership:
        sizes[cluster] += 1
    results = {}
    common_draw_count = None
    for cfg_id, data in configurations.items():
        exact_keys(data, {'target_ids', 'release_ids', 'success_draws',
                   'cluster_order_sha256', 'cluster_multiplicities_sha256',
                   'reported_replicates'}, cfg_id)
        require(data['cluster_order_sha256'] == cluster_hash, 'BOOTSTRAP_PAIRED_CLUSTERS',
                f'{cfg_id}: supplied cluster order differs from the common canonical plan')
        require(data['cluster_multiplicities_sha256'] == plan_hash, 'BOOTSTRAP_PAIRED_PLAN',
                f'{cfg_id}: supplied multiplicities differ from the paired resampling plan')
        release, retained, means, draw_count = _observations(
            cfg_id, data, canonical, targets, fixture_mode)
        if common_draw_count is None:
            common_draw_count = draw_count
        require(draw_count == common_draw_count, 'RISK_PAIRED_DRAW_SHAPE',
                'Every CFG must use the same draw count')
        reported = _sequence(data['reported_replicates'], f'{cfg_id}.reported_replicates')
        require(len(reported) == len(plan), 'BOOTSTRAP_REPORT_COUNT',
                f'{cfg_id}: exactly one supplied report is required for every replicate')
        successes_by_cluster = [[] for _ in range(cluster_count)]
        retained_sizes = [0] * cluster_count
        for cluster, mean, is_retained in zip(membership, means, retained):
            successes_by_cluster[cluster].append(mean)
            retained_sizes[cluster] += is_retained
        cluster_success = [fsum(values) for values in successes_by_cluster]
        replicates = []
        for index, (multiplicities, report) in enumerate(zip(plan, reported)):
            name = f'{cfg_id}.replicate[{index}]'
            exact_keys(report, _REPLICATE_KEYS, name)
            total = sum(weight * size for weight, size in zip(multiplicities, sizes))
            retained_total = sum(weight * size for weight, size in zip(multiplicities, retained_sizes))
            numerator = fsum(weight * success for weight, success in zip(multiplicities, cluster_success))
            require(total > 0, 'BOOTSTRAP_EMPTY_RECORD_SAMPLE', 'Record-weighted denominator must be positive')
            require(integer(report['N_b'], f'{name}.N_b') == total, 'BOOTSTRAP_RECORD_DENOMINATOR',
                    f'{name}: N_b must be the actual record-weighted count, not K')
            require(integer(report['N_ret'], f'{name}.N_ret') == retained_total,
                    'BOOTSTRAP_RETAINED_DENOMINATOR',
                    f'{name}: N_ret must be the record-weighted retained-target count')
            checked = _aggregates(report, numerator, total, retained_total, len(release), name)
            replicates.append(dict(checked, replicate=index, N_b=total, N_ret=retained_total))
        results[cfg_id] = {'n_c': len(release), 'draw_count': draw_count,
                           'release_id_order_sha256': json_digest(release),
                           'replicates': replicates}
    receipt = _receipt('bootstrap_risk_identity', fixture_mode, targets, results)
    receipt.update(cluster_count=cluster_count, replicate_count=len(plan),
                   cluster_order_sha256=cluster_hash,
                   target_cluster_membership_sha256=json_digest(membership),
                   cluster_multiplicities_sha256=plan_hash,
                   record_weight_derivation='weight[target_i] = multiplicity[cluster_id[target_i]]',
                   resampling_performed=False)
    return receipt
