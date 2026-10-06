from collections.abc import Mapping, Sequence
from copy import deepcopy
from math import fsum

from common import exact_keys, integer, json_digest, number, require
from risk_metrics import assert_bootstrap_risk, assert_point_risk


def _sequence(value, name, *, nonempty=False):
    require(isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
            'RISK_CONSUMER_SEQUENCE', name + ' must be an ordered sequence')
    result = list(value)
    require(not nonempty or bool(result), 'RISK_CONSUMER_EMPTY_SEQUENCE',
            name + ' must not be empty')
    return result


def _snapshot(canonical_rids, target_ids, configurations, fixture_mode, **extra):
    require(type(fixture_mode) is bool, 'RISK_FIXTURE_MODE', 'fixture_mode must be Boolean')
    require(isinstance(configurations, Mapping) and bool(configurations),
            'RISK_EMPTY_CONFIGURATIONS', 'At least one configuration is required')
    supplied = deepcopy(dict(canonical_rids=canonical_rids, target_ids=target_ids,
                             configurations=configurations, fixture_mode=fixture_mode, **extra))
    identity = json_digest(supplied)
    return supplied, identity


def _observations(target_ids, configurations):
    targets = _sequence(target_ids, 'target_ids', nonempty=True)
    result = {}
    for cfg, supplied in configurations.items():
        exact_keys(supplied, {'target_ids', 'release_ids', 'success_draws'}, cfg)
        own_targets = _sequence(supplied['target_ids'], cfg + '.target_ids', nonempty=True)
        require(own_targets == targets, 'RISK_TARGET_ALIGNMENT',
                cfg + ': exact supplied target order differs')
        release = _sequence(supplied['release_ids'], cfg + '.release_ids', nonempty=True)
        require(all(isinstance(item, str) for item in release), 'RISK_ID_TYPE',
                cfg + ': release IDs must be strings')
        release_set = set(release)
        rows = _sequence(supplied['success_draws'], cfg + '.success_draws')
        require(len(rows) == len(targets), 'RISK_DRAW_ALIGNMENT',
                cfg + ': success rows must align with targets')
        means = []
        draw_count = None
        for index, supplied_row in enumerate(rows):
            row = _sequence(supplied_row, cfg + '.success_draws', nonempty=True)
            if draw_count is None:
                draw_count = len(row)
            require(len(row) == draw_count, 'RISK_DRAW_SHAPE',
                    cfg + ': every target must have the same draw count')
            means.append(fsum(number(value, cfg + '.success_draws[' + str(index) + ']')
                              for value in row) / len(row))
        result[cfg] = {'release_count': len(release),
                       'retained': [target in release_set for target in targets],
                       'means': means}
    return targets, result


def _report(numerator, total, retained, release_count):
    require(total > 0, 'RISK_CONSUMER_EMPTY_RECORD_SAMPLE',
            'The record denominator must be positive')
    return {'R_all': numerator / total,
            'R_released': numerator / retained if retained else None,
            'uniform_R_all': retained / (total * release_count),
            'uniform_R_released': 1 / release_count,
            'execution_anomaly': retained == 0,
            'identity_status': 'PASS' if retained else 'NOT_EVALUATED'}


def _accepted(family, supplied, input_identity, aggregates, aggregate_identity, receipt):
    require(isinstance(receipt, Mapping) and receipt.get('status') == 'PASS',
            'RISK_CONSUMER_GUARD_NOT_PASS', 'The downstream guard did not return PASS')
    expected_family = {'point_risk': 'point_risk_identity',
                       'bootstrap_risk': 'bootstrap_risk_identity'}[family]
    expected_scope = ('SYNTHETIC_FIXTURE' if supplied['fixture_mode']
                      else 'SUPPLIED_OPERATIONAL_OBSERVATIONS')
    require(receipt.get('assertion_family') == expected_family
            and receipt.get('scope') == expected_scope
            and receipt.get('section_12_1_step_7_status') == 'pending'
            and receipt.get('main_runs_authorized') is False,
            'RISK_CONSUMER_GUARD_SCOPE', 'The downstream receipt has the wrong scope or gate state')
    require(json_digest(supplied) == input_identity, 'RISK_CONSUMER_INPUT_MUTATED',
            'The input snapshot changed during downstream verification')
    require(json_digest(aggregates) == aggregate_identity, 'RISK_CONSUMER_REPORT_MUTATED',
            'The computed reports changed during downstream verification')
    payload = {'aggregates': aggregates, 'guard_receipt': receipt}
    return {
        'record_schema': 'step7-risk-aggregate-consumer/1',
        'consumer_family': family,
        'aggregate_validation_status': 'PASS',
        'candidate_status': 'PARTIAL_CANDIDATE_PENDING_UPSTREAM_INTEGRATION',
        'scope': 'SYNTHETIC_FIXTURE' if supplied['fixture_mode'] else 'SUPPLIED_OPERATIONAL_OBSERVATIONS',
        'upstream_provenance_verification': 'NOT_VERIFIED',
        'upstream_attack_pipeline_integration': 'NOT_IMPLEMENTED',
        'target_sampling_provenance': 'NOT_VERIFIED',
        'success_draw_generation_provenance': 'NOT_VERIFIED',
        'cluster_key_provenance': 'NOT_VERIFIED' if family == 'bootstrap_risk' else 'NOT_APPLICABLE',
        'bootstrap_plan_provenance': 'NOT_VERIFIED' if family == 'bootstrap_risk' else 'NOT_APPLICABLE',
        'input_json_sha256': input_identity,
        'output_payload_json_sha256': json_digest(payload),
        'digest_contract': 'input is the supplied argument snapshot; output is exactly payload',
        'payload': payload,
        'section_12_1_step_7_status': 'pending',
        'gate_a_status': 'pending',
        'main_runs_authorized': False,
        'main_runs_executed': False,
        'rng_invoked': False,
        'targets_generated': False,
        'success_draws_generated': False,
        'noise_generated': False,
        'resampling_performed': False,
    }


def produce_point_risk(canonical_rids, target_ids, configurations, *, fixture_mode=False):

    supplied, identity = _snapshot(canonical_rids, target_ids, configurations, fixture_mode)
    targets, observations = _observations(supplied['target_ids'], supplied['configurations'])
    reports, guard_inputs = {}, {}
    for cfg, observed in observations.items():
        n_ret = sum(observed['retained'])
        report = _report(fsum(observed['means']), len(targets), n_ret, observed['release_count'])
        report.update(n_c=observed['release_count'], n_ret=n_ret)
        reports[cfg] = report
        guard_inputs[cfg] = dict(supplied['configurations'][cfg], reported=report)
    report_identity = json_digest(reports)
    receipt = assert_point_risk(supplied['canonical_rids'], supplied['target_ids'],
                                guard_inputs, fixture_mode=fixture_mode)
    return _accepted('point_risk', supplied, identity, reports, report_identity, receipt)


def _record_weights(cluster_keys, target_count, supplied_plan):
    keys = _sequence(cluster_keys, 'cluster_keys')
    require(len(keys) == target_count, 'BOOTSTRAP_CLUSTER_ALIGNMENT',
            'Raw cluster keys must align with every target')
    order, membership = [], []
    for supplied_key in keys:
        key = _sequence(supplied_key, 'cluster_key')
        require(len(key) == 4 and all(isinstance(value, str) for value in key),
                'BOOTSTRAP_CLUSTER_KEY', 'Raw cluster keys must be four strings')

        if key not in order:
            order.append(key)
        membership.append(order.index(key))
    plan = _sequence(supplied_plan, 'cluster_multiplicities', nonempty=True)
    checked_plan = []
    for supplied_row in plan:
        row = _sequence(supplied_row, 'cluster_multiplicities row')
        require(len(row) == len(order), 'BOOTSTRAP_MULTIPLICITY_SHAPE',
                'Each multiplicity row must include every raw cluster')
        checked = [integer(value, 'cluster multiplicity') for value in row]
        require(sum(checked) == len(order), 'BOOTSTRAP_MULTIPLICITY_TOTAL',
                'A supplied replicate must select exactly K clusters')
        checked_plan.append(checked)
    return order, membership, checked_plan


def produce_bootstrap_risk(canonical_rids, target_ids, cluster_keys,
                           cluster_multiplicities, configurations, *, fixture_mode=False):
    """Apply each raw cluster multiplicity to every target in that cluster."""
    supplied, identity = _snapshot(canonical_rids, target_ids, configurations, fixture_mode,
                                   cluster_keys=cluster_keys,
                                   cluster_multiplicities=cluster_multiplicities)
    targets, observations = _observations(supplied['target_ids'], supplied['configurations'])
    order, membership, plan = _record_weights(supplied['cluster_keys'], len(targets),
                                               supplied['cluster_multiplicities'])
    cluster_identity, plan_identity = json_digest(order), json_digest(plan)
    reports, guard_inputs = {}, {}
    for cfg, observed in observations.items():
        replicates = []
        for multiplicities in plan:
            weights = [multiplicities[cluster] for cluster in membership]
            total = sum(weights)
            retained = sum(weight for weight, included in zip(weights, observed['retained']) if included)
            numerator = fsum(weight * mean for weight, mean in zip(weights, observed['means']))
            report = _report(numerator, total, retained, observed['release_count'])
            report.update(N_b=total, N_ret=retained)
            replicates.append(report)
        reports[cfg] = {'n_c': observed['release_count'], 'replicates': replicates}
        guard_inputs[cfg] = dict(supplied['configurations'][cfg],
                                cluster_order_sha256=cluster_identity,
                                cluster_multiplicities_sha256=plan_identity,
                                reported_replicates=replicates)
    report_identity = json_digest(reports)
    receipt = assert_bootstrap_risk(supplied['canonical_rids'], supplied['target_ids'],
                                    supplied['cluster_keys'], supplied['cluster_multiplicities'],
                                    guard_inputs, fixture_mode=fixture_mode)
    return _accepted('bootstrap_risk', supplied, identity, reports, report_identity, receipt)
