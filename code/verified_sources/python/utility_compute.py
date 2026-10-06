import hashlib
import json
import math

from common import exact_keys, json_digest, require
from utility_evaluation import assert_paired_utility_bootstrap
from utility_admission import (
    admit_fixture_bytes, admit_operational_bytes,
)


CFGS = tuple('CFG%02d' % index for index in range(17))
METRICS = ('auroc', 'average_precision', 'balanced_accuracy', 'accuracy')
POINT_SCHEMA = 'raw-to-model-prediction-only-point/1.0'
BOOTSTRAP_SCHEMA = 'raw-to-model-prediction-only-bootstrap/1.0'
PARTIAL_SCHEMA = 'raw-to-model-prediction-only-bootstrap-partial/1.0'
NUMPY_VERSION = '2.0.2'
SEED = 11006
REPLICATES = 2000


def numerical_conventions():

    return {
        'positive_class': 1, 'probability_column': 1,
        'auroc': 'average_rank_ties',
        'average_precision': 'recall_increment_times_precision_at_complete_tie_groups',
        'balanced_accuracy_threshold': 0.5,
        'threshold_comparison': 'positive_probability_greater_than_or_equal',
        'accuracy_role': 'descriptive',
        'delta_direction': 'CFG00_AUROC_minus_released_CFG_AUROC',
        'interval_method': 'percentile_linear_interpolation_type_7',
        'interval_percentiles': [2.5, 97.5],
    }


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _identity(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def _scope(accepted, schema, stage):
    return {
        'record_schema': schema, 'result': 'PASS', 'mode': accepted.mode,
        'stage': stage, 'configuration_count_per_group': 17,
        'unique_prediction_arrays_scored': 33,
        'holdout_row_count': len(accepted.labels),
        'class_counts': [accepted.labels.count(0), accepted.labels.count(1)],
        'input_identities': {
            'private_model_artifact': dict(accepted.private_identity),
            'public_model_receipt': dict(accepted.public_identity),
            'row_ids_sha256': json_digest(list(accepted.row_ids)),
            'labels_sha256': json_digest(list(accepted.labels)),
        },
        'conventions': numerical_conventions(),
        'x_revalidated_here': False,
        'x_provenance': 'INHERITED_FROM_BOUND_UPSTREAM_EVIDENCE',
        'private_payloads_in_return': False,
        'execution_authorization_conferred': False,
        'model_fits_executed': False, 'predictions_generated': False,
        'dummy_baseline_metrics_recomputed': False,
        'sensitivity_scenarios_executed': False,
        'raw_to_model_end_to_end_verified': False,
        'production_pipeline_verified': False,
    }


def _score_admitted(labels, probabilities, *, auroc_only=False):

    require(set(labels) == {0, 1}, 'UTILITY_CLASSES', 'both classes required')
    require(len(labels) == len(probabilities), 'UTILITY_LENGTH', 'length differs')
    total = len(labels)
    positives = sum(labels)
    negatives = total - positives
    ordered = sorted((pair[1], label) for pair, label in zip(probabilities, labels))
    rank_sum, positives_below = 0.0, 0
    ap_terms = []
    start = 0
    while start < total:
        end = start + 1
        while end < total and ordered[end][0] == ordered[start][0]:
            end += 1
        in_group = sum(label for _, label in ordered[start:end])
        rank_sum += in_group * ((start + 1 + end) / 2.0)
        if in_group and not auroc_only:
            precision = (positives - positives_below) / (total - start)
            ap_terms.append((in_group / positives) * precision)
        positives_below += in_group
        start = end
    auc = (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)
    if auroc_only:
        return {'auroc': auc}
    tp = sum(label == 1 and pair[1] >= 0.5
             for label, pair in zip(labels, probabilities))
    tn = sum(label == 0 and pair[1] < 0.5
             for label, pair in zip(labels, probabilities))
    return {'auroc': auc, 'average_precision': math.fsum(ap_terms),
            'balanced_accuracy': (tp / positives + tn / negatives) / 2.0,
            'accuracy': (tp + tn) / total}


def _point(accepted):
    release = {cfg: _score_admitted(accepted.labels, accepted.release[cfg]) for cfg in CFGS}
    counterfactual = {'CFG00': dict(release['CFG00'])}
    counterfactual.update({cfg: _score_admitted(accepted.labels, accepted.counterfactual[cfg])
                           for cfg in CFGS[1:]})
    result = _scope(accepted, POINT_SCHEMA, 'point_only')
    result.update(
        rng_instantiated=False, rng_invoked=False,
        bootstrap_indices_generated=False, point_metrics_recomputed=False,
        groups={
            'release': {'classification': 'release_evaluation', 'metrics_by_cfg': release,
                        'delta_auroc_by_cfg': {
                            cfg: release['CFG00']['auroc'] - release[cfg]['auroc']
                            for cfg in CFGS[1:]}},
            'counterfactual': {'classification': 'counterfactual_evaluation',
                               'metrics_by_cfg': counterfactual,
                               'delta_auroc_by_cfg': None},
        })
    return result


def compute_point_from_bytes(private_data, public_data, session_data,
                             verification_receipt_data):

    return _point(admit_operational_bytes(private_data, public_data, session_data,
                                          verification_receipt_data))


def compute_fixture_point_from_bytes(private_data, public_data):

    return _point(admit_fixture_bytes(private_data, public_data))


def _finite(value, *, low=0.0, high=1.0):
    require(type(value) in (int, float) and math.isfinite(value) and low <= value <= high,
            'POINT_VALUE', 'point receipt has an invalid aggregate')


def _checked_identity(identity):
    exact_keys(identity, {'bytes', 'sha256'}, 'artifact identity')
    require(type(identity['bytes']) is int and identity['bytes'] > 0,
            'POINT_IDENTITY', 'positive byte count required')
    digest = identity['sha256']
    require(type(digest) is str and len(digest) == 64 and
            all(c in '0123456789abcdef' for c in digest),
            'POINT_IDENTITY', 'lowercase SHA256 required')


def _validate_point_shape(point):

    expected = {
        'record_schema', 'result', 'mode', 'stage', 'configuration_count_per_group',
        'unique_prediction_arrays_scored', 'holdout_row_count', 'class_counts',
        'input_identities', 'conventions', 'x_revalidated_here', 'x_provenance',
        'private_payloads_in_return', 'execution_authorization_conferred',
        'model_fits_executed', 'predictions_generated', 'dummy_baseline_metrics_recomputed',
        'sensitivity_scenarios_executed', 'raw_to_model_end_to_end_verified',
        'production_pipeline_verified', 'rng_instantiated', 'rng_invoked',
        'bootstrap_indices_generated', 'point_metrics_recomputed', 'groups',
    }
    exact_keys(point, expected, 'point receipt')
    require(point['record_schema'] == POINT_SCHEMA and point['result'] == 'PASS' and
            point['stage'] == 'point_only' and point['mode'] in ('operational', 'fixture'),
            'POINT_SCOPE', 'point receipt scope differs')
    require(type(point['configuration_count_per_group']) is int and
            point['configuration_count_per_group'] == 17 and
            type(point['unique_prediction_arrays_scored']) is int and
            point['unique_prediction_arrays_scored'] == 33,
            'POINT_COUNTS', 'point model counts differ')
    for field in ('x_revalidated_here', 'private_payloads_in_return',
                  'execution_authorization_conferred', 'model_fits_executed',
                  'predictions_generated', 'dummy_baseline_metrics_recomputed',
                  'sensitivity_scenarios_executed', 'raw_to_model_end_to_end_verified',
                  'production_pipeline_verified', 'rng_instantiated', 'rng_invoked',
                  'bootstrap_indices_generated', 'point_metrics_recomputed'):
        require(point[field] is False, 'POINT_SCOPE', 'point scope flag differs')
    require(point['x_provenance'] == 'INHERITED_FROM_BOUND_UPSTREAM_EVIDENCE' and
            _canonical(point['conventions']) == _canonical(numerical_conventions()),
            'POINT_CONVENTIONS', 'point convention differs')
    classes = point['class_counts']
    require(type(classes) is list and len(classes) == 2 and
            all(type(n) is int and n > 0 for n in classes) and
            type(point['holdout_row_count']) is int and sum(classes) == point['holdout_row_count'],
            'POINT_CLASSES', 'point row/class counts differ')
    require((point['mode'] == 'operational' and classes == [11360, 3700]) or
            (point['mode'] == 'fixture' and 2 <= sum(classes) <= 64),
            'POINT_CLASSES', 'point mode dimensions differ')
    identities = point['input_identities']
    exact_keys(identities, {'private_model_artifact', 'public_model_receipt',
                            'row_ids_sha256', 'labels_sha256'}, 'point identities')
    for field in ('private_model_artifact', 'public_model_receipt'):
        _checked_identity(identities[field])
    for field in ('row_ids_sha256', 'labels_sha256'):
        _checked_identity({'bytes': 1, 'sha256': identities[field]})
    exact_keys(point['groups'], {'release', 'counterfactual'}, 'point groups')
    for group in ('release', 'counterfactual'):
        record = point['groups'][group]
        exact_keys(record, {'classification', 'metrics_by_cfg', 'delta_auroc_by_cfg'}, group)
        require(record['classification'] == group + '_evaluation',
                'POINT_CLASSIFICATION', 'point classification differs')
        exact_keys(record['metrics_by_cfg'], CFGS, 'point configurations')
        for values in record['metrics_by_cfg'].values():
            exact_keys(values, METRICS, 'point metrics')
            for value in values.values():
                _finite(value)
        delta = record['delta_auroc_by_cfg']
        if group == 'counterfactual':
            require(delta is None, 'POINT_DELTA', 'counterfactual primary delta forbidden')
        else:
            exact_keys(delta, CFGS[1:], 'release delta')
            for cfg, value in delta.items():
                _finite(value, low=-1.0)
                require(value == record['metrics_by_cfg']['CFG00']['auroc'] -
                        record['metrics_by_cfg'][cfg]['auroc'],
                        'POINT_DELTA', 'saved point delta direction/value differs')
    require(point['groups']['release']['metrics_by_cfg']['CFG00'] ==
            point['groups']['counterfactual']['metrics_by_cfg']['CFG00'],
            'POINT_SHARED_RAW', 'shared raw point differs')


def point_receipt_bytes(point):

    _validate_point_shape(point)
    return _canonical(point)


def _bind_point(data, expected_identity, accepted):
    require(type(data) is bytes and len(data) <= 65536,
            'POINT_BYTES', 'bounded immutable point bytes required')
    _checked_identity(expected_identity)
    require(_identity(data) == dict(expected_identity),
            'POINT_BINDING', 'point bytes differ from independent expected identity')

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'POINT_DUPLICATE_KEY', 'duplicate point JSON key')
            result[key] = value
        return result

    def reject_constant(value):
        require(False, 'POINT_NONFINITE', 'nonfinite JSON constant forbidden')

    try:
        point = json.loads(data.decode('ascii'), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('POINT_JSON: invalid point receipt') from None
    _validate_point_shape(point)
    require(_canonical(point) == data, 'POINT_CANONICAL', 'point bytes not canonical')
    expected_scope = _scope(accepted, POINT_SCHEMA, 'point_only')
    for key, value in expected_scope.items():
        require(point[key] == value, 'POINT_INPUT_BINDING', 'point belongs to different inputs/scope')
    return point


def _interval(values):
    """Type-7 quantiles at exact rational positions 1/40 and 39/40."""
    ordered = sorted(values)
    require(len(ordered) >= 2, 'INTERVAL_COUNT', 'at least two completed replicates required')
    endpoints = []
    for numerator in (1, 39):
        quotient, remainder = divmod((len(ordered) - 1) * numerator, 40)
        lower = ordered[quotient]
        upper = ordered[min(quotient + 1, len(ordered) - 1)]
        endpoints.append(lower + (upper - lower) * (remainder / 40.0))
    return endpoints


def _sample_group(accepted, predictions, indices):
    ids = [accepted.row_ids[i] for i in indices]
    labels = [accepted.labels[i] for i in indices]
    return {cfg: {'row_ids': ids[:], 'y': labels[:],
                  'predictions': [predictions[cfg][i] for i in indices]}
            for cfg in CFGS}


def _guard_samples(accepted, predictions, sampled, indices, classes, replicate_id):
    return assert_paired_utility_bootstrap(
        accepted.row_ids, accepted.labels, classes, dict(predictions),
        {cfg: indices[:] for cfg in CFGS},
        {cfg: sampled[cfg]['row_ids'] for cfg in CFGS},
        {cfg: sampled[cfg]['y'] for cfg in CFGS},
        {cfg: sampled[cfg]['predictions'] for cfg in CFGS},
        replicate_id=replicate_id, mode=accepted.mode)


class UtilityBootstrapFailure(ValueError):


    def __init__(self, journal):
        super().__init__('UTILITY_BOOTSTRAP_FAILED: no completed result or intervals returned')
        self.partial_receipt = journal


def _bootstrap(accepted, point_receipt_data, expected_point_identity, replicate_count):
    completed = 0
    draws = 0
    current = None
    instantiated = False
    index_receipts = []
    guard_digest = hashlib.sha256(b'rtm-impl05-paired-guard-sequence/1\x00')
    metric_digest = hashlib.sha256(b'rtm-impl05-paired-auroc-sequence/1\x00')
    try:
        require(type(replicate_count) is int and
                ((accepted.mode == 'operational' and replicate_count == REPLICATES) or
                 (accepted.mode == 'fixture' and 2 <= replicate_count <= REPLICATES)),
                'BOOTSTRAP_COUNT', 'replicate count outside explicit mode scope')
        point = _bind_point(point_receipt_data, expected_point_identity, accepted)

        import numpy as np
        require(np.__version__ == NUMPY_VERSION, 'BOOTSTRAP_NUMPY_VERSION',
                'bootstrap requires exact NumPy 2.0.2; no fallback')
        rng = np.random.Generator(np.random.PCG64(SEED))
        instantiated = True
        classes = {label: [i for i, value in enumerate(accepted.labels) if value == label]
                   for label in (0, 1)}
        series = {group: {cfg: [] for cfg in CFGS} for group in ('release', 'counterfactual')}
        deltas = {cfg: [] for cfg in CFGS[1:]}
        for current in range(replicate_count):
            indices = []
            for label in (0, 1):
                positions = rng.integers(0, len(classes[label]), size=len(classes[label]),
                                         dtype=np.int64, endpoint=False)
                draws += 1
                indices.extend(classes[label][int(position)] for position in positions)

            sampled = {
                'release': _sample_group(accepted, accepted.release, indices),
                'counterfactual': _sample_group(accepted, accepted.counterfactual, indices),
            }
            guards = {
                'release': _guard_samples(accepted, accepted.release, sampled['release'],
                                           indices, classes, current),
                'counterfactual': _guard_samples(accepted, accepted.counterfactual,
                                                 sampled['counterfactual'], indices, classes, current),
            }
            index_hash = json_digest(indices)
            require(all(receipt['index_sha256'] == index_hash for receipt in guards.values()),
                    'BOOTSTRAP_GROUP_PAIRING', 'postconstruction group hashes differ')
            index_receipts.append({'replicate_id': current, 'indices_sha256': index_hash})

            scores = {'release': {
                cfg: _score_admitted(sampled['release'][cfg]['y'],
                                      sampled['release'][cfg]['predictions'], auroc_only=True)['auroc']
                for cfg in CFGS}}
            scores['counterfactual'] = {'CFG00': scores['release']['CFG00']}
            scores['counterfactual'].update({
                cfg: _score_admitted(sampled['counterfactual'][cfg]['y'],
                                      sampled['counterfactual'][cfg]['predictions'],
                                      auroc_only=True)['auroc'] for cfg in CFGS[1:]})
            paired_delta = {cfg: scores['release']['CFG00'] - scores['release'][cfg]
                            for cfg in CFGS[1:]}
            for group in series:
                for cfg in CFGS:
                    series[group][cfg].append(scores[group][cfg])
            for cfg in deltas:
                deltas[cfg].append(paired_delta[cfg])
            guard_digest.update(bytes.fromhex(json_digest(guards)))
            metric_digest.update(bytes.fromhex(json_digest({
                'replicate_id': current, 'auroc_by_group': scores,
                'paired_release_delta_auroc_by_cfg': paired_delta})))
            completed += 1
        result = _scope(accepted, BOOTSTRAP_SCHEMA, 'bootstrap_only')
        result.update(
            point_receipt_identity=_identity(point_receipt_data),
            accepted_point_receipt=point,
            point_metrics_recomputed=False,
            numpy_version=NUMPY_VERSION, rng='Generator(PCG64(11006))', seed=SEED,
            rng_instantiated=True, rng_invoked=True, bootstrap_indices_generated=True,
            requested_replicate_count=replicate_count, completed_replicate_count=completed,
            rng_generator_count=1, rng_draw_calls_completed=draws,
            unchanged_postconstruction_guard_count=2 * completed,
            identical_realized_indices_across_groups=True,
            replicate_index_receipts=index_receipts,
            guard_sequence_sha256=guard_digest.hexdigest(),
            replicate_metric_sequence_sha256=metric_digest.hexdigest(),
            interval_coverage=0.95, partial_intervals_returned=False,
            groups={
                'release': {
                    'classification': 'release_evaluation',
                    'auroc_intervals_by_cfg': {cfg: _interval(series['release'][cfg]) for cfg in CFGS},
                    'paired_delta_auroc_intervals_by_cfg': {
                        cfg: _interval(deltas[cfg]) for cfg in CFGS[1:]},
                },
                'counterfactual': {
                    'classification': 'counterfactual_evaluation',
                    'auroc_intervals_by_cfg': {
                        cfg: _interval(series['counterfactual'][cfg]) for cfg in CFGS},
                    'paired_delta_auroc_intervals_by_cfg': None,
                },
            })
        return result
    except Exception:
        raise UtilityBootstrapFailure({
            'record_schema': PARTIAL_SCHEMA, 'result': 'FAIL', 'mode': accepted.mode,
            'failed_replicate_id': current, 'fully_scored_replicate_count': completed,
            'requested_replicate_count': replicate_count if type(replicate_count) is int and
                2 <= replicate_count <= REPLICATES else None,
            'postconstruction_validated_replicate_count': len(index_receipts),
            'replicate_index_receipts': index_receipts,
            'completed_guard_sequence_sha256': guard_digest.hexdigest(),
            'rng_instantiated': instantiated, 'rng_draw_calls_completed': draws,
            'partial_intervals_returned': False, 'private_payloads_in_return': False,
            'point_metrics_recomputed': False, 'execution_authorization_conferred': False,
        }) from None


def compute_bootstrap_from_bytes(private_data, public_data, session_data,
                                 verification_receipt_data, *, point_receipt_data,
                                 expected_point_identity):

    accepted = admit_operational_bytes(private_data, public_data, session_data,
                                       verification_receipt_data)
    return _bootstrap(accepted, point_receipt_data, expected_point_identity, REPLICATES)


def compute_fixture_bootstrap_from_bytes(private_data, public_data, *, point_receipt_data,
                                         expected_point_identity, replicate_count=2):

    accepted = admit_fixture_bytes(private_data, public_data)
    return _bootstrap(accepted, point_receipt_data, expected_point_identity, replicate_count)


def _index_receipts(records, count):
    require(type(records) is list and len(records) == count,
            'PUBLIC_INDEX_RECEIPTS', 'ordered bounded index receipts required')
    for position, record in enumerate(records):
        exact_keys(record, {'replicate_id', 'indices_sha256'}, 'index hash receipt')
        require(type(record['replicate_id']) is int and record['replicate_id'] == position,
                'PUBLIC_REPLICATE_ORDER', 'replicate hash order differs')
        _checked_identity({'bytes': 1, 'sha256': record['indices_sha256']})


def _validate_bootstrap_shape(result):
    point = result.get('accepted_point_receipt')
    _validate_point_shape(point)
    common = {key: value for key, value in point.items()
              if key not in {'groups', 'rng_instantiated', 'rng_invoked',
                             'bootstrap_indices_generated', 'point_metrics_recomputed'}}
    common.update(record_schema=BOOTSTRAP_SCHEMA, stage='bootstrap_only')
    additional = {
        'point_receipt_identity', 'accepted_point_receipt', 'point_metrics_recomputed',
        'numpy_version', 'rng', 'seed', 'rng_instantiated', 'rng_invoked',
        'bootstrap_indices_generated', 'requested_replicate_count',
        'completed_replicate_count', 'rng_generator_count', 'rng_draw_calls_completed',
        'unchanged_postconstruction_guard_count', 'identical_realized_indices_across_groups',
        'replicate_index_receipts', 'guard_sequence_sha256',
        'replicate_metric_sequence_sha256', 'interval_coverage',
        'partial_intervals_returned', 'groups',
    }
    exact_keys(result, set(common) | additional, 'bootstrap receipt')
    for key, value in common.items():
        require(_canonical(result[key]) == _canonical(value),
                'BOOTSTRAP_POINT_SCOPE', 'bootstrap and saved point scope differ')
    _checked_identity(result['point_receipt_identity'])
    require(result['point_receipt_identity'] == _identity(point_receipt_bytes(point)),
            'BOOTSTRAP_POINT_IDENTITY', 'embedded accepted point identity differs')
    constants = {
        'point_metrics_recomputed': False, 'numpy_version': NUMPY_VERSION,
        'rng': 'Generator(PCG64(11006))', 'seed': SEED,
        'rng_instantiated': True, 'rng_invoked': True, 'bootstrap_indices_generated': True,
        'rng_generator_count': 1, 'identical_realized_indices_across_groups': True,
        'interval_coverage': 0.95, 'partial_intervals_returned': False,
    }
    for key, value in constants.items():
        require(type(result[key]) is type(value) and result[key] == value,
                'BOOTSTRAP_SCOPE', 'bootstrap producer/scope convention differs')
    count = result['completed_replicate_count']
    require(type(count) is int and 2 <= count <= REPLICATES and
            (result['mode'] == 'fixture' or count == REPLICATES),
            'BOOTSTRAP_COMPLETION', 'bootstrap completion count differs')
    for key, expected in (('requested_replicate_count', count),
                          ('rng_draw_calls_completed', 2 * count),
                          ('unchanged_postconstruction_guard_count', 2 * count)):
        require(type(result[key]) is int and result[key] == expected,
                'BOOTSTRAP_COMPLETION', 'bootstrap counts do not agree')
    _index_receipts(result['replicate_index_receipts'], count)
    for field in ('guard_sequence_sha256', 'replicate_metric_sequence_sha256'):
        _checked_identity({'bytes': 1, 'sha256': result[field]})
    exact_keys(result['groups'], {'release', 'counterfactual'}, 'bootstrap groups')
    for group in ('release', 'counterfactual'):
        record = result['groups'][group]
        exact_keys(record, {'classification', 'auroc_intervals_by_cfg',
                            'paired_delta_auroc_intervals_by_cfg'}, 'bootstrap group')
        require(record['classification'] == group + '_evaluation',
                'BOOTSTRAP_CLASSIFICATION', 'bootstrap classification differs')
        exact_keys(record['auroc_intervals_by_cfg'], CFGS, 'AUROC intervals')
        maps = [(record['auroc_intervals_by_cfg'], 0.0)]
        if group == 'release':
            exact_keys(record['paired_delta_auroc_intervals_by_cfg'], CFGS[1:],
                       'paired release delta intervals')
            maps.append((record['paired_delta_auroc_intervals_by_cfg'], -1.0))
        else:
            require(record['paired_delta_auroc_intervals_by_cfg'] is None,
                    'BOOTSTRAP_DELTA_SCOPE', 'counterfactual primary delta forbidden')
        for mapping, low in maps:
            for interval in mapping.values():
                require(type(interval) is list and len(interval) == 2,
                        'BOOTSTRAP_INTERVAL', 'only a two-endpoint interval is allowed')
                for endpoint in interval:
                    _finite(endpoint, low=low)
                require(interval[0] <= interval[1], 'BOOTSTRAP_INTERVAL', 'interval reversed')
    require(result['groups']['release']['auroc_intervals_by_cfg']['CFG00'] ==
            result['groups']['counterfactual']['auroc_intervals_by_cfg']['CFG00'],
            'BOOTSTRAP_SHARED_RAW', 'shared raw interval differs')


def _validate_partial_shape(result):
    exact_keys(result, {
        'record_schema', 'result', 'mode', 'failed_replicate_id',
        'fully_scored_replicate_count', 'requested_replicate_count',
        'postconstruction_validated_replicate_count', 'replicate_index_receipts',
        'completed_guard_sequence_sha256', 'rng_instantiated', 'rng_draw_calls_completed',
        'partial_intervals_returned', 'private_payloads_in_return',
        'point_metrics_recomputed', 'execution_authorization_conferred',
    }, 'bounded failure receipt')
    require(result['record_schema'] == PARTIAL_SCHEMA and result['result'] == 'FAIL' and
            result['mode'] in ('operational', 'fixture'),
            'PARTIAL_SCOPE', 'failure scope differs')
    for field in ('partial_intervals_returned', 'private_payloads_in_return',
                  'point_metrics_recomputed', 'execution_authorization_conferred'):
        require(result[field] is False, 'PARTIAL_SCOPE', 'failure cannot return private/CI values')
    requested = result['requested_replicate_count']
    require(requested is None or (type(requested) is int and 2 <= requested <= REPLICATES),
            'PARTIAL_COUNT', 'failure requested count invalid')
    completed = result['fully_scored_replicate_count']
    checked = result['postconstruction_validated_replicate_count']
    draws = result['rng_draw_calls_completed']
    require(all(type(n) is int and 0 <= n <= REPLICATES for n in (completed, checked)) and
            completed <= checked <= completed + 1 and
            type(draws) is int and 2 * checked <= draws <= 2 * REPLICATES,
            'PARTIAL_COUNT', 'failure progress counts invalid')
    failed = result['failed_replicate_id']
    require(failed is None or (type(failed) is int and 0 <= failed < REPLICATES),
            'PARTIAL_REPLICATE', 'failure replicate invalid')
    require(type(result['rng_instantiated']) is bool and
            (result['rng_instantiated'] or draws == 0),
            'PARTIAL_RNG', 'failure RNG flags disagree')
    _index_receipts(result['replicate_index_receipts'], checked)
    _checked_identity({'bytes': 1, 'sha256': result['completed_guard_sequence_sha256']})


def receipt_bytes(result):

    data = _canonical(result)
    validate_receipt_bytes(data)
    return data


def validate_receipt_bytes(data):

    require(type(data) is bytes and 0 < len(data) <= 1048576,
            'PUBLIC_RECEIPT_BYTES', 'bounded immutable public receipt bytes required')

    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, 'PUBLIC_DUPLICATE_KEY', 'duplicate public receipt key')
            obj[key] = value
        return obj

    def reject_constant(value):
        require(False, 'PUBLIC_NONFINITE', 'nonfinite public receipt value forbidden')

    try:
        result = json.loads(data.decode('ascii'), object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError('PUBLIC_RECEIPT_JSON: invalid public receipt') from None
    require(type(result) is dict, 'PUBLIC_RECEIPT_OBJECT', 'public receipt must be object')
    schema = result.get('record_schema')
    if schema == POINT_SCHEMA:
        _validate_point_shape(result)
    elif schema == BOOTSTRAP_SCHEMA:
        _validate_bootstrap_shape(result)
    elif schema == PARTIAL_SCHEMA:
        _validate_partial_shape(result)
    else:
        require(False, 'PUBLIC_RECEIPT_SCHEMA', 'unknown public receipt schema')
    require(_canonical(result) == data, 'PUBLIC_RECEIPT_CANONICAL', 'noncanonical public bytes')
    return result
