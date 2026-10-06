import hashlib
import math

from common import json_digest, require
from utility_consumer import (
    accept_predictions_by_cfg, consume_paired_utility_bootstrap,
)


METRIC_NAMES = ('auroc', 'average_precision', 'balanced_accuracy', 'accuracy')
OPERATIONAL_CFGS = frozenset('CFG%02d' % index for index in range(17))
CLASSIFICATIONS = ('release_evaluation', 'counterfactual_evaluation')
CONVENTIONS = {
    'positive_class': 1,
    'probability_column': 1,
    'auroc': 'average_rank_ties',
    'average_precision': 'recall_increment_times_precision_at_complete_tie_groups',
    'balanced_accuracy_threshold': 0.5,
    'threshold_comparison': 'positive_probability_greater_than_or_equal',
    'threshold_status': 'explicit_candidate_implementation_convention',
    'accuracy_role': 'descriptive',
    'delta_direction': 'CFG00_AUROC_minus_released_CFG_AUROC',
    'interval_method': 'percentile_linear_interpolation_type_7',
    'interval_percentiles': [2.5, 97.5],
    'interval_method_status': 'explicit_candidate_implementation_convention',
}


def _scope(schema, mode, classification):
    return {
        'record_schema': schema,
        'result': 'PASS',
        'scope': 'supplied_prediction_utility_metrics_consumer_candidate',
        'mode': mode,
        'classification': classification,
        'private_payloads_in_return': False,
        'section_12_1_step_7_status': 'pending',
        'gate_a_status': 'pending',
        'step7_assertions_activated': False,
        'main_runs_authorized': False,
        'main_runs_executed': False,
        'model_fits_executed': False,
        'predictions_generated': False,
        'rng_instantiated': False,
        'rng_invoked': False,
        'bootstrap_indices_generated': False,
        'scientific_packages_imported': False,
        'external_source_provenance_verified': False,
        'model_prediction_provenance_verified': False,
        'external_bootstrap_index_producer_provenance_verified': False,
        'unknown_category_rates_evaluated': False,
        'dummy_baselines_evaluated': False,
        'primary_release_delta_reported': classification == 'release_evaluation',
        'conventions': {key: value[:] if isinstance(value, list) else value
                        for key, value in CONVENTIONS.items()},
    }


def _validate_scope(data_by_cfg, mode, classification):
    require(type(mode) is str and mode in ('operational', 'fixture'),
            'UTILITY_MODE', 'mode must explicitly be operational or fixture')
    require(type(classification) is str and classification in CLASSIFICATIONS,
            'METRIC_CLASSIFICATION', 'unsupported utility evaluation classification')
    require(isinstance(data_by_cfg, dict), 'METRIC_CONFIGURATIONS',
            'data_by_cfg must be an actual CFG-keyed dictionary')
    cfgs = set(data_by_cfg)
    require('CFG00' in cfgs and len(cfgs) >= 2, 'METRIC_CONFIGURATIONS',
            'utility evaluation requires CFG00 and at least one output CFG')
    if mode == 'operational':
        require(cfgs == OPERATIONAL_CFGS, 'METRIC_CONFIGURATIONS',
                'operational evaluation requires exactly CFG00 through CFG16')


def _score_checked(y, predictions, *, auroc_only=False):

    require(set(y) == {0, 1}, 'METRIC_CLASSES',
            'both binary holdout classes are required for utility metrics')
    count = len(y)
    positive_count = sum(y)
    negative_count = count - positive_count
    ordered = sorted((row[1], label) for row, label in zip(predictions, y))
    positive_rank_sum = 0.0
    ap_terms = []
    positives_below = 0
    start = 0
    while start < count:
        end = start + 1
        while end < count and ordered[end][0] == ordered[start][0]:
            end += 1
        group_positives = sum(label for _, label in ordered[start:end])
        average_rank = (start + 1 + end) / 2.0
        positive_rank_sum += group_positives * average_rank


        if group_positives and not auroc_only:
            precision_at_threshold = (positive_count - positives_below) / (count - start)
            ap_terms.append((group_positives / positive_count) * precision_at_threshold)
        positives_below += group_positives
        start = end
    auroc = (positive_rank_sum - positive_count * (positive_count + 1) / 2.0) / (
        positive_count * negative_count)
    if auroc_only:
        return {'auroc': auroc}
    true_positive = sum(label == 1 and row[1] >= 0.5
                        for label, row in zip(y, predictions))
    true_negative = sum(label == 0 and row[1] < 0.5
                        for label, row in zip(y, predictions))
    return {
        'auroc': auroc,
        'average_precision': math.fsum(ap_terms),
        'balanced_accuracy': (true_positive / positive_count +
                              true_negative / negative_count) / 2.0,
        'accuracy': (true_positive + true_negative) / count,
    }


def _delta(metrics, classification):
    if classification == 'counterfactual_evaluation':
        return None
    return {cfg: metrics['CFG00']['auroc'] - values['auroc']
            for cfg, values in metrics.items() if cfg != 'CFG00'}


def evaluate_utility_predictions(*, feature_names, data_by_cfg, expected_row_ids,
                                 source_rows_by_cfg, source_labels,
                                 mode='operational', classification='release_evaluation'):

    _validate_scope(data_by_cfg, mode, classification)
    acceptance = accept_predictions_by_cfg(
        feature_names=feature_names, data_by_cfg=data_by_cfg,
        expected_row_ids=expected_row_ids, source_rows_by_cfg=source_rows_by_cfg,
        source_labels=source_labels, mode=mode)
    accepted = acceptance['accepted_data']
    metrics = {cfg: _score_checked(data['y'], data['predictions'])
               for cfg, data in accepted.items()}
    reference_y = accepted['CFG00']['y']
    result = _scope('step7-utility-metric-consumer/1', mode, classification)
    result.update(
        configuration_count=len(accepted),
        holdout_row_count=len(reference_y),
        class_counts=[reference_y.count(0), reference_y.count(1)],
        metrics_by_cfg=metrics,
        delta_auroc_by_cfg=_delta(metrics, classification),
        accepted_input_identities=acceptance['identities'],
        alignment_guard_receipts_sha256=json_digest(acceptance['guard_receipts']),
        alignment_guard_count=len(accepted),
    )
    return result


def _interval(values):
    """Type-7 quantiles at exact rational positions 1/40 and 39/40."""
    ordered = sorted(values)
    endpoints = []
    for numerator in (1, 39):
        quotient, remainder = divmod((len(ordered) - 1) * numerator, 40)
        lower = ordered[quotient]
        upper = ordered[min(quotient + 1, len(ordered) - 1)]
        endpoints.append(lower + (upper - lower) * (remainder / 40.0))
    return endpoints


def bootstrap_utility_intervals(*, feature_names, data_by_cfg, expected_row_ids,
                                source_rows_by_cfg, source_labels,
                                class_source_indices, resample_indices_by_replicate,
                                mode='operational', classification='release_evaluation'):

    _validate_scope(data_by_cfg, mode, classification)
    require(isinstance(resample_indices_by_replicate, (list, tuple)),
            'METRIC_REPLICATE_SEQUENCE', 'ordered replicate vectors must be a list or tuple')
    replicate_count = len(resample_indices_by_replicate)
    require((mode == 'operational' and replicate_count == 2000) or
            (mode == 'fixture' and 2 <= replicate_count <= 2000),
            'METRIC_REPLICATE_COUNT',
            'operational bootstrap requires 2000 supplied replicates; fixture requires 2..2000')
    base_args = dict(feature_names=feature_names, data_by_cfg=data_by_cfg,
                     expected_row_ids=expected_row_ids, source_rows_by_cfg=source_rows_by_cfg,
                     source_labels=source_labels, mode=mode)
    point = evaluate_utility_predictions(**base_args, classification=classification)
    cfgs = sorted(data_by_cfg)
    series = {cfg: [] for cfg in cfgs}
    delta_series = {cfg: [] for cfg in cfgs if cfg != 'CFG00'}
    guard_digest = hashlib.sha256(b'step7-utility-bootstrap-guard-sequence/1\x00')
    metrics_digest = hashlib.sha256(b'step7-utility-bootstrap-metric-sequence/1\x00')
    index_receipts = []
    completed = 0
    for replicate_id, indices in enumerate(resample_indices_by_replicate):
        try:
            consumed = consume_paired_utility_bootstrap(
                **base_args, class_source_indices=class_source_indices,
                resample_indices=indices, replicate_id=replicate_id)
            index_receipts.append({
                'replicate_id': replicate_id,
                'resample_indices_sha256': consumed['identities']['resample_indices_sha256'],
            })


            replicate_metrics = {
                cfg: _score_checked(data['y'], data['predictions'], auroc_only=True)
                for cfg, data in consumed['sampled_data'].items()}
            paired_delta = _delta(replicate_metrics, classification)
            for cfg in cfgs:
                series[cfg].append(replicate_metrics[cfg]['auroc'])
                if paired_delta is not None and cfg != 'CFG00':
                    delta_series[cfg].append(paired_delta[cfg])
            guard_digest.update(bytes.fromhex(json_digest(consumed['guard_receipt'])))
            metrics_digest.update(bytes.fromhex(json_digest({
                'replicate_id': replicate_id,
                'auroc_by_cfg': {cfg: metrics['auroc']
                                 for cfg, metrics in replicate_metrics.items()},
                'delta_auroc_by_cfg': paired_delta})))
            completed += 1
        except Exception as error:
            error.partial_receipt = {
                'record_schema': 'step7-utility-bootstrap-partial/1',
                'result': 'FAIL', 'mode': mode, 'classification': classification,
                'failed_replicate_id': replicate_id,
                'fully_scored_replicate_count': completed,
                'validated_replicate_count': len(index_receipts),
                'replicate_index_receipts': [dict(receipt) for receipt in index_receipts],
                'requested_replicate_count': replicate_count,
                'partial_intervals_returned': False,
                'private_payloads_in_return': False,
                'completed_guard_sequence_sha256': guard_digest.hexdigest(),
                'step7_assertions_activated': False,
                'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
                'main_runs_authorized': False, 'main_runs_executed': False,
            }
            raise
    result = _scope('step7-utility-bootstrap-metric-consumer/1', mode, classification)
    result.update(
        configuration_count=len(cfgs), holdout_row_count=point['holdout_row_count'],
        class_counts=point['class_counts'],
        supplied_replicate_count=replicate_count,
        fully_scored_replicate_count=completed,
        replicate_index_receipts=index_receipts,
        replicate_index_receipt_count=len(index_receipts),
        fixture_intervals_are_protocol_evidence=False if mode == 'fixture' else None,
        point_metrics_by_cfg=point['metrics_by_cfg'],
        point_delta_auroc_by_cfg=point['delta_auroc_by_cfg'],
        metric_intervals_by_cfg={cfg: {'auroc': _interval(values)}
                                 for cfg, values in series.items()},
        delta_auroc_intervals_by_cfg=(None if classification == 'counterfactual_evaluation'
                                      else {cfg: _interval(values)
                                            for cfg, values in delta_series.items()}),
        accepted_input_identities=point['accepted_input_identities'],
        class_source_indices_sha256=json_digest(class_source_indices),
        supplied_replicate_sequence_sha256=json_digest(resample_indices_by_replicate),
        paired_postconstruction_guard_count=completed,
        paired_guard_sequence_sha256=guard_digest.hexdigest(),
        scored_replicate_sequence_sha256=metrics_digest.hexdigest(),
        pairing='identical_supplied_indices_for_all_CFGs_within_each_replicate',
        delta_interval_construction='percentiles_of_paired_replicate_differences',
    )
    return result
