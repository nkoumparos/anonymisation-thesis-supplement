import copy
import hashlib

from common import (
    cfg_contract, exact_keys, integer, json_digest, require,
)
from utility_evaluation import (
    assert_paired_utility_bootstrap, assert_row_y_alignment, prediction_bytes,
)


DATA_KEYS = {'X', 'x_row_ids', 'y', 'y_row_ids',
             'predictions', 'prediction_row_ids'}
MISSING_INTEGRATION = (
    'before_cv_training_and_validation',
    'before_final_model_fit',
    'model_prediction_producer',
    'production_utility_metrics_and_bootstrap_driver',
)


def _scope(record_schema, mode):
    return {
        'record_schema': record_schema,
        'result': 'PASS',
        'scope': 'partial_utility_consumer_integration',
        'integration_status': 'PARTIAL_CONSUMER_INTEGRATION_CANDIDATE',
        'private_payloads_in_return': True,
        'mode': mode,
        'section_12_1_step_7_status': 'pending',
        'gate_a_status': 'pending',
        'step7_assertions_activated': False,
        'main_runs_authorized': False,
        'main_runs_executed': False,
        'model_fits_executed': False,
        'predictions_generated': False,
        'rng_invoked': False,
        'bootstrap_indices_generated': False,
        'missing_integration': list(MISSING_INTEGRATION),
        'external_source_provenance_verified': False,
        'model_prediction_provenance_verified': False,
    }


def accept_predictions_by_cfg(*, feature_names, data_by_cfg, expected_row_ids,
                              source_rows_by_cfg, source_labels,
                              mode='operational'):

    require(isinstance(data_by_cfg, dict) and data_by_cfg,
            'UTILITY_CONFIGURATIONS', 'at least one CFG prediction array is required')
    for cfg in data_by_cfg:
        cfg_contract(cfg)
    exact_keys(source_rows_by_cfg, set(data_by_cfg), 'source_rows_by_cfg')
    accepted = {}
    receipts = {}
    identities = {}
    for cfg in sorted(data_by_cfg):
        data = data_by_cfg[cfg]
        exact_keys(data, DATA_KEYS, cfg + ' prediction submission')
        require(data['predictions'] is not None and
                data['prediction_row_ids'] is not None,
                'PREDICTION_ALIGNMENT',
                'prediction acceptance requires actual probabilities and their IDs')


        receipt = assert_row_y_alignment(
            feature_names, data['X'], data['x_row_ids'], data['y'],
            data['y_row_ids'], expected_row_ids, source_rows_by_cfg[cfg],
            source_labels, mode=mode, dataset_role='holdout',
            predictions=data['predictions'],
            prediction_row_ids=data['prediction_row_ids'])
        own_data = {
            'row_ids': list(expected_row_ids),
            'X': [list(row) for row in data['X']],
            'y': list(data['y']),
            'predictions': [[float(value) for value in row]
                            for row in data['predictions']],
        }
        prediction_sha = hashlib.sha256(prediction_bytes(
            own_data['row_ids'], own_data['predictions'])).hexdigest()
        require(prediction_sha == receipt['prediction_sha256'],
                'CONSUMER_PREDICTION_IDENTITY',
                'accepted prediction bytes differ from the checked values')
        accepted[cfg] = own_data
        receipts[cfg] = receipt
        identities[cfg] = {
            'row_order_sha256': json_digest(own_data['row_ids']),
            'X_sha256': json_digest(own_data['X']),
            'y_sha256': json_digest(own_data['y']),
            'prediction_sha256': prediction_sha,
        }
    result = _scope('step7-utility-prediction-consumer/1', mode)
    result.update(accepted_data=accepted, guard_receipts=receipts,
                  identities=identities,
                  accepted_prediction_array_count=len(accepted))
    return result


def _sample_accepted_arrays(accepted_data, resample_indices):

    return {
        cfg: {
            'row_ids': [data['row_ids'][index] for index in resample_indices],
            'y': [data['y'][index] for index in resample_indices],
            'predictions': [data['predictions'][index][:]
                            for index in resample_indices],
        }
        for cfg, data in accepted_data.items()
    }


def consume_paired_utility_bootstrap(*, feature_names, data_by_cfg,
                                    expected_row_ids, source_rows_by_cfg,
                                    source_labels, class_source_indices,
                                    resample_indices, replicate_id,
                                    mode='operational'):

    acceptance = accept_predictions_by_cfg(
        feature_names=feature_names, data_by_cfg=data_by_cfg,
        expected_row_ids=expected_row_ids, source_rows_by_cfg=source_rows_by_cfg,
        source_labels=source_labels, mode=mode)
    accepted = acceptance['accepted_data']
    require('CFG00' in accepted and len(accepted) >= 2,
            'BOOTSTRAP_CONFIGURATIONS',
            'paired utility consumption requires CFG00 and at least one output')
    integer(replicate_id, 'replicate_id', minimum=0)
    require(replicate_id < 2000, 'BOOTSTRAP_REPLICATE',
            'replicate_id must be 0..1999')
    require(isinstance(resample_indices, (list, tuple)), 'UTILITY_SEQUENCE',
            'resample_indices must be a list or tuple')
    indices = list(resample_indices)
    row_count = len(accepted['CFG00']['row_ids'])
    require(all(type(index) is int and 0 <= index < row_count for index in indices),
            'BOOTSTRAP_INDEX', 'resample indices must be valid zero-based integers')
    sampled = _sample_accepted_arrays(accepted, indices)
    indices_by_cfg = {cfg: indices[:] for cfg in accepted}


    receipt = assert_paired_utility_bootstrap(
        accepted['CFG00']['row_ids'], accepted['CFG00']['y'],
        class_source_indices,
        {cfg: data['predictions'] for cfg, data in accepted.items()},
        indices_by_cfg,
        {cfg: data['row_ids'] for cfg, data in sampled.items()},
        {cfg: data['y'] for cfg, data in sampled.items()},
        {cfg: data['predictions'] for cfg, data in sampled.items()},
        replicate_id=replicate_id, mode=mode)
    result = _scope('step7-paired-utility-consumer/1', mode)
    result.update(
        replicate_id=replicate_id,
        acceptance=acceptance,
        indices_by_cfg=indices_by_cfg,
        sampled_data=sampled,
        guard_receipt=receipt,
        identities={
            'resample_indices_sha256': json_digest(indices),
            'sampled_row_ids_sha256_by_cfg': {
                cfg: json_digest(data['row_ids']) for cfg, data in sampled.items()},
            'sampled_y_sha256_by_cfg': {
                cfg: json_digest(data['y']) for cfg, data in sampled.items()},
            'sampled_prediction_sha256_by_cfg': copy.deepcopy(
                receipt['prediction_sha256_by_cfg']),
        })
    return result
