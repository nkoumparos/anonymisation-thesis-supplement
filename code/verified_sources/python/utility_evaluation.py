import hashlib
import math
import struct

from common import (
    QIS, cfg_contract, exact_keys, integer, json_digest, number, require,
)


PREDICTION_MAGIC = b'step7-predict-proba-f64le/1\x00'
ENCODER_PARAMETERS = {
    'handle_unknown': 'ignore', 'categories': 'auto', 'drop': None,
    'dtype': 'float64', 'sparse_output': True, 'min_frequency': None,
    'max_categories': None, 'feature_name_combiner': 'concat',
}
ESTIMATOR_PARAMETERS = {
    'penalty': 'l2', 'solver': 'liblinear', 'max_iter': 2000,
    'class_weight': None, 'fit_intercept': True, 'random_state': 11008,

    'tol': 1e-4, 'dual': False, 'intercept_scaling': 1.0,
    'verbose': 0, 'warm_start': False,
}
FIT_RECEIPT_KEYS = {
    'receipt_schema', 'fit_id', 'fit_execution', 'estimator_parameters',
    'encoder_parameters', 'full_estimator_parameters', 'full_encoder_parameters',
    'preprocessing_fit_scope', 'predictor_order',
    'training_role', 'training_row_ids', 'training_X', 'training_y',
    'holdout_row_ids', 'holdout_X', 'class_order', 'n_iter',
    'warning_categories', 'prediction_probabilities',
}
TRAINING_ROLES = ('raw_training', 'released_training',
                  'counterfactual_training', 'cv_training')


def _sequence(value, name):
    require(isinstance(value, (list, tuple)), 'UTILITY_SEQUENCE',
            name + ' must be a list or tuple')
    return list(value)


def _ids(value, name, *, unique=True):
    result = _sequence(value, name)
    require(all(type(x) is str and x and '\x00' not in x for x in result),
            'ROW_ID', name + ' must contain nonempty exact string identities')
    for item in result:
        try:
            item.encode('utf-8', errors='strict')
        except UnicodeEncodeError:
            require(False, 'ROW_ID', name + ' contains an invalid Unicode ID')
    if unique:
        require(len(result) == len(set(result)), 'ROW_ID_DUPLICATE',
                name + ' must contain unique base-row identities')
    return result


def _labels(value, name):
    result = _sequence(value, name)
    require(all(type(x) is int and x in (0, 1) for x in result),
            'LABEL_ENCODING', name + ' must encode <=50K=0 and >50K=1')
    return result


def _matrix(value, name, expected_length):
    rows = _sequence(value, name)
    require(len(rows) == expected_length, 'ROW_LENGTH', name + ' length differs')
    result = []
    for row in rows:
        fields = _sequence(row, name + ' row')
        require(len(fields) == len(QIS), 'FEATURE_SCHEMA',
                name + ' must contain exactly eight predictors')
        require(all(type(v) is str and v and v.strip() and v != '?' and
                    '\x00' not in v for v in fields), 'CATEGORICAL_FEATURES',
                name + ' predictors must be nonmissing categorical strings')
        result.append(fields)
    return result


def _dimensions(count, mode, role):
    require(mode in ('operational', 'fixture'), 'UTILITY_MODE',
            'mode must explicitly be operational or fixture')
    require(role in TRAINING_ROLES + ('holdout', 'cv_validation'),
            'DATASET_ROLE', 'unsupported dataset role')
    require(count > 0, 'ROW_LENGTH', 'dataset is empty')
    if mode == 'fixture':
        return
    if role in ('raw_training', 'counterfactual_training'):
        require(count == 30162, 'OPERATIONAL_DIMENSIONS',
                'full training requires 30162 complete-case rows')
    elif role == 'holdout':
        require(count == 15060, 'OPERATIONAL_DIMENSIONS',
                'holdout requires 15060 complete-case rows without suppression')
    elif role == 'released_training':
        require(count <= 30162, 'OPERATIONAL_DIMENSIONS',
                'release training exceeds the full training population')
    elif role == 'cv_training':
        require(count in (24129, 24130), 'OPERATIONAL_DIMENSIONS',
                'five-fold CV training must have 24129 or 24130 rows')
    else:
        require(count in (6032, 6033), 'OPERATIONAL_DIMENSIONS',
                'five-fold CV validation must have 6032 or 6033 rows')


def _probabilities(values, row_count):
    rows = _sequence(values, 'prediction_probabilities')
    require(len(rows) == row_count, 'PREDICTION_LENGTH',
            'predictions must match the ordered row count')
    checked = []
    for row in rows:
        pair = _sequence(row, 'prediction row')
        require(len(pair) == 2, 'PREDICTION_SHAPE',
                'predict_proba must have exactly two columns in [0,1] class order')
        for value in pair:
            number(value, 'predicted probability')
            require(math.isfinite(float(value)) and 0.0 <= value <= 1.0,
                    'PREDICTION_RANGE', 'probability must be finite and in [0,1]')
        pair = [float(x) for x in pair]
        require(abs(sum(pair) - 1.0) <= 1e-12, 'PREDICTION_NORMALIZATION',
                'binary probability columns must sum to one within 1e-12')
        checked.append(pair)
    return checked


def prediction_bytes(row_ids, probabilities, *, allow_repeated_ids=False):

    ids = _ids(row_ids, 'prediction row IDs', unique=not allow_repeated_ids)
    require(ids, 'PREDICTION_LENGTH', 'prediction array must be nonempty')
    values = _probabilities(probabilities, len(ids))
    parts = [PREDICTION_MAGIC, struct.pack('<QQ', len(ids), 2)]
    for rid, row in zip(ids, values):
        encoded = rid.encode('utf-8')
        parts.extend((struct.pack('<Q', len(encoded)), encoded,
                      struct.pack('<dd', *row)))
    return b''.join(parts)


def assert_row_y_alignment(feature_names, X, x_row_ids, y, y_row_ids,
                           expected_row_ids, source_rows, source_labels, *,
                           mode='operational', dataset_role='holdout',
                           predictions=None, prediction_row_ids=None):

    require(tuple(_sequence(feature_names, 'feature_names')) == tuple(QIS),
            'FEATURE_SCHEMA', 'predictors must be exactly the frozen eight QIs')
    expected = _ids(expected_row_ids, 'independent expected row IDs')
    x_ids = _ids(x_row_ids, 'X row IDs')
    y_ids = _ids(y_row_ids, 'y row IDs')
    _dimensions(len(expected), mode, dataset_role)
    require(x_ids == expected and y_ids == expected, 'ROW_ORDER',
            'X/y identities differ from independent ordered identities')
    features = _matrix(X, 'X', len(expected))
    labels = _labels(y, 'y')
    require(len(labels) == len(expected), 'ROW_LENGTH', 'y length differs')
    require(isinstance(source_rows, dict) and isinstance(source_labels, dict),
            'INDEPENDENT_SOURCE', 'independent sources must be identity-keyed maps')
    require(all(rid in source_rows and rid in source_labels for rid in expected),
            'INDEPENDENT_SOURCE', 'independent expected row/label is missing')
    for pos, rid in enumerate(expected):
        independently_expected = _matrix([source_rows[rid]], 'source row', 1)[0]
        independently_expected_y = _labels([source_labels[rid]], 'source label')[0]
        require(features[pos] == independently_expected, 'ROW_CONTENT',
                'feature row differs from independently expected source identity')
        require(labels[pos] == independently_expected_y, 'ROW_LABEL',
                'label differs from independently expected source identity')
    require((predictions is None) == (prediction_row_ids is None),
            'PREDICTION_ALIGNMENT', 'predictions and their IDs must be supplied together')
    prediction_hash = None
    if predictions is not None:
        require(_ids(prediction_row_ids, 'prediction row IDs') == expected,
                'PREDICTION_ALIGNMENT', 'predictions have a different ordered identity vector')
        prediction_hash = hashlib.sha256(prediction_bytes(expected, predictions)).hexdigest()
    return {'guard': 'row_y_alignment', 'result': 'PASS', 'mode': mode,
            'dataset_role': dataset_role, 'rows': len(expected),
            'row_order_sha256': json_digest(expected),
            'training_X_sha256': json_digest(features), 'y_sha256': json_digest(labels),
            'prediction_sha256': prediction_hash}


def assert_paired_utility_bootstrap(base_row_ids, base_y, class_source_indices,
                                    base_predictions_by_cfg, indices_by_cfg,
                                    sampled_row_ids_by_cfg, sampled_y_by_cfg,
                                    sampled_predictions_by_cfg, *, replicate_id,
                                    mode='operational'):

    integer(replicate_id, 'replicate_id', minimum=0)
    require(replicate_id < 2000, 'BOOTSTRAP_REPLICATE', 'replicate_id must be 0..1999')
    ids = _ids(base_row_ids, 'base holdout row IDs')
    _dimensions(len(ids), mode, 'holdout')
    labels = _labels(base_y, 'base holdout y')
    require(len(labels) == len(ids), 'ROW_LENGTH', 'base holdout y length differs')
    require(set(labels) == {0, 1}, 'BOOTSTRAP_CLASSES', 'both holdout classes are required')
    exact_keys(class_source_indices, {0, 1}, 'class_source_indices')
    require(all(type(key) is int for key in class_source_indices), 'CLASS_SOURCE_ORDER',
            'class keys must be integer 0 and 1, not booleans')
    canonical = {c: [i for i, label in enumerate(labels) if label == c] for c in (0, 1)}
    for cls in (0, 1):
        supplied = _sequence(class_source_indices[cls], 'class-specific source indices')
        require(all(type(i) is int for i in supplied) and supplied == canonical[cls],
                'CLASS_SOURCE_ORDER', 'class source indices must preserve ascending holdout positions')
    require(isinstance(base_predictions_by_cfg, dict), 'BOOTSTRAP_CONFIGURATIONS',
            'base predictions must be configuration-keyed')
    cfgs = set(base_predictions_by_cfg)
    require('CFG00' in cfgs and len(cfgs) >= 2, 'BOOTSTRAP_CONFIGURATIONS',
            'paired bootstrap requires CFG00 and at least one output')
    for cfg in cfgs:
        cfg_contract(cfg)
    for mapping, name in ((indices_by_cfg, 'indices_by_cfg'),
                          (sampled_row_ids_by_cfg, 'sampled_row_ids_by_cfg'),
                          (sampled_y_by_cfg, 'sampled_y_by_cfg'),
                          (sampled_predictions_by_cfg, 'sampled_predictions_by_cfg')):
        exact_keys(mapping, cfgs, name)
    reference = _sequence(indices_by_cfg['CFG00'], 'CFG00 bootstrap indices')
    require(len(reference) == len(ids), 'BOOTSTRAP_CLASS_COUNTS',
            'stratified bootstrap must retain total holdout size')
    require(all(type(i) is int and 0 <= i < len(ids) for i in reference),
            'BOOTSTRAP_INDEX', 'bootstrap indices must be valid zero-based integers')
    expected_y = [labels[i] for i in reference]
    require(expected_y == [0] * len(canonical[0]) + [1] * len(canonical[1]),
            'BOOTSTRAP_CLASS_COUNTS', 'sample must preserve class counts and class 0 then 1 draw blocks')
    expected_ids = [ids[i] for i in reference]
    prediction_hashes = {}
    for cfg in sorted(cfgs):
        current = _sequence(indices_by_cfg[cfg], cfg + ' bootstrap indices')
        require(all(type(i) is int for i in current) and current == reference,
                'BOOTSTRAP_PAIRING', 'every CFG must use the identical replicate index vector')
        require(_ids(sampled_row_ids_by_cfg[cfg], cfg + ' sampled IDs', unique=False) == expected_ids,
                'BOOTSTRAP_ROW_ORDER', 'sampled identities differ from indexed base holdout')
        require(_labels(sampled_y_by_cfg[cfg], cfg + ' sampled y') == expected_y,
                'BOOTSTRAP_ROW_LABEL', 'sampled labels differ from indexed base holdout')
        base = _probabilities(base_predictions_by_cfg[cfg], len(ids))
        expected_values = [base[i] for i in reference]
        observed_bytes = prediction_bytes(expected_ids, sampled_predictions_by_cfg[cfg],
                                          allow_repeated_ids=True)
        expected_bytes = prediction_bytes(expected_ids, expected_values, allow_repeated_ids=True)
        require(observed_bytes == expected_bytes, 'BOOTSTRAP_PREDICTION_ALIGNMENT',
                'sampled predictions differ from this CFG indexed stored predictions')
        prediction_hashes[cfg] = hashlib.sha256(observed_bytes).hexdigest()
    return {'guard': 'paired_utility_bootstrap', 'result': 'PASS', 'mode': mode,
            'replicate_id': replicate_id, 'rows': len(ids),
            'class_counts': [len(canonical[0]), len(canonical[1])],
            'index_sha256': json_digest(reference), 'prediction_sha256_by_cfg': prediction_hashes}


def validate_model_parameters(estimator_parameters, encoder_parameters, *, selected_C):

    number(selected_C, 'selected_C')
    require(selected_C in (0.1, 1, 10), 'MODEL_C', 'C must be the externally frozen raw-CV selection')
    exact_keys(estimator_parameters, set(ESTIMATOR_PARAMETERS) | {'C'}, 'estimator_parameters')
    exact_keys(encoder_parameters, set(ENCODER_PARAMETERS), 'encoder_parameters')
    number(estimator_parameters['C'], 'estimator C')
    require(estimator_parameters['C'] == selected_C, 'MODEL_C', 'fit C differs from frozen C')
    for key, expected in ESTIMATOR_PARAMETERS.items():
        actual = estimator_parameters[key]
        require(type(actual) is type(expected) and actual == expected,
                'MODEL_PARAMETERS', 'actual estimator parameter differs: ' + key)
    for key, expected in ENCODER_PARAMETERS.items():
        actual = encoder_parameters[key]
        require(type(actual) is type(expected) and actual == expected,
                'ENCODER_PARAMETERS', 'actual encoder parameter differs: ' + key)
    return {'guard': 'model_parameters', 'result': 'PASS', 'selected_C': float(selected_C)}


def assert_model_convergence(n_iter, warning_categories):

    iterations = _sequence(n_iter, 'actual n_iter_')
    require(len(iterations) == 1, 'MODEL_N_ITER', 'binary liblinear must report one n_iter_ value')
    integer(iterations[0], 'actual n_iter_', minimum=0)
    require(iterations[0] < 2000, 'MODEL_CONVERGENCE', 'max_iter exhaustion blocks acceptance')
    warnings = _sequence(warning_categories, 'observed warning categories')
    require(all(type(w) is str and w for w in warnings), 'MODEL_WARNINGS', 'invalid warning category')
    require(not any(w.rsplit('.', 1)[-1] == 'ConvergenceWarning' for w in warnings),
            'MODEL_CONVERGENCE', 'ConvergenceWarning blocks acceptance')
    return {'guard': 'model_convergence', 'result': 'PASS', 'n_iter': iterations}


def _fit_identity(receipt, selected_C, mode):
    exact_keys(receipt, FIT_RECEIPT_KEYS, 'fit receipt')
    require(receipt['receipt_schema'] == 'step7-model-fit/1', 'FIT_RECEIPT_SCHEMA', 'unknown fit receipt schema')
    require(type(receipt['fit_id']) is str and receipt['fit_id'], 'FIT_ID', 'fit ID is required')
    require(receipt['fit_execution'] == 'actual_fresh_fit', 'FIT_EXECUTION', 'receipt must represent a fresh actual fit')
    require(receipt['preprocessing_fit_scope'] == 'training_rows_only', 'PREPROCESSING_SCOPE',
            'preprocessing must be fitted only on the current training rows/fold')
    require(tuple(_sequence(receipt['predictor_order'], 'predictor_order')) == tuple(QIS),
            'FEATURE_SCHEMA', 'fit predictor order differs from frozen eight QIs')
    require(receipt['training_role'] in TRAINING_ROLES, 'DATASET_ROLE', 'unsupported fit training role')
    validate_model_parameters(receipt['estimator_parameters'], receipt['encoder_parameters'], selected_C=selected_C)
    for full_name, selected_name in (
            ('full_estimator_parameters', 'estimator_parameters'),
            ('full_encoder_parameters', 'encoder_parameters')):
        full = receipt[full_name]
        selected = receipt[selected_name]
        require(isinstance(full, dict) and all(type(key) is str for key in full),
                'MODEL_FULL_PARAMETERS', 'complete actual get_params must be a string-keyed map')
        require(set(full).issuperset(selected), 'MODEL_FULL_PARAMETERS',
                'complete actual parameters omit a reviewed normalized parameter')
        require(all(type(full[key]) is type(value) and full[key] == value
                    for key, value in selected.items()), 'MODEL_FULL_PARAMETERS',
                'complete actual get_params contradicts normalized reviewed parameters')
        json_digest(full)
    assert_model_convergence(receipt['n_iter'], receipt['warning_categories'])
    train_ids = _ids(receipt['training_row_ids'], 'actual training row IDs')
    _dimensions(len(train_ids), mode, receipt['training_role'])
    train_X = _matrix(receipt['training_X'], 'actual training X', len(train_ids))
    train_y = _labels(receipt['training_y'], 'actual training y')
    require(len(train_y) == len(train_ids) and set(train_y) == {0, 1}, 'TRAINING_LABELS',
            'training labels must align in length and contain both classes')
    holdout_ids = _ids(receipt['holdout_row_ids'], 'actual prediction row IDs')
    prediction_role = 'cv_validation' if receipt['training_role'] == 'cv_training' else 'holdout'
    _dimensions(len(holdout_ids), mode, prediction_role)
    require(not set(train_ids).intersection(holdout_ids), 'TRAIN_HOLDOUT_OVERLAP',
            'training and prediction identities overlap; IDs must be source-qualified')
    if mode == 'operational' and receipt['training_role'] == 'cv_training':
        require(len(train_ids) + len(holdout_ids) == 30162, 'CV_PARTITION',
                'CV training and validation must partition the full training population')
    holdout_X = _matrix(receipt['holdout_X'], 'actual prediction X', len(holdout_ids))
    classes = _labels(receipt['class_order'], 'actual model classes_')
    require(classes == [0, 1], 'MODEL_CLASS_ORDER', 'model classes_ must be exactly [0,1]')
    data = prediction_bytes(holdout_ids, receipt['prediction_probabilities'])
    return {'predictor_order': list(QIS), 'training_role': receipt['training_role'],
            'full_estimator_parameters_sha256': json_digest(receipt['full_estimator_parameters']),
            'full_encoder_parameters_sha256': json_digest(receipt['full_encoder_parameters']),
            'training_row_order_sha256': json_digest(train_ids),
            'training_X_sha256': json_digest(train_X), 'training_y_sha256': json_digest(train_y),
            'holdout_row_order_sha256': json_digest(holdout_ids),
            'holdout_X_sha256': json_digest(holdout_X),
            'prediction_sha256': hashlib.sha256(data).hexdigest(),
            'prediction_bytes': len(data), 'training_rows': len(train_ids), 'prediction_rows': len(holdout_ids)}


def assert_model_determinism(first_receipt, second_receipt, *, selected_C, mode='operational'):

    first = _fit_identity(first_receipt, selected_C, mode)
    second = _fit_identity(second_receipt, selected_C, mode)
    require(first_receipt['fit_id'] != second_receipt['fit_id'], 'FIT_NOT_INDEPENDENT',
            'two distinct fresh-fit receipt IDs are required')
    input_keys = set(first) - {'prediction_sha256', 'prediction_bytes'}
    require(all(first[key] == second[key] for key in input_keys), 'MODEL_INPUT_IDENTITY',
            'two fits did not receive exactly identical ordered training/prediction inputs')
    require(first['prediction_sha256'] == second['prediction_sha256'] and
            first['prediction_bytes'] == second['prediction_bytes'], 'MODEL_DETERMINISM',
            'two identical fresh fits have different canonical prediction bits')
    return {'guard': 'model_determinism', 'result': 'PASS', 'mode': mode,
            'fit_ids': [first_receipt['fit_id'], second_receipt['fit_id']],
            'input_and_prediction_identities': first,
            'n_iter_per_fit': [list(first_receipt['n_iter']), list(second_receipt['n_iter'])],
            'prediction_serialization': 'step7-predict-proba-f64le/1',
            'gate_d_status': 'not_evaluated', 'section_12_1_step_7_status': 'pending'}
