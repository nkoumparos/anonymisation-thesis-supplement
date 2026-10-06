import copy
import hashlib
import struct
import sys

from common import QIS, json_digest, require
from utility_evaluation import ENCODER_PARAMETERS


CHUNK_ROWS = 256


def _matrix(value, name):
    require(type(value) is list and value, 'DIAGNOSTIC_ROWS',
            name + ' must be a nonempty list')
    require(all(type(row) is list and len(row) == len(QIS) and
                all(type(item) is str and item and '\x00' not in item for item in row)
                for row in value), 'DIAGNOSTIC_ROWS',
            name + ' must have exactly eight nonempty categorical strings per row')
    json_digest(value)


def _native_type(value, module_name, class_name):
    module = sys.modules.get(module_name)
    return module is not None and type(value) is getattr(module, class_name, None)


def _parameters(encoder):
    parameters = copy.deepcopy(encoder.get_params(deep=False))
    require(type(parameters) is dict and set(parameters).issuperset(ENCODER_PARAMETERS),
            'DIAGNOSTIC_PARAMETERS', 'Actual encoder parameters are incomplete')
    dtype = parameters['dtype']
    if type(dtype) is not str:
        require(isinstance(dtype, type) and dtype.__module__ == 'numpy'
                and dtype.__name__ == 'float64', 'DIAGNOSTIC_PARAMETERS',
                'Actual dtype is not NumPy float64')
        parameters['dtype'] = 'float64'
    require(all(type(parameters[key]) is type(expected) and parameters[key] == expected
                for key, expected in ENCODER_PARAMETERS.items()),
            'DIAGNOSTIC_PARAMETERS', 'Actual encoder differs from the reviewed parameters')
    json_digest(parameters)
    return parameters


def _state(encoder, training_categories):
    categories = getattr(encoder, 'categories_', None)
    require(type(categories) in (list, tuple) and len(categories) == len(QIS),
            'DIAGNOSTIC_CATEGORIES', 'Actual categories_ must contain eight arrays')
    observed = []
    for i, values in enumerate(categories):
        require(callable(getattr(values, 'tolist', None)), 'DIAGNOSTIC_CATEGORIES',
                'Actual categories_ entries must be array objects')
        category = values.tolist()
        require(type(category) is list and category and
                all(type(item) is str for item in category) and
                category == training_categories[i],
                'DIAGNOSTIC_TRAINING_SCOPE',
                'Actual fitted categories differ from the current training strings')
        observed.append(category)
    n_features = getattr(encoder, 'n_features_in_', None)
    require(n_features == len(QIS) and not isinstance(n_features, bool),
            'DIAGNOSTIC_FEATURE_COUNT', 'Actual fitted encoder must have eight features')
    require(getattr(encoder, 'drop_idx_', None) is None,
            'DIAGNOSTIC_DROP', 'Fitted encoder must not drop categories')
    return {'parameters': _parameters(encoder), 'categories': observed,
            'n_features_in': int(n_features)}


def inspect_fitted_encoder(*, encoder, feature_names, training_X, prediction_X,
                           prediction_row_ids, prediction_role, execution_kind,
                           mode='operational'):

    require(mode in ('operational', 'fixture'), 'DIAGNOSTIC_MODE', 'Unknown mode')
    require(feature_names == list(QIS), 'DIAGNOSTIC_FEATURES', 'QI order differs')
    require(prediction_role in ('holdout', 'cv_validation'),
            'DIAGNOSTIC_ROLE', 'Unknown prediction role')
    require(execution_kind in ('NATIVE_SKLEARN', 'SYNTHETIC_TEST_DOUBLE'),
            'DIAGNOSTIC_BACKEND', 'Unknown execution classification')
    if execution_kind == 'NATIVE_SKLEARN':
        require(_native_type(encoder, 'sklearn.preprocessing._encoders', 'OneHotEncoder'),
                'DIAGNOSTIC_ENCODER_TYPE', 'Native diagnostics require the actual OneHotEncoder')
    else:
        require(mode == 'fixture', 'DIAGNOSTIC_BACKEND',
                'Synthetic doubles are allowed only in explicit fixture mode')
    _matrix(training_X, 'training_X')
    _matrix(prediction_X, 'prediction_X')
    require(type(prediction_row_ids) is list and len(prediction_row_ids) == len(prediction_X)
            and all(type(item) is str and item and '\x00' not in item
                    for item in prediction_row_ids)
            and len(set(prediction_row_ids)) == len(prediction_row_ids),
            'DIAGNOSTIC_ROW_IDS', 'Prediction row association differs')
    if mode == 'operational' and prediction_role == 'holdout':
        require(len(prediction_X) == 15060, 'DIAGNOSTIC_POPULATION',
                'The complete holdout population is required')
    before_inputs = json_digest([feature_names, training_X, prediction_X, prediction_row_ids])
    training_categories = [sorted(set(row[i] for row in training_X)) for i in range(len(QIS))]
    before = _state(encoder, training_categories)
    categories = before['categories']
    maps = [{value: position for position, value in enumerate(category)} for category in categories]
    offsets = [0]
    for category in categories:
        offsets.append(offsets[-1] + len(category))
    unknown_rows = [0] * len(QIS)
    unknown_values = [set() for _ in QIS]
    encoded_hash = hashlib.sha256(b'step7-onehot-sparse-coordinates/1\x00')
    encoded_hash.update(struct.pack('<QQ', len(prediction_X), offsets[-1]))
    transform_count = 0
    for start in range(0, len(prediction_X), CHUNK_ROWS):
        chunk = copy.deepcopy(prediction_X[start:start + CHUNK_ROWS])
        chunk_before = json_digest(chunk)
        transformed = encoder.transform(chunk)
        transform_count += 1
        if execution_kind == 'NATIVE_SKLEARN':
            require(_native_type(transformed, 'scipy.sparse._csr', 'csr_matrix'),
                    'DIAGNOSTIC_SPARSE_TYPE', 'Actual encoder transform must return CSR matrix')
        require(getattr(transformed, 'format', None) == 'csr'
                and transformed.shape == (len(chunk), offsets[-1])
                and str(transformed.dtype) == 'float64', 'DIAGNOSTIC_TRANSFORM_SHAPE',
                'Actual transform shape, sparse format or dtype differs')
        indptr = transformed.indptr.tolist()
        indices = transformed.indices.tolist()
        data = transformed.data.tolist()
        require(type(indptr) is list and type(indices) is list and type(data) is list
                and len(indptr) == len(chunk) + 1 and indptr[0] == 0
                and indptr[-1] == len(indices) == len(data)
                and all(type(value) is int and 0 <= value <= len(indices) for value in indptr)
                and indptr == sorted(indptr), 'DIAGNOSTIC_SPARSE_STRUCTURE',
                'Actual sparse row pointers are invalid')
        require(all(type(value) is int and 0 <= value < offsets[-1] for value in indices)
                and all(type(value) is float and value == 1.0 for value in data),
                'DIAGNOSTIC_ONEHOT_VALUES', 'Every stored coordinate must be a valid one')
        for local, row in enumerate(chunk):
            expected = []
            for feature, value in enumerate(row):
                if value in maps[feature]:
                    expected.append(offsets[feature] + maps[feature][value])
                else:
                    unknown_rows[feature] += 1
                    unknown_values[feature].add(value)
            actual = indices[indptr[local]:indptr[local + 1]]
            require(actual == expected, 'DIAGNOSTIC_ONEHOT_BLOCK',
                    'Unknown blocks must be all zero; known blocks must select the exact category')
            encoded_hash.update(struct.pack('<Q', len(actual)))
            for index in actual:
                encoded_hash.update(struct.pack('<Q', index))
        require(json_digest(chunk) == chunk_before, 'DIAGNOSTIC_INPUT_MUTATION',
                'Encoder transform changed its prediction input')
        require(_state(encoder, training_categories) == before, 'DIAGNOSTIC_ENCODER_MUTATION',
                'Transform changed fitted categories or actual parameters')
    require(json_digest([feature_names, training_X, prediction_X, prediction_row_ids])
            == before_inputs, 'DIAGNOSTIC_INPUT_MUTATION', 'Diagnostic inputs changed')
    return {
        'record_schema': 'step7-fitted-encoder-diagnostics/1', 'result': 'PASS',
        'mode': mode, 'execution_kind': execution_kind,
        'actual_native_encoder_transform_verified': execution_kind == 'NATIVE_SKLEARN',
        'new_native_validation_status': 'pending',
        'prediction_role': prediction_role, 'prediction_row_count': len(prediction_X),
        'prediction_row_order_sha256': json_digest(prediction_row_ids),
        'training_row_count': len(training_X),
        'fitted_categories_sha256': json_digest(categories),
        'actual_encoder_parameters_sha256': json_digest(before['parameters']),
        'transformed_shape': [len(prediction_X), offsets[-1]],
        'actual_sparse_coordinates_sha256': encoded_hash.hexdigest(),
        'sparse_hash_encoding': 'ASCII magic NUL; uint64-LE rows/columns; per-row uint64-LE nnz then indices',
        'transform_chunk_rows': CHUNK_ROWS, 'transform_call_count': transform_count,
        'counting_convention': 'distinct_unknown_values_and_affected_rows; rate_denominator_all_prediction_rows',
        'features': [{
            'qi': name, 'fitted_category_count': len(categories[i]),
            'distinct_unknown_value_count': len(unknown_values[i]),
            'unknown_row_count': unknown_rows[i],
            'unknown_row_rate': unknown_rows[i] / len(prediction_X),
            'all_zero_block_row_count': unknown_rows[i],
        } for i, name in enumerate(QIS)],
        'known_and_unknown_blocks_checked': True,
        'fitted_state_and_inputs_unchanged': True,
        'source_and_environment_provenance_verified': False,
        'diagnostics_used_for_tuning': False, 'private_values_in_receipt': False,
        'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
        'main_runs_authorized': False,
    }


if __name__ == '__main__':
    raise SystemExit('Direct execution disabled; use a separately reviewed model consumer.')
