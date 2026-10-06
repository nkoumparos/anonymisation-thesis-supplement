import copy
import json
import os
import sys
import warnings

from common import QIS, exact_keys, json_digest, require
from utility_evaluation import (
    ENCODER_PARAMETERS, ESTIMATOR_PARAMETERS, assert_model_convergence,
    assert_model_determinism, assert_row_y_alignment, validate_model_parameters,
)


def _rows(fixture, key):
    records = fixture[key]
    require(type(records) is list and len(records) == (16 if key == 'training' else 8),
            'SYNTHETIC_FIXTURE', 'Unexpected fixed synthetic population')
    expected_ids = ['synthetic.' + ('train' if key == 'training' else 'holdout') + ':' + format(i + 1, '02d')
                    for i in range(len(records))]
    for record in records:
        exact_keys(record, ('row_id', 'X', 'y'), 'synthetic fixture row')
    ids = [record['row_id'] for record in records]
    require(ids == expected_ids, 'SYNTHETIC_FIXTURE', 'Fixture identity order differs')
    X = [copy.deepcopy(record['X']) for record in records]
    y = [record['y'] for record in records]
    source_rows = {record['row_id']: copy.deepcopy(record['X']) for record in records}
    source_labels = {record['row_id']: record['y'] for record in records}
    alignment = assert_row_y_alignment(QIS, X, ids, y, list(ids), expected_ids,
        source_rows, source_labels, mode='fixture', dataset_role='raw_training' if key == 'training' else 'holdout')
    return ids, X, y, source_rows, source_labels, alignment


def run_synthetic_pilot(fixture, *, expected_executable, expected_fixture_sha256):

    require(sys.platform == 'win32' and sys.version_info[:3] == (3, 12, 10),
            'LOCKED_RUNTIME', 'The reviewed native CPython 3.12.10 runtime is required')
    require(os.path.normcase(os.path.abspath(sys.executable)) ==
            os.path.normcase(os.path.abspath(expected_executable)),
            'LOCKED_RUNTIME', 'Interpreter differs from the controlled validator')
    require(sys.flags.isolated and sys.dont_write_bytecode, 'LOCKED_RUNTIME',
            'Invoke the controlled validator with -I -B')
    require(json_digest(fixture) == expected_fixture_sha256, 'SYNTHETIC_FIXTURE',
            'Pinned synthetic fixture identity differs')
    require(fixture['record_schema'] == 'step7-synthetic-model-fixture/1'
            and fixture['scope'] == 'SYNTHETIC_ONLY_NO_ADULT_RECORDS'
            and fixture['predictor_order'] == list(QIS) and fixture['selected_C'] == 1.0
            and fixture['expected_fresh_fit_count'] == 2,
            'SYNTHETIC_FIXTURE', 'Synthetic pilot contract differs')
    before = json_digest(fixture)
    train_ids, train_X, train_y, _, _, train_alignment = _rows(fixture, 'training')
    test_ids, test_X, test_y, expected_test, expected_y, holdout_alignment = _rows(fixture, 'holdout')


    import numpy as np
    import sklearn
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
    require(np.__version__ == '2.0.2' and sklearn.__version__ == '1.9.0',
            'LOCKED_RUNTIME', 'Scientific package versions differ from the hashed lock')

    def actual_parameters(model, encoder):
        full_model = model.get_params(deep=False)
        full_encoder = encoder.get_params(deep=False)
        full_encoder['dtype'] = np.dtype(full_encoder['dtype']).name


        json.dumps(full_model, sort_keys=True, allow_nan=False)
        json.dumps(full_encoder, sort_keys=True, allow_nan=False)
        model_subset = {key: full_model[key] for key in (*ESTIMATOR_PARAMETERS, 'C')}
        encoder_subset = {key: full_encoder[key] for key in ENCODER_PARAMETERS}
        validate_model_parameters(model_subset, encoder_subset, selected_C=1.0)
        return model_subset, encoder_subset, full_model, full_encoder

    receipts = []
    prediction_alignments = []
    retained_objects = []
    for fit_index in range(2):
        encoder_args = dict(ENCODER_PARAMETERS, dtype=np.float64)
        model = LogisticRegression(C=1.0, **ESTIMATOR_PARAMETERS)
        encoder = OneHotEncoder(**encoder_args)
        pipeline = Pipeline([('onehot', encoder), ('logistic_regression', model)])
        require(all(pipeline is not old[0] and model is not old[1] and encoder is not old[2]
                    for old in retained_objects), 'FRESH_FIT', 'Fresh estimator objects are required')
        retained_objects.append((pipeline, model, encoder))
        before_parameters = actual_parameters(model, encoder)
        input_identity = json_digest([train_X, train_y, test_X])
        with warnings.catch_warnings(record=True) as observed_warnings:
            warnings.simplefilter('always')
            pipeline.fit(train_X, train_y)
            probabilities = pipeline.predict_proba(test_X)
        categories = [item.category.__module__ + '.' + item.category.__name__ for item in observed_warnings]
        parameters = actual_parameters(model, encoder)
        require(parameters == before_parameters, 'MODEL_PARAMETERS', 'Fit changed declared parameters')
        require(json_digest([train_X, train_y, test_X]) == input_identity,
                'MODEL_INPUT_MUTATION', 'Fit/prediction modified input arrays')
        n_iter = model.n_iter_.tolist()
        assert_model_convergence(n_iter, categories)
        values = probabilities.tolist()
        prediction_alignment = assert_row_y_alignment(QIS, test_X, test_ids, test_y, list(test_ids),
            test_ids, expected_test, expected_y, mode='fixture', dataset_role='holdout',
            predictions=values, prediction_row_ids=list(test_ids))
        prediction_alignments.append(prediction_alignment)
        receipts.append({
            'receipt_schema': 'step7-model-fit/1', 'fit_id': 'synthetic-fresh-fit-' + str(fit_index + 1),
            'fit_execution': 'actual_fresh_fit', 'estimator_parameters': parameters[0],
            'encoder_parameters': parameters[1], 'full_estimator_parameters': parameters[2],
            'full_encoder_parameters': parameters[3], 'preprocessing_fit_scope': 'training_rows_only',
            'predictor_order': list(QIS), 'training_role': 'raw_training',
            'training_row_ids': list(train_ids), 'training_X': copy.deepcopy(train_X), 'training_y': list(train_y),
            'holdout_row_ids': list(test_ids), 'holdout_X': copy.deepcopy(test_X),
            'class_order': model.classes_.tolist(), 'n_iter': n_iter,
            'warning_categories': categories, 'prediction_probabilities': values,
        })
    result = assert_model_determinism(*receipts, selected_C=1.0, mode='fixture')
    require(json_digest(fixture) == before, 'SYNTHETIC_FIXTURE', 'Pilot modified fixture')
    return {'record_schema': 'step7-synthetic-model-pilot/1', 'result': 'PASS',
            'fixture_sha256_canonical_json': before, 'fit_count': 2, 'fit_receipts': receipts,
            'training_alignment': train_alignment, 'holdout_alignment': holdout_alignment,
            'prediction_alignments': prediction_alignments, 'model_determinism': result,
            'python_executable': sys.executable, 'python_full_version': sys.version,
            'python_platform': sys.platform,
            'python_version': sys.version.split()[0], 'numpy_version': np.__version__,
            'sklearn_version': sklearn.__version__, 'scientific_packages_imported': True,
            'scientific_functions_invoked': True, 'model_fits_executed': True,
            'sklearn_internal_random_state_used': 11008, 'direct_numpy_rng_instantiated': False,
            'production_realizations_generated': False, 'Adult_rows_accessed': False,
            'C_selected_by_Adult_CV': False, 'section_12_1_step_7_status': 'pending',
            'gate_a_status': 'pending', 'gate_d_status': 'not_evaluated',
            'main_runs_authorized': False, 'main_runs_executed': False}


if __name__ == '__main__':
    raise SystemExit('Direct pilot execution is disabled. Use a separately reviewed controlled validator.')
