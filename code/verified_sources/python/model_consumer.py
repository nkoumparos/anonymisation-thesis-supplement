import copy
import hashlib
import os
import sys
import warnings

from common import QIS, json_digest, require
from utility_evaluation import (
    ENCODER_PARAMETERS, ESTIMATOR_PARAMETERS, FIT_RECEIPT_KEYS, TRAINING_ROLES,
    assert_model_convergence, assert_row_y_alignment, prediction_bytes,
    validate_model_parameters,
)


def _native_factory(*, expected_executable, selected_C):

    require(sys.implementation.name == 'cpython' and sys.platform == 'win32'
            and sys.version_info[:3] == (3, 12, 10), 'LOCKED_RUNTIME',
            'Native CPython 3.12.10 on Windows is required')
    expected = os.path.normcase(os.path.abspath(expected_executable))
    require(os.path.normcase(os.path.abspath(sys.executable)) == expected,
            'LOCKED_RUNTIME', 'Interpreter differs from the controlled path')
    require(sys.flags.isolated and sys.dont_write_bytecode, 'LOCKED_RUNTIME',
            'The controlled interpreter must use -I -B')

    import numpy as np
    import sklearn
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder

    require(np.__version__ == '2.0.2' and sklearn.__version__ == '1.9.0',
            'LOCKED_RUNTIME', 'Scientific package versions differ from the lock')
    approved_site = os.path.normcase(os.path.realpath(os.path.join(
        os.path.dirname(os.path.dirname(expected)), 'Lib', 'site-packages')))
    origins = {}
    module_names = ('numpy', 'sklearn', LogisticRegression.__module__,
                    OneHotEncoder.__module__, Pipeline.__module__)
    for name in module_names:
        module = sys.modules.get(name)
        origin = getattr(module, '__file__', None)
        require(type(origin) is str and origin, 'LOCKED_MODULE_ORIGIN',
                'Required native module has no ordinary origin: ' + name)
        resolved = os.path.normcase(os.path.realpath(origin))
        try:
            beneath_site = os.path.commonpath((approved_site, resolved)) == approved_site
        except ValueError:
            beneath_site = False
        require(beneath_site and resolved != approved_site,
                'LOCKED_MODULE_ORIGIN', 'Module is outside the approved site: ' + name)
        origins[name] = resolved
    encoder = OneHotEncoder(**dict(ENCODER_PARAMETERS, dtype=np.float64))
    model = LogisticRegression(C=selected_C, **ESTIMATOR_PARAMETERS)
    pipeline = Pipeline([('onehot', encoder), ('logistic_regression', model)])
    runtime = {
        'backend_kind': 'NATIVE_SKLEARN',
        'python_executable': sys.executable,
        'python_version': sys.version.split()[0],
        'python_platform': sys.platform,
        'python_implementation': sys.implementation.name,
        'isolated': bool(sys.flags.isolated),
        'dont_write_bytecode': bool(sys.dont_write_bytecode),
        'numpy_version': np.__version__, 'sklearn_version': sklearn.__version__,
        'approved_site_packages': approved_site, 'checked_module_origins': origins,
    }
    return pipeline, model, encoder, runtime


def _dtype_name(value):


    if type(value) is str:
        return value
    require(isinstance(value, type) and value.__module__ == 'numpy'
            and value.__name__ == 'float64', 'ENCODER_DTYPE',
            'Actual encoder dtype is not the reviewed NumPy float64')
    return 'float64'


def _actual_parameters(model, encoder, selected_C):
    full_model = copy.deepcopy(model.get_params(deep=False))
    full_encoder = copy.deepcopy(encoder.get_params(deep=False))
    require(type(full_model) is dict and type(full_encoder) is dict,
            'MODEL_FULL_PARAMETERS', 'Actual get_params must return maps')
    require(all(type(key) is str for key in full_model)
            and all(type(key) is str for key in full_encoder),
            'MODEL_FULL_PARAMETERS', 'Actual parameter names must be strings')
    require(set(full_model).issuperset(set(ESTIMATOR_PARAMETERS) | {'C'})
            and set(full_encoder).issuperset(ENCODER_PARAMETERS),
            'MODEL_FULL_PARAMETERS', 'Actual get_params omits a reviewed parameter')
    full_encoder['dtype'] = _dtype_name(full_encoder['dtype'])

    json_digest(full_model)
    json_digest(full_encoder)
    model_subset = {key: full_model[key] for key in (*ESTIMATOR_PARAMETERS, 'C')}
    encoder_subset = {key: full_encoder[key] for key in ENCODER_PARAMETERS}
    guard = validate_model_parameters(model_subset, encoder_subset, selected_C=selected_C)
    return model_subset, encoder_subset, full_model, full_encoder, guard


def _bundle_structure(pipeline, model, encoder):
    steps = pipeline.named_steps
    require(list(steps) == ['onehot', 'logistic_regression']
            and steps['onehot'] is encoder and steps['logistic_regression'] is model,
            'MODEL_PIPELINE', 'Pipeline must contain the actual reviewed objects in order')
    parameters = pipeline.get_params(deep=False)
    require(parameters.get('memory') is None, 'MODEL_PIPELINE',
            'Pipeline caching must remain disabled')


def _warnings_categories(observed):
    return [item.category.__module__ + '.' + item.category.__name__ for item in observed]


def _actual_vector(value, name):
    require(hasattr(value, 'tolist'), 'MODEL_NATIVE_ARRAY',
            name + ' must be an actual estimator/prediction array')
    result = value.tolist()
    require(type(result) is list, 'MODEL_NATIVE_ARRAY', name + ' must be one-dimensional or matrix')
    return result


def _fit_predict_guarded(*, fit_id, feature_names, training_X, training_row_ids,
                        training_y, training_y_row_ids, prediction_X,
                        prediction_row_ids, prediction_y, prediction_y_row_ids,
                        expected_training_row_ids, expected_prediction_row_ids,
                        source_training_rows, source_training_labels,
                        source_prediction_rows, source_prediction_labels,
                        training_role, selected_C, expected_executable,
                        mode='operational', _progress):

    require(type(fit_id) is str and fit_id and '\x00' not in fit_id,
            'FIT_ID', 'An exact nonempty fit identity is required')
    require(training_role in TRAINING_ROLES, 'DATASET_ROLE',
            'Unsupported fit training role')
    require(type(expected_executable) is str and expected_executable
            and '\x00' not in expected_executable, 'LOCKED_RUNTIME',
            'The controlled native interpreter path is required')

    validate_model_parameters(dict(ESTIMATOR_PARAMETERS, C=selected_C),
                              dict(ENCODER_PARAMETERS), selected_C=selected_C)
    prediction_role = 'cv_validation' if training_role == 'cv_training' else 'holdout'
    train_alignment = assert_row_y_alignment(
        feature_names, training_X, training_row_ids, training_y, training_y_row_ids,
        expected_training_row_ids, source_training_rows, source_training_labels,
        mode=mode, dataset_role=training_role)
    before_prediction_alignment = assert_row_y_alignment(
        feature_names, prediction_X, prediction_row_ids, prediction_y,
        prediction_y_row_ids, expected_prediction_row_ids, source_prediction_rows,
        source_prediction_labels, mode=mode, dataset_role=prediction_role)
    require(set(training_y) == {0, 1}, 'TRAINING_LABELS',
            'Both training classes are required before constructing a model')
    require(not set(training_row_ids).intersection(prediction_row_ids),
            'TRAIN_HOLDOUT_OVERLAP', 'Training and prediction identities overlap')
    if mode == 'operational' and training_role == 'cv_training':
        require(len(training_row_ids) + len(prediction_row_ids) == 30162,
                'CV_PARTITION', 'CV training and validation must partition 30162 rows')

    original_inputs = {
        'feature_names': feature_names, 'training_X': training_X,
        'training_row_ids': training_row_ids, 'training_y': training_y,
        'training_y_row_ids': training_y_row_ids, 'prediction_X': prediction_X,
        'prediction_row_ids': prediction_row_ids, 'prediction_y': prediction_y,
        'prediction_y_row_ids': prediction_y_row_ids,
        'expected_training_row_ids': expected_training_row_ids,
        'expected_prediction_row_ids': expected_prediction_row_ids,
        'source_training_rows': source_training_rows,
        'source_training_labels': source_training_labels,
        'source_prediction_rows': source_prediction_rows,
        'source_prediction_labels': source_prediction_labels,
    }
    original_identity = json_digest(original_inputs)

    train_X = [list(row) for row in training_X]
    train_y = list(training_y)
    predict_X = [list(row) for row in prediction_X]
    working_identity = json_digest([train_X, train_y, predict_X])
    _progress.update(stage='construct_fresh_internal_model', native_factory_attempted=True)
    pipeline, model, encoder, runtime = _native_factory(
        expected_executable=expected_executable, selected_C=selected_C)
    require(type(runtime) is dict and runtime.get('backend_kind') in
            ('NATIVE_SKLEARN', 'SYNTHETIC_TEST_DOUBLE'), 'MODEL_BACKEND',
            'Internal model boundary returned an unsupported execution kind')
    native = runtime['backend_kind'] == 'NATIVE_SKLEARN'
    _progress.update(stage='validate_fresh_model_before_fit',
                     execution_kind=runtime['backend_kind'])
    require(native or mode == 'fixture', 'MODEL_BACKEND',
            'Test doubles cannot represent operational execution')
    _bundle_structure(pipeline, model, encoder)
    require(not any(hasattr(model, key) for key in ('coef_', 'classes_', 'n_iter_'))
            and not hasattr(encoder, 'categories_'), 'FRESH_FIT',
            'Internal factory returned previously fitted objects')
    parameters_before = _actual_parameters(model, encoder, selected_C)

    def unchanged():
        require(json_digest(original_inputs) == original_identity
                and json_digest([train_X, train_y, predict_X]) == working_identity,
                'MODEL_INPUT_MUTATION', 'Model construction/fit/prediction changed input data')
        _bundle_structure(pipeline, model, encoder)
        current = _actual_parameters(model, encoder, selected_C)
        require(current == parameters_before, 'MODEL_PARAMETERS',
                'Construction/fit/prediction changed actual parameters')
        return current

    unchanged()
    _progress.update(stage='fit_current_training_rows', fit_attempted=True)
    with warnings.catch_warnings(record=True) as fit_warnings:
        warnings.simplefilter('always')
        try:
            fitted = pipeline.fit(train_X, train_y)
        finally:
            _partial_warning_evidence(_progress, 'fit', _warnings_categories(fit_warnings))
    _progress.update(stage='assert_fit_convergence_before_prediction',
                     fit_returned_successfully=True)
    require(fitted is pipeline, 'MODEL_PIPELINE', 'Fit returned a different pipeline')
    categories_fit = _warnings_categories(fit_warnings)
    n_iter = _actual_vector(model.n_iter_, 'actual n_iter_')
    _progress['observed_n_iter_prefix'] = [item if type(item) in (int, bool) else
                                          'INVALID_TYPE' for item in n_iter[:8]]
    _progress['observed_n_iter_length'] = len(n_iter)

    fit_convergence = assert_model_convergence(n_iter, categories_fit)
    class_order = _actual_vector(model.classes_, 'actual classes_')
    require(class_order == [0, 1] and all(type(item) is int for item in class_order),
            'MODEL_CLASS_ORDER', 'Actual classes_ must be exactly integer [0,1]')
    unchanged()

    _progress.update(stage='predict_current_prediction_rows', prediction_attempted=True)
    with warnings.catch_warnings(record=True) as prediction_warnings:
        warnings.simplefilter('always')
        try:
            probabilities = pipeline.predict_proba(predict_X)
        finally:
            _partial_warning_evidence(_progress, 'prediction',
                                      _warnings_categories(prediction_warnings))
    _progress.update(stage='assert_prediction_and_preservation',
                     prediction_returned_successfully=True)
    categories_predict = _warnings_categories(prediction_warnings)
    categories = categories_fit + categories_predict
    parameters = unchanged()
    classes_after = _actual_vector(model.classes_, 'actual classes_')
    require(classes_after == class_order and all(type(item) is int for item in classes_after),
            'MODEL_CLASS_ORDER', 'Prediction changed the fitted class order')
    iterations_after = _actual_vector(model.n_iter_, 'actual n_iter_')
    require(iterations_after == n_iter,
            'MODEL_N_ITER', 'Prediction changed actual fitted n_iter_')
    final_convergence = assert_model_convergence(iterations_after, categories)
    values = _actual_vector(probabilities, 'actual predict_proba')
    prediction_alignment = assert_row_y_alignment(
        feature_names, predict_X, prediction_row_ids, prediction_y,
        prediction_y_row_ids, expected_prediction_row_ids, source_prediction_rows,
        source_prediction_labels, mode=mode, dataset_role=prediction_role,
        predictions=values, prediction_row_ids=list(prediction_row_ids))
    unchanged()

    private = {
        'receipt_schema': 'step7-model-fit/1', 'fit_id': fit_id,
        'fit_execution': 'actual_fresh_fit' if native else 'synthetic_test_double_fit',
        'estimator_parameters': parameters[0], 'encoder_parameters': parameters[1],
        'full_estimator_parameters': parameters[2], 'full_encoder_parameters': parameters[3],
        'preprocessing_fit_scope': 'training_rows_only', 'predictor_order': list(QIS),
        'training_role': training_role, 'training_row_ids': list(training_row_ids),
        'training_X': copy.deepcopy(train_X), 'training_y': list(train_y),
        'holdout_row_ids': list(prediction_row_ids), 'holdout_X': copy.deepcopy(predict_X),
        'class_order': list(class_order), 'n_iter': list(n_iter),
        'warning_categories': categories[:], 'prediction_probabilities': copy.deepcopy(values),
    }
    require(set(private) == FIT_RECEIPT_KEYS, 'FIT_RECEIPT_SCHEMA',
            'Internally captured fit receipt schema differs')
    encoded = prediction_bytes(prediction_row_ids, values)
    receipt = {
        'record_schema': 'step7-guarded-fit-consumer/1', 'result': 'PASS',
        'fit_id': fit_id, 'mode': mode, 'training_role': training_role,
        'prediction_role': prediction_role, 'selected_C': float(selected_C),
        'C_scope': ('raw_cv_candidate' if training_role == 'cv_training' else
                    'externally_supplied_final_selection_not_verified_by_consumer'),
        'execution_kind': runtime['backend_kind'],
        'actual_native_fit_count': 1 if native else 0,
        'synthetic_double_fit_count': 0 if native else 1,
        'runtime': copy.deepcopy(runtime),
        'runtime_provenance': 'UNVERIFIED_BY_THIS_CONSUMER',
        'complete_locked_payload_verification_performed': False,
        'external_source_provenance_verified': False,
        'freshness_basis': 'internal_constructor_and_pre_fit_unfitted_object_check',
        'private_fit_receipt_sha256': json_digest(private),
        'training_alignment': train_alignment,
        'pre_prediction_alignment': before_prediction_alignment,
        'prediction_alignment': prediction_alignment,
        'fit_convergence_before_prediction': fit_convergence,
        'final_convergence': final_convergence,
        'fit_warning_categories': categories_fit,
        'prediction_warning_categories': categories_predict,
        'input_payloads_unchanged': True,
        'full_estimator_parameters_sha256': json_digest(parameters[2]),
        'full_encoder_parameters_sha256': json_digest(parameters[3]),
        'prediction_bytes': len(encoded),
        'prediction_sha256': hashlib.sha256(encoded).hexdigest(),
        'new_native_validation_status': 'pending',
        'historical_v6_validation_applies_to_this_source': False,
        'private_payload_in_separate_return_field': True,
        'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
        'main_runs_authorized': False,
    }
    return {'private_fit_receipt': private, 'receipt': receipt}


def _partial_warning_evidence(progress, role, categories):

    progress[role + '_warning_category_count'] = len(categories)
    progress[role + '_warning_categories_prefix'] = [value[:256] for value in categories[:32]]
    progress[role + '_warning_evidence_truncated'] = (
        len(categories) > 32 or any(len(value) > 256 for value in categories))


def fit_predict_guarded(*, fit_id, feature_names, training_X, training_row_ids,
                        training_y, training_y_row_ids, prediction_X,
                        prediction_row_ids, prediction_y, prediction_y_row_ids,
                        expected_training_row_ids, expected_prediction_row_ids,
                        source_training_rows, source_training_labels,
                        source_prediction_rows, source_prediction_labels,
                        training_role, selected_C, expected_executable,
                        mode='operational'):

    arguments = dict(locals())
    progress = {
        'record_schema': 'step7-guarded-fit-partial/1', 'result': 'FAIL',
        'fit_id': fit_id[:256] if type(fit_id) is str else 'INVALID_FIT_ID',
        'fit_id_truncated': type(fit_id) is str and len(fit_id) > 256,
        'stage': 'validate_inputs_before_native_construction',
        'execution_kind': 'NOT_ESTABLISHED',
        'native_factory_attempted': False, 'fit_attempted': False,
        'fit_returned_successfully': False, 'prediction_attempted': False,
        'prediction_returned_successfully': False,
        'accepted': False, 'private_payloads_in_receipt': False,
        'runtime_provenance': 'UNVERIFIED_BY_THIS_CONSUMER',
        'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
        'main_runs_authorized': False,
    }
    try:
        return _fit_predict_guarded(**arguments, _progress=progress)
    except Exception as exc:


        try:
            exc.step7_model_fit_partial_receipt = copy.deepcopy(progress)
        except Exception:
            pass
        raise


if __name__ == '__main__':
    raise SystemExit('Use a separately reviewed controlled driver; direct execution is disabled.')
