import copy
import hashlib
import os
import struct
import sys
import warnings

from common import QIS, json_digest, number, require
from utility_evaluation import assert_row_y_alignment, prediction_bytes


PARAMETERS = {'strategy': 'prior', 'constant': None, 'random_state': None}
POPULATION_CONVENTION = 'one_complete_raw_training_population_baseline'


def _native_factory(*, expected_executable):

    require(sys.implementation.name == 'cpython' and sys.platform == 'win32'
            and sys.version_info[:3] == (3, 12, 10)
            and struct.calcsize('P') * 8 == 64, 'LOCKED_RUNTIME',
            'Native 64-bit CPython 3.12.10 on Windows is required')
    expected = os.path.normcase(os.path.abspath(expected_executable))
    require(os.path.normcase(os.path.abspath(sys.executable)) == expected,
            'LOCKED_RUNTIME', 'Interpreter differs from the controlled path')
    require(sys.flags.isolated and sys.dont_write_bytecode, 'LOCKED_RUNTIME',
            'The controlled interpreter must use -I -B')

    import numpy as np
    import sklearn
    from sklearn.dummy import DummyClassifier

    require(np.__version__ == '2.0.2' and sklearn.__version__ == '1.9.0',
            'LOCKED_RUNTIME', 'Scientific package versions differ from the lock')
    approved_site = os.path.normcase(os.path.realpath(os.path.join(
        os.path.dirname(os.path.dirname(expected)), 'Lib', 'site-packages')))
    origins = {}
    for name in ('numpy', 'sklearn', DummyClassifier.__module__):
        origin = getattr(sys.modules.get(name), '__file__', None)
        require(type(origin) is str and origin, 'LOCKED_MODULE_ORIGIN',
                'Required scientific module has no ordinary origin: ' + name)
        resolved = os.path.normcase(os.path.realpath(origin))
        try:
            beneath = os.path.commonpath((approved_site, resolved)) == approved_site
        except ValueError:
            beneath = False
        require(beneath and resolved != approved_site, 'LOCKED_MODULE_ORIGIN',
                'Module is outside the approved site: ' + name)
        origins[name] = resolved
    model = DummyClassifier(**PARAMETERS)
    return model, {
        'backend_kind': 'NATIVE_SKLEARN', 'python_executable': sys.executable,
        'python_version': sys.version.split()[0], 'python_platform': sys.platform,
        'python_implementation': sys.implementation.name, 'pointer_bits': 64,
        'isolated': bool(sys.flags.isolated),
        'dont_write_bytecode': bool(sys.dont_write_bytecode),
        'numpy_version': np.__version__, 'sklearn_version': sklearn.__version__,
        'approved_site_packages': approved_site, 'checked_module_origins': origins,
    }


def _actual_parameters(model):
    parameters = copy.deepcopy(model.get_params(deep=False))
    require(type(parameters) is dict and set(parameters) == set(PARAMETERS),
            'BASELINE_FULL_PARAMETERS', 'Actual Dummy parameters differ in keys')
    require(type(parameters['strategy']) is str
            and parameters['strategy'] == 'prior'
            and parameters['constant'] is None
            and parameters['random_state'] is None,
            'BASELINE_PARAMETERS', 'The baseline must use the fixed prior strategy')
    json_digest(parameters)
    return parameters


def _actual_array(value, name):
    require(hasattr(value, 'tolist'), 'BASELINE_NATIVE_ARRAY',
            name + ' must be an actual fitted or prediction array')
    values = value.tolist()
    require(type(values) is list, 'BASELINE_NATIVE_ARRAY', name + ' must be an array')
    return values


def _fitted_state(model, expected_priors):
    classes = _actual_array(model.classes_, 'classes_')
    require(classes == [0, 1] and all(type(value) is int for value in classes),
            'BASELINE_CLASS_ORDER', 'Actual classes_ must be integer [0, 1]')
    priors = _actual_array(model.class_prior_, 'class_prior_')
    require(len(priors) == 2, 'BASELINE_PRIORS', 'Two actual class priors are required')
    priors = [number(value, 'actual class prior') for value in priors]
    require(priors == expected_priors, 'BASELINE_PRIORS',
            'Actual priors differ from unweighted raw training label proportions')
    return classes, priors


def _warning_evidence(progress, role, observed):
    categories = [item.category.__module__ + '.' + item.category.__name__
                  for item in observed]
    progress[role + '_warning_count'] = len(categories)
    progress[role + '_warning_categories_prefix'] = [value[:256] for value in categories[:32]]
    progress[role + '_warning_evidence_truncated'] = (
        len(categories) > 32 or any(len(value) > 256 for value in categories))


def _scope(mode):
    return {
        'mode': mode, 'classification': 'separate_prior_baseline',
        'training_population_convention': POPULATION_CONVENTION,
        'training_population_convention_status': 'candidate_pending_control_adoption',
        'positive_class': 1, 'class_order': [0, 1],
        'primary_release_delta_included': False, 'privacy_release': False,
        'pareto_release': False, 'counterfactual_release': False,
        'cv_tuning_performed': False, 'encoder_used': False,
        'per_cfg_baselines_fitted': False,
        'runtime_provenance': 'UNVERIFIED_BY_THIS_CONSUMER',
        'complete_locked_payload_verification_performed': False,
        'external_source_provenance_verified': False,
        'native_baseline_validation_status': 'pending',
        'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
        'step7_assertions_activated': False, 'main_runs_authorized': False,
        'production_rng_realizations_generated': False,
    }


def _fit_prior_baseline_guarded(*, fit_id, feature_names, training_X,
                              training_row_ids, training_y, training_y_row_ids,
                              prediction_X, prediction_row_ids, prediction_y,
                              prediction_y_row_ids, expected_training_row_ids,
                              expected_prediction_row_ids, source_training_rows,
                              source_training_labels, source_prediction_rows,
                              source_prediction_labels, training_role,
                              expected_executable, mode, _progress):
    require(type(fit_id) is str and 0 < len(fit_id) <= 256 and '\x00' not in fit_id,
            'BASELINE_FIT_ID', 'A bounded nonempty fit identity is required')
    require(type(mode) is str and mode in ('operational', 'fixture'),
            'UTILITY_MODE', 'Mode must explicitly be operational or fixture')
    require(training_role == 'raw_training' and type(training_role) is str,
            'BASELINE_POPULATION', 'Only the complete raw training baseline is supported')
    require(type(expected_executable) is str and expected_executable
            and '\x00' not in expected_executable, 'LOCKED_RUNTIME',
            'The controlled native interpreter path is required')
    train_alignment = assert_row_y_alignment(
        feature_names, training_X, training_row_ids, training_y, training_y_row_ids,
        expected_training_row_ids, source_training_rows, source_training_labels,
        mode=mode, dataset_role='raw_training')
    holdout_alignment = assert_row_y_alignment(
        feature_names, prediction_X, prediction_row_ids, prediction_y,
        prediction_y_row_ids, expected_prediction_row_ids, source_prediction_rows,
        source_prediction_labels, mode=mode, dataset_role='holdout')
    require(set(training_y) == {0, 1}, 'BASELINE_TRAINING_CLASSES',
            'Both training classes are required')
    require(set(prediction_y) == {0, 1}, 'BASELINE_HOLDOUT_CLASSES',
            'Both holdout classes are required for the separate baseline metrics')
    require(not set(training_row_ids).intersection(prediction_row_ids),
            'TRAIN_HOLDOUT_OVERLAP', 'Training and holdout identities overlap')
    require(set(source_training_rows) == set(expected_training_row_ids)
            and set(source_training_labels) == set(expected_training_row_ids)
            and set(source_prediction_rows) == set(expected_prediction_row_ids)
            and set(source_prediction_labels) == set(expected_prediction_row_ids),
            'BASELINE_COMPLETE_SOURCES', 'Sources must cover exactly each complete population')
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
    positive_count = sum(train_y)
    expected_priors = [(len(train_y) - positive_count) / len(train_y),
                       positive_count / len(train_y)]
    _progress.update(stage='construct_fresh_internal_dummy', native_factory_attempted=True)
    model, runtime = _native_factory(expected_executable=expected_executable)
    require(type(runtime) is dict and runtime.get('backend_kind') in
            ('NATIVE_SKLEARN', 'SYNTHETIC_TEST_DOUBLE'), 'BASELINE_BACKEND',
            'Internal baseline boundary returned an unsupported execution kind')
    native = runtime['backend_kind'] == 'NATIVE_SKLEARN'
    _progress.update(stage='validate_fresh_dummy_before_fit',
                     execution_kind=runtime['backend_kind'])
    require(native or mode == 'fixture', 'BASELINE_BACKEND',
            'Test doubles cannot represent operational execution')
    require(not any(hasattr(model, name) for name in
                    ('classes_', 'class_prior_', 'n_outputs_', 'n_classes_', 'sparse_output_')),
            'FRESH_BASELINE_FIT', 'The internal estimator must be newly constructed and unfitted')
    parameters_before = _actual_parameters(model)

    def unchanged():
        require(json_digest(original_inputs) == original_identity
                and json_digest([train_X, train_y, predict_X]) == working_identity,
                'BASELINE_INPUT_MUTATION', 'Baseline construction or execution changed inputs')
        current = _actual_parameters(model)
        require(current == parameters_before, 'BASELINE_PARAMETERS',
                'Baseline execution changed actual parameters')
        return current

    def preserve_failure():
        try:
            unchanged()
            _progress['input_and_parameter_preservation_after_failure'] = 'PASS'
        except Exception as preservation_error:
            _progress['input_and_parameter_preservation_after_failure'] = 'FAIL'
            code = getattr(preservation_error, 'code', None)
            _progress['preservation_failure_code'] = (
                code if type(code) is str and len(code) <= 128 else 'PRESERVATION_CHECK_ERROR')

    unchanged()
    try:
        _progress.update(stage='fit_complete_raw_training_once', fit_attempted=True)
        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter('always')
            try:
                fitted = model.fit(train_X, train_y)
            finally:
                _warning_evidence(_progress, 'fit', observed)
        _progress.update(stage='verify_fitted_priors_before_prediction',
                         fit_returned_successfully=True,
                         actual_native_fit_return_count=1 if native else 0,
                         synthetic_double_fit_return_count=0 if native else 1)
        require(fitted is model, 'BASELINE_FIT_RETURN', 'Fit returned a different estimator')
        classes, priors = _fitted_state(model, expected_priors)
        unchanged()
        _progress.update(stage='predict_common_holdout_once', prediction_attempted=True)
        with warnings.catch_warnings(record=True) as observed:
            warnings.simplefilter('always')
            try:
                probabilities = model.predict_proba(predict_X)
            finally:
                _warning_evidence(_progress, 'prediction', observed)
        _progress.update(stage='verify_actual_constant_predictions',
                         prediction_returned_successfully=True)
        unchanged()
        require(_fitted_state(model, expected_priors) == (classes, priors),
                'BASELINE_FITTED_MUTATION', 'Prediction changed the actual fitted state')
        values = _actual_array(probabilities, 'predict_proba')
        prediction_alignment = assert_row_y_alignment(
            feature_names, predict_X, prediction_row_ids, prediction_y,
            prediction_y_row_ids, expected_prediction_row_ids, source_prediction_rows,
            source_prediction_labels, mode=mode, dataset_role='holdout',
            predictions=values, prediction_row_ids=list(prediction_row_ids))
        require(all([number(item, 'actual predicted probability') for item in row] == priors
                    for row in values), 'BASELINE_PRIOR_PREDICTIONS',
                'Every actual probability row must equal the fitted class priors')
        unchanged()
    except Exception as exc:
        preserve_failure()
        raise


    holdout_positive_count = sum(prediction_y)
    holdout_count = len(prediction_y)
    predicted_class = 1 if priors[1] >= 0.5 else 0
    correct = holdout_positive_count if predicted_class else holdout_count - holdout_positive_count
    metrics = {
        'auroc': 0.5, 'average_precision': holdout_positive_count / holdout_count,
        'balanced_accuracy': 0.5, 'accuracy': correct / holdout_count,
    }
    private = {
        'receipt_schema': 'step7-prior-baseline-private/1', 'fit_id': fit_id,
        'fit_execution': 'actual_fresh_fit' if native else 'synthetic_test_double_fit',
        'classification': 'separate_prior_baseline', 'training_role': 'raw_training',
        'feature_names': list(QIS), 'training_row_ids': list(training_row_ids),
        'training_X': copy.deepcopy(train_X), 'training_y': list(train_y),
        'holdout_row_ids': list(prediction_row_ids), 'holdout_X': copy.deepcopy(predict_X),
        'holdout_y': list(prediction_y), 'class_order': list(classes),
        'class_prior': list(priors), 'full_estimator_parameters': parameters_before,
        'prediction_probabilities': copy.deepcopy(values),
    }
    encoded = prediction_bytes(prediction_row_ids, values)
    receipt = dict(_scope(mode), record_schema='step7-prior-baseline-consumer/1',
                   result='PASS', fit_id=fit_id, training_role='raw_training',
                   prediction_role='holdout', execution_kind=runtime['backend_kind'],
                   actual_native_fit_count=1 if native else 0,
                   synthetic_double_fit_count=0 if native else 1,
                   runtime=copy.deepcopy(runtime), training_alignment=train_alignment,
                   pre_prediction_alignment=holdout_alignment,
                   prediction_alignment=prediction_alignment,
                   training_class_counts=[len(train_y) - positive_count, positive_count],
                   holdout_class_counts=[holdout_count - holdout_positive_count, holdout_positive_count],
                   fitted_class_prior=list(priors), actual_class_priors_verified=True,
                   actual_constant_probability_rows_verified=True,
                   full_estimator_parameters_sha256=json_digest(parameters_before),
                   input_payloads_unchanged=True, prediction_bytes=len(encoded),
                   prediction_sha256=hashlib.sha256(encoded).hexdigest(),
                   private_baseline_receipt_sha256=json_digest(private),
                   private_payload_in_separate_return_field=True,
                   private_payloads_in_receipt=False, point_metrics=metrics,
                   point_metric_basis='closed_form_after_actual_constant_probability_validation',
                   threshold=0.5, threshold_comparison='positive_probability_greater_than_or_equal',
                   threshold_status='explicit_candidate_implementation_convention',
                   accuracy_role='descriptive', intervals=None, primary_delta_auroc=None,
                   n_iter_convergence_check_applicable=False,
                   completed_fit_invocations=1, completed_prediction_invocations=1)
    for key, value in _progress.items():
        if '_warning_' in key:
            receipt[key] = copy.deepcopy(value)
    return {'private_baseline_receipt': private, 'receipt': receipt}


def fit_prior_baseline_guarded(*, fit_id, feature_names, training_X, training_row_ids,
                              training_y, training_y_row_ids, prediction_X,
                              prediction_row_ids, prediction_y, prediction_y_row_ids,
                              expected_training_row_ids, expected_prediction_row_ids,
                              source_training_rows, source_training_labels,
                              source_prediction_rows, source_prediction_labels,
                              expected_executable, training_role='raw_training',
                              mode='operational'):

    arguments = dict(locals())
    bounded_mode = mode if type(mode) is str and mode in ('operational', 'fixture') else 'INVALID'
    progress = dict(_scope(bounded_mode), record_schema='step7-prior-baseline-partial/1',
                    result='FAIL', fit_id=fit_id[:256] if type(fit_id) is str else 'INVALID',
                    stage='validate_inputs_before_native_construction',
                    execution_kind='NOT_ESTABLISHED', native_factory_attempted=False,
                    fit_attempted=False, fit_returned_successfully=False,
                    actual_native_fit_return_count=0, synthetic_double_fit_return_count=0,
                    prediction_attempted=False, prediction_returned_successfully=False,
                    accepted=False, private_payloads_in_receipt=False)
    try:
        return _fit_prior_baseline_guarded(**arguments, _progress=progress)
    except Exception as exc:
        try:
            exc.step7_dummy_baseline_partial_receipt = copy.deepcopy(progress)
        except Exception:
            pass
        raise


if __name__ == '__main__':
    raise SystemExit('Use a separately reviewed controlled driver; direct execution is disabled.')
