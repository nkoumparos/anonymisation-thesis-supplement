import copy
import hashlib
import math
import os
import re
import sys

from common import (
    QIS, RID_ORDER_SHA256, cfg_contract, exact_keys, json_digest, require,
)
from utility_evaluation import assert_row_y_alignment
from model_consumer import fit_predict_guarded


MASTER_PERMUTATION_SHA256 = '4e1f8403536e0016645e42663763fd8551ca2f6babdd8185a1f30b7a6a017066'
CANDIDATE_CS = (0.1, 1.0, 10.0)
DATA_KEYS = {'X', 'x_row_ids', 'y', 'y_row_ids'}
SOURCE_KEYS = {'rows', 'labels'}
EXPECTED_OUTPUT_CFGS = {'CFG' + format(i, '02d') for i in range(1, 17)}


def _native_runtime(expected_executable):
    require(type(expected_executable) is str and expected_executable,
            'DRIVER_RUNTIME', 'The reviewed outer runner must supply its approved interpreter')
    require(sys.platform == 'win32' and sys.version_info[:3] == (3, 12, 10),
            'DRIVER_RUNTIME', 'Native CPython 3.12.10 Windows is required')
    require(sys.flags.isolated and sys.dont_write_bytecode,
            'DRIVER_RUNTIME', 'The controlled native invocation requires -I -B')
    require(os.path.normcase(os.path.abspath(sys.executable)) ==
            os.path.normcase(os.path.abspath(expected_executable)),
            'DRIVER_RUNTIME', 'Interpreter differs from the outer runner')


    import numpy
    import sklearn
    require(numpy.__version__ == '2.0.2' and sklearn.__version__ == '1.9.0',
            'DRIVER_RUNTIME', 'Package versions differ from the frozen environment')


def _native_cv_plan(X, y, expected_executable):
    _native_runtime(expected_executable)
    from sklearn.model_selection import StratifiedKFold
    splitter = StratifiedKFold(n_splits=5, shuffle=True, random_state=11004)
    return [{'training_indices': train.tolist(), 'validation_indices': validation.tolist()}
            for train, validation in splitter.split(X, y)]


def _native_auroc(y, probabilities, expected_executable):
    _native_runtime(expected_executable)
    from sklearn.metrics import roc_auc_score

    return float(roc_auc_score(y, [pair[1] for pair in probabilities]))


def _ids(values, name):
    require(type(values) is list and values,
            'DRIVER_IDS', name + ' must be a nonempty list')
    require(all(type(rid) is str and rid and '\x00' not in rid for rid in values),
            'DRIVER_IDS', name + ' must contain exact string identities')
    require(len(values) == len(set(values)), 'DRIVER_IDS', name + ' contains duplicates')
    return list(values)


def _line_hash(values):
    return hashlib.sha256(('\n'.join(str(item) for item in values) + '\n').encode('ascii')).hexdigest()


def _check_vectors(canonical_rids, master_permutation, holdout_ids, mode):
    require(mode in ('operational', 'fixture'), 'DRIVER_MODE', 'Unknown driver mode')
    canonical = _ids(canonical_rids, 'canonical training IDs')
    holdout = _ids(holdout_ids, 'independent holdout IDs')
    require(not set(canonical).intersection(holdout), 'DRIVER_SOURCE_OVERLAP',
            'Training and holdout must use disjoint source-qualified identities')
    require(type(master_permutation) is list and
            all(type(index) is int for index in master_permutation) and
            sorted(master_permutation) == list(range(len(canonical))),
            'DRIVER_PERMUTATION', 'Master permutation must be a complete zero-based bijection')
    if mode == 'operational':
        require(len(canonical) == 30162 and _line_hash(canonical) == RID_ORDER_SHA256,
                'DRIVER_FROZEN_RIDS', 'Canonical private RID vector differs from its authoritative freeze')
        require(_line_hash(master_permutation) == MASTER_PERMUTATION_SHA256,
                'DRIVER_FROZEN_PERMUTATION', 'Private master permutation differs from its authoritative freeze')
        require(len(holdout) == 15060, 'DRIVER_HOLDOUT', 'Holdout must contain all 15060 complete cases')
        physical_lines = []
        for rid in holdout:
            require(re.fullmatch(r'adult\.test:[1-9][0-9]*', rid) is not None,
                    'DRIVER_HOLDOUT', 'Holdout IDs must retain original adult.test physical lines')
            physical_lines.append(int(rid.split(':')[1]))
        require(physical_lines == sorted(physical_lines),
                'DRIVER_HOLDOUT', 'Holdout must remain in original source order')
    return canonical, holdout


def _check_source(source, expected_ids, name):
    exact_keys(source, SOURCE_KEYS, name)
    require(type(source['rows']) is dict and type(source['labels']) is dict,
            'DRIVER_SOURCE', name + ' must contain independent identity-keyed maps')
    exact_keys(source['rows'], set(expected_ids), name + ' row keys')
    exact_keys(source['labels'], set(expected_ids), name + ' label keys')


def _check_dataset(data, source, expected_ids, feature_names, role, mode):
    exact_keys(data, DATA_KEYS, role + ' dataset')
    return assert_row_y_alignment(
        feature_names, data['X'], data['x_row_ids'], data['y'], data['y_row_ids'],
        expected_ids, source['rows'], source['labels'], mode=mode, dataset_role=role)


def _take(data, indices):


    return {'X': [copy.deepcopy(data['X'][i]) for i in indices],
            'x_row_ids': [data['x_row_ids'][i] for i in indices],
            'y': [data['y'][i] for i in indices],
            'y_row_ids': [data['y_row_ids'][i] for i in indices]}


def _check_plan(plan, labels):
    require(type(plan) is list and len(plan) == 5, 'DRIVER_CV_PLAN',
            'Frozen raw-training CV requires exactly five folds')
    n = len(labels)
    seen = []
    per_class_validation_counts = {0: [], 1: []}
    for fold in plan:
        exact_keys(fold, {'training_indices', 'validation_indices'}, 'CV fold')
        train, valid = fold['training_indices'], fold['validation_indices']
        for indices in (train, valid):
            require(type(indices) is list and indices and
                    all(type(i) is int and 0 <= i < n for i in indices) and
                    len(indices) == len(set(indices)), 'DRIVER_CV_PLAN',
                    'CV indices must be unique valid nonempty integer lists')
        require(not set(train).intersection(valid) and
                set(train).union(valid) == set(range(n)),
                'DRIVER_CV_PLAN', 'Each fold must partition the full raw training population')
        require(len(valid) in {n // 5, (n + 4) // 5} and
                len(train) == n - len(valid), 'DRIVER_CV_PLAN',
                'Five-fold validation sizes must be floor/ceiling of one fifth of raw training')
        require(set(labels[i] for i in train) == {0, 1} and
                set(labels[i] for i in valid) == {0, 1},
                'DRIVER_CV_CLASSES', 'Every training and validation fold must contain both classes')
        for label in (0, 1):
            per_class_validation_counts[label].append(sum(labels[i] == label for i in valid))
        seen.extend(valid)
    require(sorted(seen) == list(range(n)), 'DRIVER_CV_PLAN',
            'Each raw training position must occur in exactly one validation fold')
    for counts in per_class_validation_counts.values():
        require(max(counts) - min(counts) <= 1, 'DRIVER_CV_CLASSES',
                'Stratified validation class counts must differ by at most one')
    return copy.deepcopy(plan)


def _invoke_fit(*, fit_id, training, prediction, expected_train_ids,
                expected_prediction_ids, training_source, prediction_source,
                training_role, C, expected_executable, feature_names, mode):
    result = fit_predict_guarded(
        fit_id=fit_id, feature_names=feature_names,
        training_X=training['X'], training_row_ids=training['x_row_ids'],
        training_y=training['y'], training_y_row_ids=training['y_row_ids'],
        prediction_X=prediction['X'], prediction_row_ids=prediction['x_row_ids'],
        prediction_y=prediction['y'], prediction_y_row_ids=prediction['y_row_ids'],
        expected_training_row_ids=expected_train_ids,
        expected_prediction_row_ids=expected_prediction_ids,
        source_training_rows=training_source['rows'],
        source_training_labels=training_source['labels'],
        source_prediction_rows=prediction_source['rows'],
        source_prediction_labels=prediction_source['labels'],
        training_role=training_role, selected_C=C,
        expected_executable=expected_executable, mode=mode)
    require(type(result) is dict and type(result.get('private_fit_receipt')) is dict and
            type(result.get('receipt')) is dict, 'DRIVER_FIT_RESULT',
            'Fit consumer must return its actual private and bounded receipts')
    private = result['private_fit_receipt']
    require(private.get('fit_execution') in ('actual_fresh_fit', 'synthetic_test_double_fit'),
            'DRIVER_FIT_RESULT', 'Unknown actual-versus-test execution classification')
    require(private.get('holdout_row_ids') == expected_prediction_ids,
            'DRIVER_PREDICTION_ASSOCIATION',
            'Returned private prediction association differs from independent expected identities')


    alignment = assert_row_y_alignment(
        feature_names, prediction['X'], prediction['x_row_ids'], prediction['y'],
        prediction['y_row_ids'], expected_prediction_ids,
        prediction_source['rows'], prediction_source['labels'], mode=mode,
        dataset_role='cv_validation' if training_role == 'cv_training' else 'holdout',
        predictions=private.get('prediction_probabilities'),
        prediction_row_ids=private['holdout_row_ids'])
    return result, alignment


def _select_C_raw(*, raw, source, canonical, feature_names, expected_executable, mode, journal):
    require(all(raw['y'].count(label) >= 5 for label in (0, 1)),
            'DRIVER_CV_CLASSES', 'Five-fold stratification needs at least five raw rows per class')
    raw_identity = json_digest(raw)
    journal['stage'] = 'create_raw_cv_fold_plan'
    plan = _check_plan(_native_cv_plan(copy.deepcopy(raw['X']), list(raw['y']),
                                     expected_executable), raw['y'])
    scores, receipts, executions = [], [], []
    for C in CANDIDATE_CS:
        fold_scores = []
        for fold_id, fold in enumerate(plan):
            train_indices, valid_indices = fold['training_indices'], fold['validation_indices']
            training, validation = _take(raw, train_indices), _take(raw, valid_indices)


            expected_train = [canonical[i] for i in train_indices]
            expected_valid = [canonical[i] for i in valid_indices]
            fit_id = 'raw-cv/C=' + format(C, '.1f') + '/fold=' + str(fold_id)
            journal.update(stage='fit_raw_cv_fold', current_fit_id=fit_id)
            journal['fit_invocation_attempts'] += 1
            fit, alignment = _invoke_fit(
                fit_id=fit_id, training=training, prediction=validation,
                expected_train_ids=expected_train, expected_prediction_ids=expected_valid,
                training_source=source, prediction_source=source, training_role='cv_training',
                C=C, expected_executable=expected_executable, feature_names=feature_names, mode=mode)
            journal['completed_fit_receipts'].append(copy.deepcopy(fit['receipt']))
            journal['stage'] = 'score_raw_cv_fold'
            probabilities = fit['private_fit_receipt']['prediction_probabilities']
            score = _native_auroc(list(validation['y']), copy.deepcopy(probabilities),
                                  expected_executable)
            require(type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1,
                    'DRIVER_AUROC', 'Actual validation AUROC must be finite and within [0,1]')
            fold_scores.append(float(score))
            executions.append(fit['private_fit_receipt']['fit_execution'])
            receipts.append({'fit_id': fit_id, 'candidate_C': C, 'fold_id': fold_id,
                             'C_scope': 'raw_cv_candidate_not_final_selection',
                             'validation_auroc': float(score),
                             'prediction_alignment': alignment,
                             'fit_receipt': copy.deepcopy(fit['receipt'])})

        scores.append({'C': C, 'fold_aurocs': fold_scores,
                       'mean_auroc': sum(fold_scores) / 5.0})

    selected = min(scores, key=lambda record: (-record['mean_auroc'], record['C']))['C']
    require(json_digest(raw) == raw_identity, 'DRIVER_INPUT_MUTATION',
            'Raw CV changed its supplied training dataset')
    return {'selected_C': selected, 'candidate_scores': scores, 'fold_plan': plan,
            'fold_plan_sha256': json_digest(plan), 'fit_receipts': receipts,
            'fit_executions': executions, 'fit_count': 15,
            'splitter': 'sklearn.model_selection.StratifiedKFold',
            'splitter_parameters': {'n_splits': 5, 'shuffle': True, 'random_state': 11004},
            'selection_scope': 'raw_training_only', 'holdout_used_for_selection': False,
            'selection_rule': 'mean_five_fold_AUROC_then_smaller_C_on_exact_tie'}


def run_guarded_utility_models(*, feature_names, canonical_rids, master_permutation,
                               independent_holdout_row_ids, raw_training, raw_holdout,
                               transformed_training_by_cfg, transformed_holdout_by_cfg,
                               retained_row_ids_by_cfg, independent_sources,
                               expected_executable, mode='operational'):

    inputs = {'feature_names': feature_names, 'canonical_rids': canonical_rids,
              'master_permutation': master_permutation,
              'independent_holdout_row_ids': independent_holdout_row_ids,
              'raw_training': raw_training, 'raw_holdout': raw_holdout,
              'transformed_training_by_cfg': transformed_training_by_cfg,
              'transformed_holdout_by_cfg': transformed_holdout_by_cfg,
              'retained_row_ids_by_cfg': retained_row_ids_by_cfg,
              'independent_sources': independent_sources}
    before = json_digest(inputs)
    journal = {'record_schema': 'step7-model-workflow-partial/1',
               'result': 'IN_PROGRESS', 'stage': 'preflight', 'current_fit_id': None,
               'fit_invocation_attempts': 0, 'completed_fit_receipts': [],
               'private_row_payloads_included': False,
               'unreturned_fit_completion_not_inferred': True,
               'main_runs_authorized': False, 'section_12_1_step_7_status': 'pending'}
    try:
        canonical, holdout_ids = _check_vectors(canonical_rids, master_permutation,
                                               independent_holdout_row_ids, mode)
        require(type(transformed_training_by_cfg) is dict and transformed_training_by_cfg,
                'DRIVER_CONFIGURATIONS', 'At least one transformed output configuration is required')
        cfgs = set(transformed_training_by_cfg)
        require('CFG00' not in cfgs, 'DRIVER_CONFIGURATIONS', 'CFG00 raw is supplied separately')
        for cfg in cfgs:
            cfg_contract(cfg)
        if mode == 'operational':
            require(cfgs == EXPECTED_OUTPUT_CFGS, 'DRIVER_CONFIGURATIONS',
                    'Operational dispatch requires all CFG01 through CFG16')
        exact_keys(transformed_holdout_by_cfg, cfgs, 'transformed holdout configurations')
        exact_keys(retained_row_ids_by_cfg, cfgs, 'retained release configurations')
        exact_keys(independent_sources, {'training', 'holdout'}, 'independent source groups')
        all_cfgs = cfgs | {'CFG00'}
        for group in ('training', 'holdout'):
            exact_keys(independent_sources[group], all_cfgs, group + ' source configurations')
            expected = canonical if group == 'training' else holdout_ids
            for cfg in all_cfgs:
                _check_source(independent_sources[group][cfg], expected, group + '/' + cfg)
        source_train = independent_sources['training']
        source_holdout = independent_sources['holdout']
        input_alignments = {
            'CFG00/training': _check_dataset(raw_training, source_train['CFG00'], canonical,
                                             feature_names, 'raw_training', mode),
            'CFG00/holdout': _check_dataset(raw_holdout, source_holdout['CFG00'], holdout_ids,
                                            feature_names, 'holdout', mode)}
        retained = {}
        for cfg in sorted(cfgs):

            require(source_train[cfg]['labels'] == source_train['CFG00']['labels'] and
                    source_holdout[cfg]['labels'] == source_holdout['CFG00']['labels'],
                    'DRIVER_TRANSFORMED_LABELS', 'Transformation source labels differ from raw labels')
            input_alignments[cfg + '/training'] = _check_dataset(
                transformed_training_by_cfg[cfg], source_train[cfg], canonical,
                feature_names, 'counterfactual_training', mode)
            input_alignments[cfg + '/holdout'] = _check_dataset(
                transformed_holdout_by_cfg[cfg], source_holdout[cfg], holdout_ids,
                feature_names, 'holdout', mode)
            retained[cfg] = _ids(retained_row_ids_by_cfg[cfg], cfg + ' retained IDs')
            require(set(retained[cfg]).issubset(canonical), 'DRIVER_RETAINED_IDS',
                    'Release membership contains unknown training identities')
            if mode == 'operational':
                contract = cfg_contract(cfg)
                require(len(canonical) - len(retained[cfg]) <=
                        math.floor(contract['suppression_limit'] * len(canonical)),
                        'DRIVER_RETAINED_IDS', 'Release membership exceeds the frozen suppression budget')
            retained_labels = [source_train['CFG00']['labels'][rid] for rid in retained[cfg]]
            require(set(retained_labels) == {0, 1}, 'DRIVER_TRAINING_CLASSES',
                    'Each planned release fit must retain both training classes')

        cv = _select_C_raw(raw=raw_training, source=source_train['CFG00'], canonical=canonical,
                           feature_names=feature_names, expected_executable=expected_executable,
                           mode=mode, journal=journal)


        selected_C = cv['selected_C']
        final = {}
        executions = list(cv['fit_executions'])
        recipes = [('CFG00', 'CFG00', 'raw_training', raw_training, raw_holdout,
                    list(master_permutation))]
        for cfg in sorted(cfgs):
            retained_set = set(retained[cfg])
            release_indices = [i for i in master_permutation if canonical[i] in retained_set]
            recipes.extend([
                (cfg + '/release', cfg, 'released_training', transformed_training_by_cfg[cfg],
                 transformed_holdout_by_cfg[cfg], release_indices),
                (cfg + '/counterfactual', cfg, 'counterfactual_training', transformed_training_by_cfg[cfg],
                 transformed_holdout_by_cfg[cfg], list(master_permutation))])
        for key, cfg, role, training, prediction, indices in recipes:
            expected_train = [canonical[i] for i in indices]
            journal.update(stage='fit_final_model', current_fit_id='final/' + key)
            journal['fit_invocation_attempts'] += 1
            fit, alignment = _invoke_fit(
                fit_id='final/' + key, training=_take(training, indices),
                prediction=copy.deepcopy(prediction), expected_train_ids=expected_train,
                expected_prediction_ids=holdout_ids, training_source=source_train[cfg],
                prediction_source=source_holdout[cfg], training_role=role, C=selected_C,
                expected_executable=expected_executable, feature_names=feature_names, mode=mode)
            journal['completed_fit_receipts'].append(copy.deepcopy(fit['receipt']))
            executions.append(fit['private_fit_receipt']['fit_execution'])
            final[key] = {'cfg_id': cfg, 'training_role': role,
                          'C': selected_C, 'C_scope': 'selected_by_this_raw_cv_workflow',
                          'prediction_row_ids': list(holdout_ids),
                          'prediction_probabilities': copy.deepcopy(
                              fit['private_fit_receipt']['prediction_probabilities']),
                          'prediction_alignment': alignment,
                          'training_row_order_sha256': json_digest(expected_train),
                          'fit_receipt': copy.deepcopy(fit['receipt']),
                          'privacy_validity_claimed_by_model_driver': False}
        expected_final = 1 + 2 * len(cfgs)
        require(len(final) == expected_final, 'DRIVER_FINAL_COUNT', 'Final model dispatch is incomplete')
        actual_count = executions.count('actual_fresh_fit')
        double_count = executions.count('synthetic_test_double_fit')
        require(actual_count == 0 or double_count == 0, 'DRIVER_MIXED_EXECUTION',
                'A workflow may not mix actual fits and synthetic test doubles')
        return {'record_schema': 'step7-guarded-model-workflow/1', 'result': 'PASS',
                'selected_C': selected_C, 'cv': cv, 'final_models': final,
                'receipt': {
                    'mode': mode, 'private_payloads_in_return': True,
                    'scope': 'concrete_cv_and_final_fit_callsite_candidate',
                    'integration_status': 'PARTIAL_CONSUMER_INTEGRATION_CANDIDATE',
                    'execution_classification': 'actual_native_fits' if actual_count else 'synthetic_test_doubles',
                    'actual_model_fit_count': actual_count, 'synthetic_test_double_fit_count': double_count,
                    'cv_fit_count': 15, 'final_fit_count': expected_final,
                    'selected_C': selected_C, 'selection_source': 'this_workflow_raw_cv_predictions',
                    'cv_plan_sha256': cv['fold_plan_sha256'],
                    'artifact_hash_encoding': 'common.json_digest: sorted compact ASCII JSON; no LF',
                    'authoritative_vector_checks': 'operational mode separately verifies frozen LF file hashes',
                    'canonical_row_ids_sha256': json_digest(canonical),
                    'master_permutation_sha256': json_digest(master_permutation),
                    'independent_holdout_row_ids_sha256': json_digest(holdout_ids),
                    'input_artifacts_sha256': before, 'input_alignments': input_alignments,
                    'external_source_and_release_provenance_verified': False,
                    'new_protocol_activation': False, 'step7_assertions_activated': False,
                    'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
                    'gate_d_status': 'not_evaluated', 'main_runs_authorized': False,
                    'missing_integration': [
                        'independent_native_Java_transformation_and_release_association_producer',
                        'reviewed_native_validation_of_this_exact_new_model_driver',
                        'production_utility_metrics_unknown_category_diagnostics_and_dummy_baseline',
                        'production_bootstrap_index_generation_and_final_interval_reporting',
                        'separate_evidence_and_human_control_adoption']}}
    except Exception as error:


        journal.update(result='FAIL', error_type=type(error).__name__)
        error.step7_model_workflow_partial_receipt = copy.deepcopy(journal)
        raise
    finally:
        require(json_digest(inputs) == before, 'DRIVER_INPUT_MUTATION',
                'Model workflow changed a supplied input; preserve all partial outputs')


if __name__ == '__main__':
    raise SystemExit('Direct execution disabled; use a separately reviewed controlled outer runner.')
