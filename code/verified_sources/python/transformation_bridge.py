from copy import deepcopy
import hashlib
import re

from common import (
    HOLDOUT_SIZE, POPULATION_SIZE, QIS, RID_ORDER_SHA256,
    cfg_contract, exact_keys, integer, json_digest, require,
)
from release_consumer import admit_retained_release
from utility_evaluation import assert_row_y_alignment


ROW_KEYS = frozenset(QIS) | {'salary-class'}
OUTPUT_CFGS = frozenset('CFG%02d' % number for number in range(1, 17))
TRANSCRIPT_KEYS = {'original_index', 'row', 'is_outlier'}
ASSOCIATION_KEYS = {'original_index', 'row_id', 'transformed_row_sha256', 'is_outlier'}
MODEL_INPUT_KEYS = frozenset((
    'feature_names', 'canonical_rids', 'independent_holdout_row_ids',
    'raw_training', 'raw_holdout', 'transformed_training_by_cfg',
    'transformed_holdout_by_cfg', 'retained_row_ids_by_cfg', 'independent_sources',
))
_TRAIN_RID = re.compile(r'adult\.data:([1-9][0-9]*)\Z')
_HOLDOUT_RID = re.compile(r'adult\.test:([1-9][0-9]*)\Z')


def _list(value, name, nonempty=True):
    require(type(value) is list and (not nonempty or bool(value)),
            'TRANSFORM_LIST', name + ' must be an explicit ordered list')
    return value


def _cell(value):
    require(type(value) is str and bool(value) and value == value.strip()
            and value != '?' and not any(char in value for char in ('\0', '\r', '\n', '\t')),
            'TRANSFORM_CELL', 'Cells must be nonmissing categorical strings without controls')


def _row(value, *, original_label):
    exact_keys(value, ROW_KEYS, 'source or transcript row')
    for cell in value.values():
        _cell(cell)
    if original_label:
        require(value['salary-class'] in ('<=50K', '>50K'),
                'TRANSFORM_LABEL', 'Source and retained labels must use the unchanged binary encoding')


def _source_records(records, training, mode):
    _list(records, 'source records')
    pattern = _TRAIN_RID if training else _HOLDOUT_RID
    lower, upper = (1, 32561) if training else (2, 16282)
    ids, positions, labels = [], [], set()
    for record in records:
        exact_keys(record, {'row_id', 'row'}, 'source record')
        rid = record['row_id']
        match = pattern.fullmatch(rid) if type(rid) is str else None
        require(match is not None, 'TRANSFORM_SOURCE_ID',
                'Source identities must use the declared physical-line namespace')
        position = int(match.group(1))
        require(lower <= position <= upper, 'TRANSFORM_SOURCE_ID_RANGE',
                'Source physical-line identity is outside the declared file range')
        _row(record['row'], original_label=True)
        ids.append(rid)
        positions.append(position)
        labels.add(record['row']['salary-class'])
    require(all(a < b for a, b in zip(positions, positions[1:])),
            'TRANSFORM_SOURCE_ORDER', 'Source identities must be unique and in original physical-line order')
    require(labels == {'<=50K', '>50K'}, 'TRANSFORM_SOURCE_CLASSES',
            'Each model source population must include both binary classes')
    if mode == 'operational':
        require(len(records) == (POPULATION_SIZE if training else HOLDOUT_SIZE),
                'TRANSFORM_SOURCE_COUNT', 'Operational source population count differs from the frozen shape')
        if training:
            require(_rid_hash(ids) == RID_ORDER_SHA256, 'TRANSFORM_FROZEN_RIDS',
                    'Canonical training identities differ from the authoritative freeze')
    return ids


def _rid_hash(ids):
    return hashlib.sha256(('\n'.join(ids) + '\n').encode('ascii')).hexdigest()


def _hierarchies(tables, training, holdout):
    exact_keys(tables, QIS, 'hierarchy names')
    indexed = {}
    for qi in QIS:
        table = tables[qi]
        exact_keys(table, {'levels', 'rows'}, 'hierarchy table')
        levels = _list(table['levels'], 'hierarchy levels')
        require(all(type(level) is int for level in levels)
                and levels == list(range(len(levels))),
                'TRANSFORM_HIERARCHY_LEVELS', 'Hierarchy levels must be contiguous zero-based integers')
        rows = _list(table['rows'], 'hierarchy rows')
        by_leaf = {}
        child_to_parent = [{} for _ in range(len(levels) - 1)]
        for cells in rows:
            _list(cells, 'hierarchy row')
            require(len(cells) == len(levels), 'TRANSFORM_HIERARCHY_RECTANGLE',
                    'Every hierarchy row must contain every declared level')
            for cell in cells:
                _cell(cell)
            leaf = cells[0]
            require(leaf not in by_leaf, 'TRANSFORM_HIERARCHY_LEAF',
                    'Each hierarchy leaf must have exactly one path')
            by_leaf[leaf] = tuple(cells)
            for level, parents in enumerate(child_to_parent):
                child, parent = cells[level:level + 2]
                require(child not in parents or parents[child] == parent,
                        'TRANSFORM_HIERARCHY_NESTING',
                        'A hierarchy class must not split at the next level')
                parents[child] = parent
        for records in (training, holdout):
            require(all(record['row'][qi] in by_leaf for record in records),
                    'TRANSFORM_HIERARCHY_COVERAGE',
                    'Every raw training and holdout value must be a hierarchy leaf')
        indexed[qi] = by_leaf
    return indexed


def _vectors(vectors, tables, mode):
    require(type(vectors) is dict and bool(vectors), 'TRANSFORM_CONFIGURATIONS',
            'At least one output transformation must be supplied')
    for cfg, vector in vectors.items():
        cfg_contract(cfg)
        require(cfg != 'CFG00', 'TRANSFORM_RAW_CONTROL',
                'CFG00 remains the raw control and has no supplied output transformation')
        exact_keys(vector, QIS, 'named transformation vector')
        for qi in QIS:
            level = integer(vector[qi], 'named transformation level')
            require(level < len(tables[qi]['levels']), 'TRANSFORM_LEVEL_RANGE',
                    'Named transformation level is outside its hierarchy')
    if mode == 'operational':
        require(set(vectors) == OUTPUT_CFGS, 'TRANSFORM_CONFIGURATIONS',
                'Operational transformation admission requires all CFG01 through CFG16')
    return sorted(vectors)


def _transform_row(row, vector, indexed):
    result = {qi: indexed[qi][row[qi]][vector[qi]] for qi in QIS}
    result['salary-class'] = row['salary-class']
    return result


def _dataset(records, vector, indexed):

    rows = [dict(record['row']) if vector is None else
            _transform_row(record['row'], vector, indexed) for record in records]
    ids = [record['row_id'] for record in records]
    return {'X': [[row[qi] for qi in QIS] for row in rows],
            'x_row_ids': list(ids),
            'y': [int(row['salary-class'] == '>50K') for row in rows],
            'y_row_ids': list(ids)}, rows


def _independent_source(records, vector, tables):

    selected = (None if vector is None else
                {qi: {row[0]: row[vector[qi]] for row in tables[qi]['rows']} for qi in QIS})
    rows, labels = {}, {}
    for record in records:
        rid, row = record['row_id'], record['row']
        rows[rid] = [row[qi] if selected is None else selected[qi][row[qi]] for qi in QIS]
        labels[rid] = 0 if row['salary-class'] == '<=50K' else 1
    return {'rows': rows, 'labels': labels}


def _alignment(data, source, ids, mode, role):
    return assert_row_y_alignment(
        list(QIS), data['X'], data['x_row_ids'], data['y'], data['y_row_ids'],
        ids, source['rows'], source['labels'], mode=mode, dataset_role=role)


def _transcript(transcript, association, computed_rows, canonical_ids):
    _list(transcript, 'Java transcript')
    _list(association, 'captured association')
    require(len(transcript) == len(association) == len(canonical_ids),
            'TRANSFORM_TRANSCRIPT_COUNT', 'Transcript and captured association must cover every source index')
    original_rows, flags = [], []
    for index, (item, captured) in enumerate(zip(transcript, association)):
        exact_keys(item, TRANSCRIPT_KEYS, 'Java transcript item')
        exact_keys(captured, ASSOCIATION_KEYS, 'captured association item')
        require(type(item['original_index']) is int and item['original_index'] == index
                and type(captured['original_index']) is int and captured['original_index'] == index,
                'TRANSFORM_TRANSCRIPT_INDEX', 'Transcript and capture must preserve original zero-based index order')
        require(type(item['is_outlier']) is bool and type(captured['is_outlier']) is bool
                and item['is_outlier'] is captured['is_outlier'],
                'TRANSFORM_TRANSCRIPT_OUTLIER', 'Captured Boolean outlier flags must match the transcript')
        require(type(captured['row_id']) is str and captured['row_id'] == canonical_ids[index],
                'TRANSFORM_TRANSCRIPT_RID', 'Captured source identity must match the independently supplied canonical index')
        _row(item['row'], original_label=not item['is_outlier'])
        require(captured['transformed_row_sha256'] == json_digest(item['row']),
                'TRANSFORM_TRANSCRIPT_HASH', 'Captured original handle-row identity differs from the transcript')
        if not item['is_outlier']:
            require(item['row'] == computed_rows[index], 'TRANSFORM_RETAINED_VALUE',
                    'Retained Java row differs from the independently computed named transformation')
        original_rows.append(deepcopy(item['row']))
        flags.append(item['is_outlier'])
    return original_rows, flags


def build_guarded_transformation_inputs(*, raw_training_records, raw_holdout_records,
                                       hierarchy_tables, transformations_by_cfg,
                                       java_transcripts_by_cfg, captured_associations_by_cfg,
                                       mode='operational'):

    original = dict(raw_training_records=raw_training_records,
                    raw_holdout_records=raw_holdout_records, hierarchy_tables=hierarchy_tables,
                    transformations_by_cfg=transformations_by_cfg,
                    java_transcripts_by_cfg=java_transcripts_by_cfg,
                    captured_associations_by_cfg=captured_associations_by_cfg, mode=mode)
    journal = {'record_schema': 'step7-transformation-partial/1', 'result': 'IN_PROGRESS',
               'stage': 'validate_inputs', 'current_cfg': None,
               'completed_release_receipts': {}, 'completed_alignment_receipts': {},
               'private_payloads_in_receipt': False, 'private_payload_returned': False,
               'model_fits_executed': False, 'rng_invoked': False,
               'main_runs_authorized': False, 'section_12_1_step_7_status': 'pending'}
    try:
        require(type(mode) is str and mode in ('fixture', 'operational'),
                'TRANSFORM_MODE', 'Mode must be explicitly fixture or operational')
        before = json_digest(original)
        supplied = deepcopy(original)
        training, holdout, tables, vectors, transcripts, captures = (
            supplied[name] for name in ('raw_training_records', 'raw_holdout_records',
                'hierarchy_tables', 'transformations_by_cfg', 'java_transcripts_by_cfg',
                'captured_associations_by_cfg'))
        canonical = _source_records(training, True, mode)
        holdout_ids = _source_records(holdout, False, mode)
        require(not set(canonical).intersection(holdout_ids), 'TRANSFORM_SOURCE_OVERLAP',
                'Training and holdout identities must be disjoint')
        journal['stage'] = 'validate_hierarchies_and_named_vectors'
        indexed = _hierarchies(tables, training, holdout)
        cfgs = _vectors(vectors, tables, mode)
        exact_keys(transcripts, cfgs, 'Java transcript configurations')
        exact_keys(captures, cfgs, 'captured association configurations')

        journal['stage'] = 'produce_raw_inputs_and_independent_maps'
        raw_train, _ = _dataset(training, None, indexed)
        raw_test, _ = _dataset(holdout, None, indexed)
        sources = {'training': {'CFG00': _independent_source(training, None, tables)},
                   'holdout': {'CFG00': _independent_source(holdout, None, tables)}}
        for key, data, source, ids, role in (
            ('CFG00/training', raw_train, sources['training']['CFG00'], canonical, 'raw_training'),
            ('CFG00/holdout', raw_test, sources['holdout']['CFG00'], holdout_ids, 'holdout')):
            journal['completed_alignment_receipts'][key] = _alignment(data, source, ids, mode, role)

        transformed_train, transformed_test, checked_transcripts = {}, {}, {}
        for cfg in cfgs:
            journal.update(stage='produce_and_check_transformation', current_cfg=cfg)
            transformed_train[cfg], computed_train = _dataset(training, vectors[cfg], indexed)
            transformed_test[cfg], _ = _dataset(holdout, vectors[cfg], indexed)
            sources['training'][cfg] = _independent_source(training, vectors[cfg], tables)
            sources['holdout'][cfg] = _independent_source(holdout, vectors[cfg], tables)
            for suffix, data, source, ids, role in (
                ('training', transformed_train[cfg], sources['training'][cfg], canonical, 'counterfactual_training'),
                ('holdout', transformed_test[cfg], sources['holdout'][cfg], holdout_ids, 'holdout')):
                journal['completed_alignment_receipts'][cfg + '/' + suffix] = _alignment(
                    data, source, ids, mode, role)
            journal['stage'] = 'compare_captured_retained_java_transcript'
            checked_transcripts[cfg] = _transcript(transcripts[cfg], captures[cfg],
                                                 computed_train, canonical)

        admitted, membership = {}, {}


        for cfg in cfgs:
            journal.update(stage='admit_retained_release', current_cfg=cfg)
            rows, flags = checked_transcripts[cfg]
            admitted[cfg] = admit_retained_release(cfg, rows, flags, canonical, captures[cfg],
                                                  fixture_mode=mode == 'fixture')
            membership[cfg] = list(admitted[cfg]['private_retained_rids'])
            journal['completed_release_receipts'][cfg] = deepcopy(admitted[cfg]['receipt'])

        journal.update(stage='verify_preservation_and_return', current_cfg=None)
        require(json_digest(supplied) == before and json_digest(original) == before,
                'TRANSFORM_INPUT_CHANGED', 'Supplied source or capture artifacts changed during preparation')
        model_inputs = {'feature_names': list(QIS), 'canonical_rids': list(canonical),
                        'independent_holdout_row_ids': list(holdout_ids),
                        'raw_training': raw_train, 'raw_holdout': raw_test,
                        'transformed_training_by_cfg': transformed_train,
                        'transformed_holdout_by_cfg': transformed_test,
                        'retained_row_ids_by_cfg': membership, 'independent_sources': sources}
        exact_keys(model_inputs, MODEL_INPUT_KEYS, 'model driver inputs')
        receipt = {
            'record_schema': 'step7-transformation-release-bridge/1', 'result': 'PASS',
            'scope': 'SYNTHETIC_FIXTURE' if mode == 'fixture' else 'SUPPLIED_OPERATIONAL_SOURCE_ARTIFACTS',
            'integration_status': 'PARTIAL_TRANSFORMATION_RELEASE_BRIDGE_CANDIDATE',
            'effective_protocol_version': 'v1.2.3', 'input_json_sha256': before,
            'model_driver_inputs_json_sha256': json_digest(model_inputs),
            'source_counts': {'training': len(canonical), 'holdout': len(holdout_ids)},
            'source_order_sha256': {'training_lf': _rid_hash(canonical),
                                    'holdout_lf': _rid_hash(holdout_ids)},
            'hierarchy_tables_json_sha256': json_digest(tables),
            'named_transformations_json_sha256': json_digest(vectors),
            'java_transcripts_json_sha256': json_digest(transcripts),
            'captured_associations_json_sha256': json_digest(captures),
            'configuration_count': len(cfgs), 'configurations': cfgs,
            'predictor_order': list(QIS),
            'independent_map_construction': 'separate source traversal and original-table selected-column lookups; never zip produced arrays',
            'transformation_computation': 'same named hierarchy levels applied to all training and holdout records',
            'retained_java_value_comparison': 'PASS_EXACT_NINE_FIELDS_AT_ORIGINAL_INDEX',
            'retention_source': 'captured original isOutlier Boolean; never a star-valued cell',
            'counterfactual_source': 'full raw training transformed independently of suppressed Java row values',
            'holdout_suppression_performed': False, 'duplicates_removed': False,
            'labels_preserved': True, 'source_inputs_unchanged': True,
            'alignment_receipts': deepcopy(journal['completed_alignment_receipts']),
            'release_receipts': deepcopy(journal['completed_release_receipts']),
            'private_payloads_in_receipt': False, 'private_payloads_in_return': True,
            'publication_order_applied': False, 'master_permutation_generated': False,
            'per_cfg_permutations_generated': False, 'model_fits_executed': False,
            'rng_invoked': False, 'scientific_packages_imported': False,
            'source_parser_provenance_verified': False,
            'physical_serialized_header_verified': False,
            'named_field_order_scope': 'named row mappings are projected by QI name; no serialized nine-column header is checked here',
            'pinned_hierarchy_artifact_provenance_verified': False,
            'native_java_exporter_provenance_verified': False,
            'selected_node_provenance_verified': False,
            'independent_map_source_authenticity_verified': False,
            'operational_producer_integration_verified': False,
            'privacy_assertions_scope': 'separate k and U_QI checks only; no l/t or full privacy-validity certification',
            'counterfactual_is_release': False,
            'outer_obligations': [
                'Bind actual complete-case source parsers, input bytes and canonical RID association',
                'Bind exact frozen hierarchy artifacts, including the semantic age hierarchy for main configurations',
                'Capture selected named T_c and original-index rows/isOutlier from the actual pinned native Java exporter',
                'Pass these admitted inputs to the guarded model driver with the frozen master Pi and locked runtime',
                'Persist bounded failure evidence and keep all private returns outside public evidence',
            ],
            'section_12_1_step_7_status': 'pending', 'gate_a_status': 'pending',
            'step7_assertions_activated': False, 'main_runs_authorized': False,
            'main_runs_executed': False, 'new_protocol_activation': False,
        }
        return {'model_driver_inputs': model_inputs, 'private_admitted_releases': admitted,
                'receipt': receipt}
    except Exception as error:
        journal.update(result='FAIL', error_type=type(error).__name__)


        error.step7_transformation_partial_receipt = deepcopy(journal)
        raise
