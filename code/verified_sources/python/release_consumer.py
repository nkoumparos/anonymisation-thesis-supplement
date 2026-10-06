from collections.abc import Sequence
import copy

from common import exact_keys, integer, json_digest, require
from privacy_metrics import assert_k, assert_u_qi_zero


ASSOCIATION_KEYS = ('original_index', 'row_id', 'transformed_row_sha256', 'is_outlier')


def _ordered(value, name):
    require(isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
            'RELEASE_ORDERED_INPUT', name + ' must be an ordered sequence')
    return value


def admit_retained_release(cfg_id, original_rows, original_is_outlier,
                           canonical_rids, independent_export_association, *,
                           fixture_mode=False):

    require(type(fixture_mode) is bool, 'RELEASE_FIXTURE_MODE',
            'fixture_mode must be an explicit Boolean')
    for value, name in ((original_rows, 'original_rows'),
                        (original_is_outlier, 'original_is_outlier'),
                        (canonical_rids, 'canonical_rids'),
                        (independent_export_association, 'independent_export_association')):
        _ordered(value, name)
    n_input = len(original_rows)
    require(len(original_is_outlier) == len(canonical_rids)
            == len(independent_export_association) == n_input,
            'RELEASE_ASSOCIATION_LENGTH', 'All supplied original-index artifacts must cover the same rows')
    require(all(type(flag) is bool for flag in original_is_outlier),
            'RELEASE_OUTLIER_TYPE', 'Original isOutlier values must be Boolean')
    snapshot = json_digest([original_rows, original_is_outlier,
                            canonical_rids, independent_export_association])
    for index, association in enumerate(independent_export_association):
        exact_keys(association, ASSOCIATION_KEYS, 'independent export association record')
        original_index = integer(association['original_index'], 'original ARX index')
        require(original_index == index, 'RELEASE_ASSOCIATION_INDEX',
                'Association must cover each original ARX index once and in original order')
        require(type(association['row_id']) is str
                and association['row_id'] == canonical_rids[index],
                'RELEASE_ASSOCIATION_RID', 'Captured export row identity differs from canonical sidecar')
        require(type(association['is_outlier']) is bool
                and association['is_outlier'] is original_is_outlier[index],
                'RELEASE_ASSOCIATION_OUTLIER', 'Captured export flag differs from original isOutlier')
        require(association['transformed_row_sha256'] == json_digest(original_rows[index]),
                'RELEASE_ASSOCIATION_ROW', 'Captured transformed row differs from supplied original-index row')


    u_qi_receipt = assert_u_qi_zero(cfg_id, original_rows, original_is_outlier,
                                  canonical_rids, fixture_mode=fixture_mode)
    k_receipt = assert_k(cfg_id, original_rows, original_is_outlier,
                        canonical_rids, fixture_mode=fixture_mode)
    selected = [index for index, outlier in enumerate(original_is_outlier) if not outlier]
    require(len(selected) == k_receipt['n_retained'] == u_qi_receipt['n_retained'],
            'RELEASE_SELECTION_COUNT', 'Independent retained selection and guard counts disagree')
    require(snapshot == json_digest([original_rows, original_is_outlier,
                                     canonical_rids, independent_export_association]),
            'RELEASE_INPUT_CHANGED', 'Supplied artifacts changed during admission')


    retained_rows = [copy.deepcopy(original_rows[index]) for index in selected]
    retained_rids = [canonical_rids[index] for index in selected]
    receipt = {
        'record_schema': 'step7-retained-release-consumer/1',
        'result': 'PASS',
        'scope': 'SYNTHETIC_FIXTURE' if fixture_mode else 'SUPPLIED_OPERATIONAL_ARTIFACTS',
        'integration_status': 'PARTIAL_CONSUMER_INTEGRATION_CANDIDATE',
        'source_association_check': 'SUPPLIED_ORIGINAL_INDEX_ASSOCIATION_CONSISTENT',
        'upstream_exporter_provenance_verified': False,
        'config_id': cfg_id,
        'selection_order': 'ORIGINAL_ARX_INDEX_ORDER_BEFORE_PI',
        'n_input': n_input,
        'n_retained': len(selected),
        'outliers': n_input - len(selected),
        'guard_receipts': {'k': k_receipt, 'u_qi': u_qi_receipt},
        'artifact_hash_encoding': 'common.json_digest: sorted compact ASCII JSON; no LF',
        'artifact_sha256': {
            'original_transformed_rows': json_digest(original_rows),
            'original_is_outlier': json_digest(original_is_outlier),
            'canonical_rids_json': json_digest(canonical_rids),
            'supplied_export_association': json_digest(independent_export_association),
            'selected_original_indices': json_digest(selected),
            'retained_rows': json_digest(retained_rows),
            'private_retained_rids': json_digest(retained_rids),
        },
        'private_payloads_in_receipt': False,
        'upstream_obligations': [
            'Capture original Java handle rows and isOutlier(i) with the actual input index',
            'Bind each actual input index to independently verified authoritative canonical RID',
            'Bind actual consumer, guard and exporter source hashes and artifact identities in the outer record',
        ],
        'publication_order_applied': False,
        'section_12_1_step_7_status': 'pending',
        'step7_assertions_activated': False,
        'main_runs_authorized': False,
    }
    return {'private_retained_rows': retained_rows,
            'private_retained_rids': retained_rids,
            'private_original_indices': selected,
            'receipt': receipt}
