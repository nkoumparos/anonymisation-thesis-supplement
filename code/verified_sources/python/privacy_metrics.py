from collections import Counter
from collections.abc import Sequence
from fractions import Fraction
import hashlib
import re

from common import (
    POPULATION_SIZE, QIS, RID_ORDER_SHA256,
    cfg_contract, exact_keys, integer, number, require,
)


EXPECTED_SOURCE_ROWS = POPULATION_SIZE
FROZEN_RID_ORDER_SHA256 = RID_ORDER_SHA256
ROW_KEYS = frozenset(QIS) | {'salary-class'}
_RID = re.compile(r'adult\.data:([1-9][0-9]*)\Z')


def _sequence(value, name):
    require(isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)),
            'PRIVACY_SEQUENCE_REQUIRED', name + ' must be an ordered sequence')
    return value


def _metrics(cfg_id, rows, is_outlier, canonical_rids, fixture_mode):
    require(type(fixture_mode) is bool, 'PRIVACY_FIXTURE_MODE_TYPE',
            'fixture_mode must be an explicit Boolean')
    cfg = cfg_contract(cfg_id)
    require(cfg['k'] is not None, 'RAW_CONTROL_NOT_ANONYMIZED',
            'CFG00 is a raw diagnostic control, not an anonymized-release assertion')
    k = integer(cfg['k'], 'configuration k', minimum=2)
    _sequence(rows, 'rows')
    _sequence(is_outlier, 'is_outlier')
    _sequence(canonical_rids, 'canonical_rids')
    n_input = len(rows)
    require(n_input > 0, 'PRIVACY_EMPTY_INPUT', 'Source rows must be nonempty')
    require(len(is_outlier) == len(canonical_rids) == n_input,
            'PRIVACY_ALIGNMENT_LENGTH', 'Rows, original flags and private IDs differ in length')
    require(fixture_mode or n_input == EXPECTED_SOURCE_ROWS,
            'PRIVACY_SOURCE_COUNT', 'Operational assertions require all 30162 source rows')
    require(all(type(flag) is bool for flag in is_outlier),
            'PRIVACY_ORIGINAL_FLAG_TYPE', 'Original isOutlier flags must be Boolean values')

    physical_indices = []
    for rid in canonical_rids:
        match = _RID.fullmatch(rid) if isinstance(rid, str) else None
        require(match is not None, 'PRIVACY_RID_FORMAT',
                'Private canonical IDs must use adult.data:<physical line> format')
        physical_indices.append(int(match.group(1)))
    require(all(1 <= index <= 32561 for index in physical_indices),
            'PRIVACY_RID_RANGE', 'Canonical source physical index is out of range')
    require(all(left < right for left, right in zip(physical_indices, physical_indices[1:])),
            'PRIVACY_RID_ORDER', 'Canonical source indices must be unique and increasing')
    rid_digest = hashlib.sha256(('\n'.join(canonical_rids) + '\n').encode('utf-8')).hexdigest()
    require(fixture_mode or rid_digest == FROZEN_RID_ORDER_SHA256,
            'PRIVACY_FROZEN_RID_MISMATCH', 'Operational canonical ID order differs from the frozen sidecar')

    outliers = sum(is_outlier)

    suppression = Fraction(str(cfg['suppression_limit']))
    require(Fraction(0) <= suppression <= Fraction(1),
            'PRIVACY_SUPPRESSION_CONTRACT', 'Configuration suppression limit is invalid')
    budget = n_input * suppression.numerator // suppression.denominator
    require(outliers <= budget, 'PRIVACY_SUPPRESSION_BUDGET',
            'Original outlier count exceeds the exact frozen configuration budget')

    equivalence_classes = Counter()
    full_classes = Counter()
    for row, outlier in zip(rows, is_outlier):
        exact_keys(row, ROW_KEYS, 'transformed source row')
        require(all(isinstance(value, str) and bool(value.strip())
                    and value == value.strip() and value != '?'
                    and not any(character in value for character in ('\0', '\r', '\n', '\t'))
                    for value in row.values()),
                'PRIVACY_FIELD_VALUE', 'Release cells must be nonmissing categorical strings')
        if outlier:
            continue
        require(row['salary-class'] in ('<=50K', '>50K'),
                'PRIVACY_SALARY_LABEL', 'Retained salary-class must use the unchanged binary labels')
        key = tuple(row[name] for name in QIS)
        equivalence_classes[key] += 1
        full_classes[key + (row['salary-class'],)] += 1
    n_retained = n_input - outliers
    require(n_retained > 0, 'PRIVACY_EMPTY_RELEASE', 'An empty retained release has no k/U_QI verdict')
    sizes = sorted(equivalence_classes.values())
    require(sizes and sum(sizes) == n_retained and sum(full_classes.values()) == n_retained,
            'PRIVACY_PARTITION_COVERAGE', 'Retained equivalence classes do not cover all rows exactly once')
    unique_qi = sum(size for size in sizes if size == 1)
    unique_full = sum(size for size in full_classes.values() if size == 1)
    return {
        'config_id': cfg_id,
        'scope': 'SYNTHETIC_FIXTURE' if fixture_mode else 'OPERATIONAL_RETAINED_ROWS',
        'n_input': n_input,
        'n_retained': n_retained,
        'outliers': outliers,
        'suppression_budget': budget,
        'canonical_rid_order_sha256': rid_digest,
        'k_required': k,
        'k_hat': min(sizes),
        'equivalence_class_count': len(sizes),
        'equivalence_class_size_sum': sum(sizes),
        'u_qi_unique_rows': unique_qi,
        'u_qi': unique_qi / n_retained,
        'u_full_unique_rows': unique_full,
        'u_full': unique_full / n_retained,
        'u_full_informational_only': True,
        'private_ids_returned': False,
    }


def assert_k(cfg_id, rows, is_outlier, canonical_rids, *, reported=None, fixture_mode=False):

    result = _metrics(cfg_id, rows, is_outlier, canonical_rids, fixture_mode)
    if reported is not None:
        exact_keys(reported, {'k_hat'}, 'reported k')
        claimed = integer(reported['k_hat'], 'reported k_hat', minimum=1)
        require(claimed == result['k_hat'], 'PRIVACY_REPORTED_K_MISMATCH',
                'Reported k_hat differs from independent retained partition')
    require(result['k_hat'] >= result['k_required'], 'PRIVACY_K_BELOW_THRESHOLD',
            'Independent retained k_hat is below the frozen CFG k')
    return dict(result, assertion='k_hat>=k', result='PASS')


def assert_u_qi_zero(cfg_id, rows, is_outlier, canonical_rids, *, reported=None, fixture_mode=False):

    result = _metrics(cfg_id, rows, is_outlier, canonical_rids, fixture_mode)
    if reported is not None:
        exact_keys(reported, {'u_qi_unique_rows', 'u_qi'}, 'reported U_QI')
        numerator = integer(reported['u_qi_unique_rows'], 'reported U_QI numerator')
        ratio = number(reported['u_qi'], 'reported U_QI')
        require(numerator == result['u_qi_unique_rows'] and ratio == result['u_qi'],
                'PRIVACY_REPORTED_U_QI_MISMATCH', 'Reported U_QI differs from independent retained partition')
    require(result['u_qi_unique_rows'] == 0, 'PRIVACY_U_QI_NONZERO',
            'A retained singleton-QI class makes U_QI positive')
    return dict(result, assertion='U_QI=0', result='PASS')
