from collections import Counter
from fractions import Fraction

QIS = ('age', 'sex', 'race', 'marital-status', 'education',
       'native-country', 'workclass', 'occupation')
FIELDS = QIS + ('salary-class',)
HEIGHTS = dict(zip(QIS, (4, 1, 1, 2, 3, 2, 2, 2)))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, name, minimum=0):
    check(type(value) is int and value >= minimum, name + ': invalid integer')
    return value


def rational(value):
    if value is None:
        return None
    value = Fraction(value)
    return {'numerator': value.numerator, 'denominator': value.denominator,
            'fraction': str(value), 'decimal': format(float(value), '.17g')}


def intensity(named_levels):
    check(set(named_levels) == set(QIS), 'Expected exactly eight named QIs')
    for a, level in named_levels.items():
        integer(level, a)
        check(level <= HEIGHTS[a], a + ': level exceeds hierarchy height')
    return sum((Fraction(named_levels[a], HEIGHTS[a]) for a in QIS), Fraction()) / 8


def suppression_salary(n_input, n_retained, source_positive, retained_positive):
    integer(n_input, 'n_input', 1)
    integer(n_retained, 'n_retained', 1)
    integer(source_positive, 'source_positive')
    integer(retained_positive, 'retained_positive')
    check(n_retained <= n_input and source_positive <= n_input
          and retained_positive <= n_retained, 'Counts exceed population')
    ns = n_input - n_retained
    positive_s = source_positive - retained_positive
    check(0 <= positive_s <= ns, 'Suppressed salary counts do not balance')
    p0 = Fraction(source_positive, n_input)
    pr = Fraction(retained_positive, n_retained)
    ps = Fraction(positive_s, ns) if ns else None
    return {
        'n_input': n_input, 'n_retained': n_retained, 'n_suppressed': ns,
        'S': rational(Fraction(ns, n_input)),
        'source_salary_counts': {'>50K': source_positive, '<=50K': n_input-source_positive},
        'retained_salary_counts': {'>50K': retained_positive, '<=50K': n_retained-retained_positive},
        'suppressed_salary_counts': {'>50K': positive_s, '<=50K': ns-positive_s},
        'source_positive_prevalence': rational(p0),
        'retained_positive_prevalence': rational(pr),
        'suppressed_positive_prevalence': rational(ps),
        'suppressed_prevalence_status': 'DEFINED' if ns else 'NA_NO_SUPPRESSED_ROWS',
        'prevalence_difference_retained_minus_source': rational(pr-p0),
        'prevalence_absolute_error': rational(abs(pr-p0)),
        'prevalence_difference_percentage_points': rational(100*(pr-p0)),
        'suppressed_minus_retained_prevalence': rational(ps-pr) if ns else None,
    }


def histogram_quantile(histogram, probability, *, convention):
    check(convention == 'type7_unweighted_items', 'An explicit quantile convention is required')
    check(isinstance(probability, Fraction) and 0 <= probability <= 1,
          'Probability must be an exact Fraction in [0,1]')
    for size, frequency in histogram.items():
        integer(size, 'size', 1)
        integer(frequency, 'frequency', 1)
    n = sum(histogram.values())
    if not n:
        return None
    rank = (n-1)*probability
    lo = rank.numerator // rank.denominator
    weight = rank-lo

    def at(index):
        seen = 0
        for size, frequency in sorted(histogram.items()):
            seen += frequency
            if index < seen:
                return size
        raise ValueError('Rank exceeds histogram')

    return Fraction(at(lo)) if not weight else (1-weight)*at(lo)+weight*at(lo+1)


def histogram_summary(histogram, *, convention):
    median = histogram_quantile(histogram, Fraction(1, 2), convention=convention)
    p95 = histogram_quantile(histogram, Fraction(19, 20), convention=convention)
    return {'item_count': sum(histogram.values()),
            'size_sum': sum(size*frequency for size, frequency in histogram.items()),
            'minimum': min(histogram) if histogram else None,
            'median': rational(median), 'p95': rational(p95),
            'maximum': max(histogram) if histogram else None,
            'size_frequency_histogram': [
                {'size': size, 'frequency': frequency}
                for size, frequency in sorted(histogram.items())],
            'quantile_convention': convention}


def equivalence_class_diagnostics(retained_rows, *, convention):
    check(bool(retained_rows), 'Retained population cannot be empty')
    for row in retained_rows:
        check(set(row) == set(FIELDS), 'EC rows must contain exactly the nine release fields')
        check(all(type(v) is str and bool(v) for v in row.values()),
              'EC fields must be nonempty strings')
    result = {}
    for family, fields in [('QI', QIS), ('full', FIELDS)]:
        sizes = Counter(tuple(row[a] for a in fields) for row in retained_rows)
        histogram = Counter(sizes.values())
        summary = histogram_summary(histogram, convention=convention)
        check(summary['size_sum'] == len(retained_rows), 'Class sizes do not cover retained rows')
        summary['weighting'] = 'one_observation_per_equivalence_class'
        summary['unique_rows'] = histogram.get(1, 0)
        summary['uniqueness'] = rational(Fraction(histogram.get(1, 0), len(retained_rows)))
        result[family] = summary
    return result


def tie_diagnostics(records, *, convention):
    histogram = Counter()
    abstentions = 0
    for record in records:
        check(set(record) == {'tie_size', 'attempted'}, 'Only tie_size and attempted are admitted')
        size = integer(record['tie_size'], 'tie_size')
        check(type(record['attempted']) is bool and record['attempted'] == (size > 0),
              'Abstention and tie size disagree')
        if size:
            histogram[size] += 1
        else:
            abstentions += 1
    summary = histogram_summary(histogram, convention=convention)
    summary.update({'population': 'all_non_abstained_target_draw_attempts',
                    'pair_count': len(records), 'abstention_count': abstentions,
                    'empty_status': 'NA_NO_ATTEMPTS' if not histogram else None})
    return summary


def selection_tvd(reference_counts, retained_counts):

    for label, counts in [('reference', reference_counts), ('retained', retained_counts)]:
        for count in counts.values():
            integer(count, label + ' count')
    n0, nr = sum(reference_counts.values()), sum(retained_counts.values())
    check(n0 > 0 and 0 < nr <= n0, 'Invalid reference/retained totals')
    keys = set(reference_counts) | set(retained_counts)
    check(all(retained_counts.get(k, 0) <= reference_counts.get(k, 0) for k in keys),
          'Retained counts are not a subset of reference counts')
    return sum((abs(Fraction(reference_counts.get(k, 0), n0)
                    - Fraction(retained_counts.get(k, 0), nr)) for k in keys), Fraction())/2


def eight_qi_tvd(reference_by_qi, retained_by_qi):
    check(set(reference_by_qi) == set(QIS) == set(retained_by_qi),
          'Exactly eight QI tables are required')
    reference_totals = {sum(v.values()) for v in reference_by_qi.values()}
    retained_totals = {sum(v.values()) for v in retained_by_qi.values()}
    check(len(reference_totals) == len(retained_totals) == 1, 'QI table totals differ')
    values = {a: selection_tvd(reference_by_qi[a], retained_by_qi[a]) for a in QIS}
    return {'by_qi': {a: rational(v) for a, v in values.items()},
            'unweighted_mean': rational(sum(values.values(), Fraction())/8),
            'maximum': rational(max(values.values()))}
