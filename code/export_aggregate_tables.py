#!/usr/bin/env python3
"""Export aggregate tables as CSV files."""
import argparse
import csv
import hashlib
import json
import pathlib
import sys

EXPECTED = {
    'utility_release': 17, 'utility_counterfactual': 17, 'dummy_baseline': 1,
    'paired_delta_auroc': 16, 'structural': 17, 'tvd': 17,
    'equivalence_classes': 34, 'native_country': 17,
    'suppressed_retained_profiles': 153, 'privacy_summary': 17,
    'ties': 85, 'risk_points_and_controls': 85, 'success_coverage': 340,
    'risk_intervals': 195, 'ohe_unknown_categories': 264, 'ohe_model_summary': 33,
}

TITLES = {
    'utility_release': 'Χρησιμότητα δημοσιευμένων συνόλων και αρχικού συνόλου αναφοράς',
    'utility_counterfactual': 'Χρησιμότητα αντιπαραθετικών συνόλων χωρίς καταστολή',
    'dummy_baseline': 'Απλός ταξινομητής αναφοράς βάσει συχνοτήτων κλάσεων',
    'paired_delta_auroc': 'Ζευγαρωμένη απώλεια AUROC έναντι του αρχικού συνόλου',
    'structural': 'Καταστολή, γενίκευση και μεταβολή της εισοδηματικής σύνθεσης',
    'tvd': 'Αποστάσεις ολικής μεταβολής κατανομών',
    'equivalence_classes': 'Μεγέθη κλάσεων ισοδυναμίας',
    'native_country': 'Χειρισμός της σπάνιας τιμής Holand-Netherlands',
    'suppressed_retained_profiles': 'Ευρετήριο οριακών κατανομών αρχικών γνωρισμάτων',
    'privacy_summary': 'Παρατηρούμενα συντακτικά κριτήρια ιδιωτικότητας',
    'ties': 'Ισοπαλίες μεταξύ υποψήφιων εγγραφών',
    'risk_points_and_controls': 'Εκτιμήσεις κινδύνου και μάρτυρες σύγκρισης',
    'success_coverage': 'Κάλυψη και υπό συνθήκη επιτυχία σύνδεσης',
    'risk_intervals': 'Διαστήματα σταθερότητας κινδύνου και διαφορών κινδύνου',
    'ohe_unknown_categories': 'Άγνωστες κατηγορίες ανά μοντέλο και γνώρισμα',
    'ohe_model_summary': 'Σύνοψη άγνωστων κατηγοριών ανά μοντέλο',
}

THESIS_MAPPING = {
    'utility_release': {'tables': ['Πίνακας 1 του Παραρτήματος'], 'sections': ['4.6', '5.2.1', '5.2.3']},
    'utility_counterfactual': {'tables': ['Πίνακας 2 του Παραρτήματος'], 'sections': ['4.5.2', '4.6.2', '6.1.2']},
    'dummy_baseline': {'tables': ['Πίνακας 3 του Παραρτήματος'], 'sections': ['4.6.2']},
    'paired_delta_auroc': {'tables': ['Πίνακας 4 του Παραρτήματος'], 'sections': ['4.7.2', '5.2.3'], 'figures': ['5.1', '5.5']},
    'structural': {'tables': ['Πίνακας 5 του Παραρτήματος'], 'sections': ['4.5.1', '5.3.2'], 'figures': ['5.4']},
    'tvd': {'tables': ['Πίνακας 6 του Παραρτήματος'], 'sections': ['4.5.2', '5.3.2'], 'figures': ['5.4']},
    'equivalence_classes': {'tables': ['Πίνακας 7 του Παραρτήματος'], 'sections': ['4.3', '5.3.2']},
    'native_country': {'tables': ['Πίνακας 5 του Παραρτήματος: συνοδευτική σημείωση'], 'sections': ['5.3.2']},
    'suppressed_retained_profiles': {'tables': ['Πίνακας 5 του Παραρτήματος: συνοδευτική σημείωση'], 'sections': ['4.5.1', '4.5.2', '5.3.2']},
    'privacy_summary': {'tables': ['Πίνακας 12 του Παραρτήματος'], 'sections': ['4.3', '5.1', '6.1.1']},
    'ties': {'tables': ['Πίνακας 8 του Παραρτήματος', 'Πίνακας 9 του Παραρτήματος'], 'sections': ['4.4.2', '5.3.1']},
    'risk_points_and_controls': {'tables': ['Πίνακας 13 του Παραρτήματος', '5.1', '5.2'], 'sections': ['4.4.3', '4.4.4'], 'figures': ['5.2', '5.5']},
    'success_coverage': {'tables': ['Πίνακας 10 του Παραρτήματος'], 'sections': ['4.4.3']},
    'risk_intervals': {'tables': [], 'sections': ['5.2.2', '5.3.1'], 'figures': ['5.2', '5.3']},
    'ohe_unknown_categories': {'tables': ['Πίνακας 11 του Παραρτήματος'], 'sections': ['4.6.1', '4.6.2', '6.3.3']},
    'ohe_model_summary': {'tables': ['Πίνακας 11 του Παραρτήματος'], 'sections': ['4.6.1', '4.6.2', '6.3.3']},
}

OMIT_KEYS = {'sources', 'source_refs', 'private_rid_included', 'numeric_acceptance_applied'}

def clean(obj):
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items() if k not in OMIT_KEYS}
    if isinstance(obj, list):
        return [clean(v) for v in obj]
    return obj

def scalar(obj):
    """Preserve the source decimal string without float conversion."""
    if isinstance(obj, dict) and 'decimal' in obj:
        return obj['decimal']
    return obj

def base(r, keys):
    return {k: r.get(k) for k in keys}

def interval(row, value, prefix):
    row[prefix + '_low'] = None if value is None else value[0]
    row[prefix + '_high'] = None if value is None else value[1]

def write_csv(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: 'NA' if v is None else v for k, v in row.items()})

    with path.open(encoding='utf-8-sig', newline='') as f:
        readback = list(csv.DictReader(f))
    assert len(readback) == len(rows)
    for expected, actual in zip(rows, readback):
        for k in fields:
            v = expected.get(k)
            assert actual[k] == ('NA' if v is None else str(v)), (path.name, k)
    return fields

def export(source, out):
    public = json.loads(source.read_text(encoding='utf-8'))
    if public.get('schema') != 'thesis-public-aggregate-results/1':
        raise ValueError('Expected the included public aggregates.json schema')
    src = {'tables': {name: {'record_count': len(records), 'records': records}
                      for name, records in public['tables'].items()}}
    assert set(src['tables']) == set(EXPECTED)
    tables = {}
    for key, count in EXPECTED.items():
        t = src['tables'][key]
        assert t['record_count'] == len(t['records']) == count, key
        tables[key] = [clean(r) for r in t['records']]

    out.mkdir(parents=True, exist_ok=True)
    csv_dir = out / 'csv'
    csv_dir.mkdir(exist_ok=True)
    flat = {}
    helpers = {}

    for key in ('utility_release', 'utility_counterfactual'):
        flat[key] = []
        for r in tables[key]:
            row = base(r, ['config_id', 'group', 'holdout_rows', 'auroc',
                           'balanced_accuracy', 'average_precision', 'accuracy'])
            interval(row, r['auroc_ci95'], 'auroc_ci95')
            flat[key].append(row)

    flat['dummy_baseline'] = []
    for r in tables['dummy_baseline']:
        row = dict(r['point_metrics'])
        row['threshold'] = r['threshold']
        row['intervals'] = r['intervals']
        for name in ('fitted_class_prior', 'training_class_counts', 'holdout_class_counts'):
            row[name + '_negative'] = r[name][0]
            row[name + '_positive'] = r[name][1]
        flat['dummy_baseline'].append(row)

    flat['paired_delta_auroc'] = []
    for r in tables['paired_delta_auroc']:
        row = base(r, ['config_id', 'point_estimate', 'direction'])
        interval(row, r['ci95'], 'ci95')
        flat['paired_delta_auroc'].append(row)

    flat['structural'] = []
    helpers['generalization_levels'] = []
    helpers['salary_class_counts'] = []
    for r in tables['structural']:
        s = r['suppression_and_salary']
        row = base(r, ['config_id', 'arx_loss', 'arx_loss_status'])
        row['G'] = scalar(r['generalization_G'])
        for k in ('n_input', 'n_retained', 'n_suppressed', 'S',
                  'source_positive_prevalence', 'retained_positive_prevalence',
                  'suppressed_positive_prevalence', 'suppressed_prevalence_status',
                  'prevalence_absolute_error', 'prevalence_difference_percentage_points',
                  'prevalence_difference_retained_minus_source', 'suppressed_minus_retained_prevalence'):
            row[k] = scalar(s[k])
        flat['structural'].append(row)
        helpers['generalization_levels'].append({'config_id': r['config_id'], **r['transformation_by_name']})
        countrow = {'config_id': r['config_id']}
        for population in ('source', 'retained', 'suppressed'):
            for income, label in [('<=50K', 'negative'), ('>50K', 'positive')]:
                countrow[population + '_' + label + '_count'] = s[population + '_salary_counts'][income]
        helpers['salary_class_counts'].append(countrow)

    flat['tvd'] = []
    for r in tables['tvd']:
        row = {'config_id': r['config_id']}
        for family in ('TVD_marginal', 'TVD_QI_salary'):
            for qi, v in r[family]['by_qi'].items():
                row[family + '__' + qi] = scalar(v)
            for k in ('unweighted_mean', 'maximum'):
                row[family + '__' + k] = scalar(r[family][k])
        flat['tvd'].append(row)

    flat['equivalence_classes'] = []
    helpers['equivalence_class_histograms'] = []
    for r in tables['equivalence_classes']:
        s = r['summary']
        row = base(r, ['config_id', 'kind'])
        for k in ('item_count', 'size_sum', 'minimum', 'median', 'p95', 'maximum', 'unique_rows', 'uniqueness'):
            row[k] = scalar(s[k])
        flat['equivalence_classes'].append(row)
        for h in s['size_frequency_histogram']:
            helpers['equivalence_class_histograms'].append({**base(r, ['config_id', 'kind']), **h})

    flat['native_country'] = [base(r, ['config_id', 'source_value', 'source_count', 'final_level', 'fate', 'rule_status'])
                              for r in tables['native_country']]

    flat['suppressed_retained_profiles'] = []
    helpers['marginal_profile_values'] = []
    for r in tables['suppressed_retained_profiles']:
        ids = base(r, ['config_id', 'attribute', 'n_source', 'n_retained', 'n_suppressed'])
        flat['suppressed_retained_profiles'].append(ids)
        for level in r['levels']:
            helpers['marginal_profile_values'].append({**ids, **{k: scalar(v) for k,v in level.items()}})

    flat['privacy_summary'] = []
    privacy_fields = ['k_required', 'k_hat', 'l_required', 'l_hat', 't_required',
                      't_hat_original_global', 'u_qi', 'u_full', 'equivalence_class_count',
                      'equivalence_class_size_min', 'equivalence_class_size_max']
    for r in tables['privacy_summary']:
        s = r['published_summary']
        flat['privacy_summary'].append({'config_id': r['config_id'],
            **{k: None if s is None else scalar(s.get(k)) for k in privacy_fields}})

    flat['ties'] = []
    helpers['tie_histograms'] = []
    for r in tables['ties']:
        s = r['summary']
        row = base(r, ['scenario', 'config_id'])
        for k in ('pair_count', 'item_count', 'abstention_count', 'minimum', 'median', 'p95', 'maximum', 'size_sum', 'empty_status'):
            row[k] = scalar(s.get(k))
        flat['ties'].append(row)
        for h in s['size_frequency_histogram']:
            helpers['tie_histograms'].append({**base(r, ['scenario', 'config_id']), **h})

    flat['risk_points_and_controls'] = tables['risk_points_and_controls']
    flat['success_coverage'] = tables['success_coverage']
    flat['risk_intervals'] = []
    for r in tables['risk_intervals']:
        row = base(r, ['scenario', 'kind', 'comparison_id', 'point_estimate', 'direction', 'endpoint_sign_classification'])
        interval(row, r['stability_interval_95'], 'stability95')
        flat['risk_intervals'].append(row)
    flat['ohe_unknown_categories'] = tables['ohe_unknown_categories']
    flat['ohe_model_summary'] = [base(r, [
        'model_id', 'config_id', 'group', 'prediction_row_count', 'qi_count',
        'qi_with_unknown_rows_count', 'total_unknown_row_qi_incidences',
        'total_distinct_unknown_levels_per_qi', 'unknown_levels_by_qi_text',
        'unknown_rows_by_qi_text']) for r in tables['ohe_model_summary']]

    manifest = []
    for index, (name, records) in enumerate(flat.items(), 1):
        assert len(records) == EXPECTED[name]
        fields = write_csv(csv_dir / (name + '.csv'), records)
        manifest.append({'family': name, 'title_el': TITLES[name], 'record_count': len(records),
                         'expected_record_count': EXPECTED[name], 'matches_expected_count': True,
                         'csv': 'csv/' + name + '.csv', 'json_pointer': '/tables/' + name,
                         'source_pointer': '/tables/' + name, 'columns': fields,
                         'thesis_mapping': THESIS_MAPPING[name]})
    helper_manifest = []
    for name, records in helpers.items():
        fields = write_csv(csv_dir / (name + '.csv'), records)
        helper_manifest.append({'csv': 'csv/' + name + '.csv', 'row_count': len(records), 'columns': fields})

    clean_json = {'schema': 'thesis-public-aggregate-results/1', 'tables': tables}
    json_path = out / 'aggregates.json'
    json_path.write_text(json.dumps(clean_json, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    assert json.loads(json_path.read_text(encoding='utf-8'))['tables'] == tables

    def nums(x):
        if isinstance(x, bool): return []
        if isinstance(x, (int, float)): return [x]
        if isinstance(x, dict): return [n for k,v in x.items() if k not in OMIT_KEYS for n in nums(v)]
        if isinstance(x, list): return [n for v in x for n in nums(v)]
        return []
    for name in EXPECTED:
        assert nums(src['tables'][name]['records']) == nums(tables[name]), name

    metadata = {'schema': 'thesis-result-table-manifest/1',
        'source_document': source.name,
        'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'source_date_note': 'Συνοδευτικό αρχείο δημόσιων συγκεντρωτικών αποτελεσμάτων.',
        'encoding': 'UTF-8 with BOM', 'delimiter': ',', 'decimal_separator': '.',
        'missing_value': 'NA', 'rounding_applied': False,
        'new_experimental_calculations': False, 'families': manifest,
        'helper_tables': helper_manifest, 'family_count': len(manifest),
        'A14_all_16_counts_match': True}
    (out / 'TABLE_MANIFEST.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out / 'SOURCE.txt').write_text('Πηγή: ' + source.name + ', δημόσια συγκεντρωτικά αποτελέσματα.\n'
        + 'SHA-256: ' + metadata['source_sha256'] + '\n'
        + 'Εξαγωγή των 16 ομάδων συγκεντρωτικών αποτελεσμάτων χωρίς επανεκτέλεση πειραμάτων ή στρογγυλοποίηση.\n'
        + 'Η αναδημιουργία αυτή αφορά την παρουσίαση των αποθηκευμένων αποτελεσμάτων.\n', encoding='utf-8')
    print(json.dumps({'families': len(manifest), 'csv_files': len(manifest)+len(helper_manifest),
                      'counts': {x['family']: x['record_count'] for x in manifest},
                      'helpers': {x['csv']: x['row_count'] for x in helper_manifest},
                      'verification': 'PASS'}, ensure_ascii=False))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-json', type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent.parent / 'results' / 'aggregates.json')
    parser.add_argument('--output-dir', required=True, type=pathlib.Path)
    args = parser.parse_args()
    source = args.input_json.resolve()
    output = args.output_dir.resolve()
    if not source.is_file():
        parser.error('Input aggregates.json does not exist')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error('The output directory must be new or empty. Existing files are never overwritten.')
    export(source, output)
