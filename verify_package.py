#!/usr/bin/env python3

from pathlib import Path
import csv
import hashlib
import json
import sys
import unicodedata


def windows_path_errors(names):

    errors = []
    seen = {}
    reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {
        prefix + str(i) for prefix in ('COM', 'LPT') for i in range(1, 10)
    }
    for name in sorted(names):
        parts = name.split('/')
        for part in parts:
            if part in ('', '.', '..') or part.endswith((' ', '.')):
                errors.append('Non-portable path component: ' + name)
            if part.split('.')[0].upper() in reserved or any(c in part for c in '<>:"\\|?*'):
                errors.append('Invalid Windows path: ' + name)
        normalized = '/'.join(unicodedata.normalize('NFC', part).casefold() for part in parts)
        if normalized in seen and seen[normalized] != name:
            errors.append('Case-insensitive path collision: ' + seen[normalized] + ' / ' + name)
        seen[normalized] = name
    return errors


def main():
    root = Path(__file__).resolve().parent
    errors = []
    manifest = root / 'checksums.sha256'
    if not manifest.is_file():
        print('FAIL: checksums.sha256 is missing')
        return 1
    expected = set()
    for line in manifest.read_text(encoding='utf-8').splitlines():
        digest, name = line.split('  ', 1)
        if name in expected:
            errors.append('Duplicate manifest entry: ' + name)
        expected.add(name)
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            errors.append('Invalid relative path: ' + name)
        elif not path.is_file():
            errors.append('Missing file: ' + name)
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errors.append('Changed file: ' + name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    errors.extend(windows_path_errors(actual))
    extra = actual - expected - {'checksums.sha256'}
    if extra:
        errors.append('Unexpected files: ' + ', '.join(sorted(extra)))
    tables = json.loads((root / 'results' / 'TABLE_MANIFEST.json').read_text(encoding='utf-8'))
    if len(tables['families']) != 16:
        errors.append('Expected 16 main table families')
    rows = 0
    for table in tables['families']:
        path = root / 'results' / table['csv']
        with path.open(encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            count = sum(1 for _ in reader)
        rows += count
        if count != table['expected_record_count']:
            errors.append('Unexpected row count: ' + str(path.relative_to(root)))
    if errors:
        for error in errors:
            print('FAIL:', error)
        return 1
    print(f'PASS: {len(expected)} file hashes, 16 table families, {rows} aggregate records.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
