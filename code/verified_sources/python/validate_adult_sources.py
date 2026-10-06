#!/usr/bin/env python3


from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import sys
import uuid
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Sequence


ARX_COMMIT = "4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f"
EXPECTED_SCHEMA = (
    "sex",
    "age",
    "race",
    "marital-status",
    "education",
    "native-country",
    "workclass",
    "occupation",
    "salary-class",
)
QI_ORDER = (
    "age",
    "education",
    "marital-status",
    "native-country",
    "workclass",
    "occupation",
    "race",
    "sex",
)
UCI_COLUMNS = (
    "age",
    "workclass",
    "fnlwgt",
    "education",
    "education-num",
    "marital-status",
    "occupation",
    "relationship",
    "race",
    "sex",
    "capital-gain",
    "capital-loss",
    "hours-per-week",
    "native-country",
    "salary-class",
)
PROJECTION = tuple(UCI_COLUMNS.index(name) for name in EXPECTED_SCHEMA)
TARGET_LABELS = ("<=50K", ">50K")

EXPECTED_ARX_FILES = {
    "adult.csv": (2_516_935, "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5"),
    "adult_hierarchy_age.csv": (2_232, "463f35372e8b1ad31fc624eb73c5da9297878a044ae5d61038eaf7b431ac55ca"),
    "adult_hierarchy_education.csv": (692, "f22e5ee519c28b05538d4e5ddea0fbee5f0017fefb3abab3fa02272325bf9ce5"),
    "adult_hierarchy_marital-status.csv": (239, "3e7ba2c4a5cd4fec059b4e3a2c57fce6e7c34a20daee1e624990ddd7beba85e5"),
    "adult_hierarchy_native-country.csv": (840, "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023"),
    "adult_hierarchy_occupation.csv": (353, "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126"),
    "adult_hierarchy_race.csv": (66, "df11abf41fa0669455adc9c9f9fa88663afa0cee8327684ecca861cd32dc4209"),
    "adult_hierarchy_sex.csv": (16, "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2"),
    "adult_hierarchy_workclass.csv": (211, "106f420349bf0071dbb25371795a78799edf24a64c3424619d563c3990ee8d02"),
}
EXPECTED_ZIP = (620_237, "7537312dd56c2b98035880805ce99e68183a30ee468aa5329d6df0fbb3cc21bb")
EXPECTED_DERIVED_AGE = (
    2_282,
    "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5",
)
EXPECTED_AGE_MAPPING_REPORT = (
    6_547,
    "a611a05b0deb35b6a578f50b32e887e0994fd30b9525f96f831aeec625e32775",
)
EXPECTED_MEMBERS = {
    "adult.data": (3_974_305, "5b00264637dbfec36bdeaab5676b0b309ff9eb788d63554ca0a249491c86603d"),
    "adult.test": (2_003_153, "a2a9044bc167a35b2361efbabec64e89d69ce82d9790d2980119aac5fd7e9c05"),
    "adult.names": (5_229, "c248284c0b5de30c9e1958d6cdd168a34a654758b620e68f46aefa83fc0a576a"),
}
EXPECTED_HIERARCHIES = {
    "age": {"rows": 100, "levels": 5, "distinct_nodes": [100, 20, 10, 5, 1]},
    "education": {"rows": 16, "levels": 4, "distinct_nodes": [16, 5, 3, 1]},
    "marital-status": {"rows": 7, "levels": 3, "distinct_nodes": [7, 2, 1]},
    "native-country": {"rows": 41, "levels": 3, "distinct_nodes": [41, 5, 1]},
    "workclass": {"rows": 8, "levels": 3, "distinct_nodes": [8, 3, 1]},
    "occupation": {"rows": 14, "levels": 3, "distinct_nodes": [14, 3, 1]},
    "race": {"rows": 5, "levels": 2, "distinct_nodes": [5, 1]},
    "sex": {"rows": 2, "levels": 2, "distinct_nodes": [2, 1]},
}
RUNTIME_REQUIREMENT = "CPython 3.12.x; standard library only"


class ValidationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_runtime() -> None:
    require(sys.implementation.name == "cpython", "This validator requires CPython")
    require(sys.version_info[:2] == (3, 12), "This validator requires CPython 3.12.x")


def read_verified_file(path: Path, expected_size: int, expected_hash: str) -> bytes:
    require(path.is_file(), f"Input is not a regular file: {path}")
    require(path.stat().st_size == expected_size, f"Unexpected byte length: {path}")
    data = path.read_bytes()
    require(len(data) == expected_size, f"Input changed while being read: {path}")
    require(sha256(data) == expected_hash, f"Unexpected SHA-256: {path}")
    return data


def parse_semicolon(data: bytes, source: str) -> list[list[str]]:
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(f"Non-ASCII bytes in {source}") from error
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=";", strict=True))
    except csv.Error as error:
        raise ValidationError(f"CSV error in {source}: {error}") from error
    require(rows, f"No rows in {source}")
    for row_number, row in enumerate(rows, 1):
        require(row, f"Blank record in {source}, row {row_number}")
        require(all(cell != "" for cell in row), f"Empty cell in {source}, row {row_number}")
        require(all(cell == cell.strip() for cell in row), f"Untrimmed cell in {source}, row {row_number}")
    return rows


def parse_uci(data: bytes, member: str, *, test: bool) -> tuple[list[list[str]], dict[str, object]]:
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError(f"Non-ASCII bytes in {member}") from error
    physical = text.splitlines()
    require(physical and physical[-1] == "", f"Expected one trailing blank line in {member}")
    require(all(line != "" for line in physical[:-1]), f"Unexpected internal blank line in {member}")
    if test:
        require(physical[0] == "|1x3 Cross validator", "Unexpected adult.test metadata line")
        physical = physical[1:]
    physical = physical[:-1]
    rows: list[list[str]] = []
    try:
        reader = csv.reader(physical, delimiter=",", skipinitialspace=True, strict=True)
        for row_number, row in enumerate(reader, 2 if test else 1):
            require(len(row) == 15, f"Expected 15 fields in {member}, row {row_number}")
            clean = [cell.strip() for cell in row]
            require(all(cell != "" for cell in clean), f"Unexpected empty field in {member}, row {row_number}")
            rows.append(clean)
    except csv.Error as error:
        raise ValidationError(f"CSV error in {member}: {error}") from error

    raw_target = Counter(row[14] for row in rows)
    if test:
        require(set(raw_target) == {"<=50K.", ">50K."}, "Unexpected raw adult.test labels")
    else:
        require(set(raw_target) == set(TARGET_LABELS), "Unexpected raw adult.data labels")

    missing_by_field = Counter()
    missing_patterns = Counter()
    complete: list[list[str]] = []
    for row in rows:
        missing = tuple(UCI_COLUMNS[index] for index, value in enumerate(row) if value == "?")
        missing_patterns[missing] += 1
        missing_by_field.update(missing)
        if missing:
            continue
        if test:
            require(row[14].endswith("."), "Missing terminal period in adult.test label")
            row = [*row]
            row[14] = row[14][:-1]
        complete.append(row)

    projected = [[row[index] for index in PROJECTION] for row in complete]
    metrics = {
        "raw_records": len(rows),
        "complete_records": len(complete),
        "rejected_incomplete_records": len(rows) - len(complete),
        "missing_occurrences_by_field": dict(sorted(missing_by_field.items())),
        "target_counts_complete": dict(sorted(Counter(row[-1] for row in projected).items())),
    }
    return projected, metrics


def canonical_table(rows: Sequence[Sequence[str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(EXPECTED_SCHEMA)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def table_metrics(rows: list[list[str]], canonical: bytes) -> dict[str, object]:
    require(all(len(row) == len(EXPECTED_SCHEMA) for row in rows), "Non-rectangular projected table")
    require(all(cell not in {"", "?"} for row in rows for cell in row), "Missing projected value")
    require(set(row[-1] for row in rows) == set(TARGET_LABELS), "Unexpected projected labels")
    return {
        "records": len(rows),
        "columns": list(EXPECTED_SCHEMA),
        "no_missing": True,
        "target_labels": list(TARGET_LABELS),
        "target_counts": dict(sorted(Counter(row[-1] for row in rows).items())),
        "distinct_values": {
            name: len({row[index] for row in rows})
            for index, name in enumerate(EXPECTED_SCHEMA)
        },
        "canonical_format": "UTF-8; semicolon; LF; header; source order; final LF",
        "canonical_bytes": len(canonical),
        "canonical_sha256": sha256(canonical),
    }


def hierarchy_metrics(
    attribute: str,
    rows: list[list[str]],
    train: list[list[str]],
    holdout: list[list[str]],
) -> dict[str, object]:
    expected = EXPECTED_HIERARCHIES[attribute]
    widths = Counter(len(row) for row in rows)
    require(len(widths) == 1, f"Non-rectangular hierarchy: {attribute}")
    levels = next(iter(widths))
    require(len(rows) == expected["rows"], f"Unexpected hierarchy row count: {attribute}")
    require(levels == expected["levels"], f"Unexpected hierarchy level count: {attribute}")
    require(all("?" not in row for row in rows), f"Question-mark value in hierarchy: {attribute}")

    leaves = [row[0] for row in rows]
    require(len(set(leaves)) == len(leaves), f"Duplicate leaf: {attribute}")
    require(all(row[-1] == "*" for row in rows), f"Non-universal root: {attribute}")
    require(all("*" not in row[:-1] for row in rows), f"Premature root: {attribute}")

    distinct_nodes = [len({row[level] for row in rows}) for level in range(levels)]
    require(distinct_nodes == expected["distinct_nodes"], f"Unexpected node counts: {attribute}")
    for level in range(levels - 1):
        parents: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            parents[row[level]].add(row[level + 1])
        require(all(len(values) == 1 for values in parents.values()),
                f"Non-functional parent mapping: {attribute}, level {level}")

    column = EXPECTED_SCHEMA.index(attribute)
    leaf_set = set(leaves)
    train_values = {row[column] for row in train}
    holdout_values = {row[column] for row in holdout}
    train_uncovered = sorted(train_values - leaf_set)
    holdout_uncovered = sorted(holdout_values - leaf_set)
    require(not train_uncovered, f"Uncovered training values: {attribute}")
    require(not holdout_uncovered, f"Uncovered holdout values: {attribute}")

    return {
        "rows": len(rows),
        "levels_including_leaf": levels,
        "max_generalization_level": levels - 1,
        "distinct_nodes_per_level": distinct_nodes,
        "rectangular": True,
        "nonempty": True,
        "unique_leaves": True,
        "universal_root": "*",
        "functional_parent_mapping": True,
        "coverage": {
            "training": {
                "distinct_values": len(train_values),
                "uncovered": train_uncovered,
                "unused_hierarchy_leaves": sorted(leaf_set - train_values),
            },
            "holdout": {
                "distinct_values": len(holdout_values),
                "uncovered": holdout_uncovered,
                "unused_hierarchy_leaves": sorted(leaf_set - holdout_values),
            },
        },
    }


def grouped_leaves(rows: Sequence[Sequence[str]], level: int) -> dict[str, tuple[int, ...]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        groups[row[level]].append(int(row[0]))
    return {label: tuple(leaves) for label, leaves in groups.items()}


def partition_blocks(rows: Sequence[Sequence[str]], level: int) -> tuple[tuple[int, ...], ...]:
    return tuple(sorted(grouped_leaves(rows, level).values()))


def validate_semantic_age(
    raw_rows: list[list[str]], derived_rows: list[list[str]]
) -> dict[str, object]:
    interval = re.compile(r"^(\d+)-(\d+)$")
    require(len(raw_rows) == 100 and len(derived_rows) == 100,
            "Age hierarchies must contain 100 rows")
    require(all(len(row) == 5 for row in derived_rows),
            "Derived age hierarchy must contain five columns")
    raw_leaves = [int(row[0]) for row in raw_rows]
    derived_leaves = [int(row[0]) for row in derived_rows]
    require(raw_leaves == list(range(1, 101)), "Unexpected raw age leaves")
    require(derived_leaves == raw_leaves, "Derived age leaves or order changed")
    require(all(row[-1] == "*" for row in derived_rows),
            "Derived age root must remain '*'")
    require([row[-1] for row in derived_rows] == [row[-1] for row in raw_rows],
            "Derived age roots changed")

    node_counts = [len({row[level] for row in derived_rows}) for level in range(5)]
    require(node_counts == [100, 20, 10, 5, 1], "Unexpected derived age node counts")
    mappings: list[dict[str, object]] = []

    for level in range(5):
        raw_blocks = partition_blocks(raw_rows, level)
        derived_blocks = partition_blocks(derived_rows, level)
        require(raw_blocks == derived_blocks,
                f"Raw/derived partition mismatch at age level {level}")
        flattened = [leaf for block in derived_blocks for leaf in block]
        require(sorted(flattened) == list(range(1, 101)),
                f"Lost or duplicated age leaf at level {level}")

    for level in range(4):
        parents: dict[str, set[str]] = defaultdict(set)
        for row in derived_rows:
            parents[row[level]].add(row[level + 1])
        require(all(len(values) == 1 for values in parents.values()),
                f"Non-functional derived age parent mapping at level {level}")

    for level in (1, 2, 3):
        raw_groups = grouped_leaves(raw_rows, level)
        derived_groups = grouped_leaves(derived_rows, level)
        derived_by_block = {leaves: label for label, leaves in derived_groups.items()}
        require(len(derived_by_block) == len(derived_groups),
                f"Derived age label collision at level {level}")
        for old_label, leaves in sorted(raw_groups.items(), key=lambda item: min(item[1])):
            require(leaves in derived_by_block,
                    f"Missing derived block for raw age label {old_label!r}")
            new_label = derived_by_block[leaves]
            match = interval.fullmatch(new_label)
            require(match is not None, f"Invalid derived age label {new_label!r}")
            low, high = map(int, match.groups())
            require((low, high) == (min(leaves), max(leaves)),
                    f"Derived age label is not exact min-max: {new_label!r}")
            require(list(leaves) == list(range(low, high + 1)),
                    f"Non-contiguous derived age block: {new_label!r}")
            mappings.append({
                "level": level,
                "old_label": old_label,
                "new_label": new_label,
                "minimum_leaf": low,
                "maximum_leaf": high,
                "leaf_count": len(leaves),
            })

    require(len(mappings) == 35, "Expected exactly 35 age label mappings")
    require(all(item["old_label"] != item["new_label"] for item in mappings),
            "Every intermediate age label must be corrected")
    return {
        "status": "PASS",
        "rows": 100,
        "levels_including_leaf": 5,
        "distinct_nodes_per_level": node_counts,
        "leaf_values_and_order_unchanged": True,
        "root_unchanged": True,
        "functional_parent_mapping": True,
        "static_partition_equivalence_all_levels": True,
        "intermediate_label_mappings": mappings,
    }


def validate_age_mapping_report(
    report_data: bytes,
    derived_data: bytes,
    expected_mappings: list[dict[str, object]],
) -> dict[str, object]:
    try:
        report = json.loads(report_data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("Invalid age mapping report JSON") from error
    require(report.get("report_schema") == "adult-age-semantic-hierarchy/1.1",
            "Unexpected age mapping report schema")
    require(report.get("source_sha256") == EXPECTED_ARX_FILES["adult_hierarchy_age.csv"][1],
            "Mapping report source SHA-256 mismatch")
    require(report.get("derived_bytes") == len(derived_data),
            "Mapping report derived byte length mismatch")
    require(report.get("derived_sha256") == sha256(derived_data),
            "Mapping report derived SHA-256 mismatch")
    require(report.get("static_partition_equivalence") == "PASS",
            "Mapping report does not record static partition equivalence PASS")
    require(report.get("api_pilot_equivalence") == "NOT_EVALUATED",
            "Mapping report must not claim API pilot equivalence")
    require(report.get("full_section_12_1") == "NOT_EVALUATED",
            "Mapping report must not claim completion of section 12.1")
    require(report.get("main_runs_authorized") is False,
            "Mapping report must not authorize main runs")
    require(report.get("intermediate_label_mappings") == expected_mappings,
            "Mapping report label mappings differ from independent validation")
    return {
        "status": "PASS",
        "bytes": len(report_data),
        "sha256": sha256(report_data),
        "mapping_count": len(expected_mappings),
    }


def native_country_assertions(
    hierarchy_rows: list[list[str]], train: list[list[str]], holdout: list[list[str]]
) -> dict[str, object]:
    column = EXPECTED_SCHEMA.index("native-country")
    leaves = {row[0] for row in hierarchy_rows}
    train_values = {row[column] for row in train}
    holdout_values = {row[column] for row in holdout}
    train_holand = sum(row[column] == "Holand-Netherlands" for row in train)
    holdout_holand = sum(row[column] == "Holand-Netherlands" for row in holdout)
    require(len(leaves) == 41, "Expected 41 native-country hierarchy leaves")
    require(len(train_values) == 41, "Expected 41 native-country training values")
    require(len(holdout_values) == 40, "Expected 40 native-country holdout values")
    require(train_values == leaves, "Training native-country values must equal hierarchy leaves")
    require(holdout_values < leaves, "Holdout native-country values must be a proper subset")
    require(leaves - holdout_values == {"Holand-Netherlands"},
            "Unexpected native-country leaf absent from holdout")
    require(train_holand == 1, "Expected Holand-Netherlands exactly once in training")
    require(holdout_holand == 0, "Expected Holand-Netherlands absent from holdout")
    return {
        "status": "PASS",
        "hierarchy_leaves": 41,
        "training_distinct_values": 41,
        "holdout_distinct_values": 40,
        "Holand-Netherlands": {"training_count": 1, "holdout_count": 0},
        "holdout_unused_hierarchy_leaves": ["Holand-Netherlands"],
    }


def age_semantic_finding(rows: list[list[str]]) -> dict[str, object]:
    shifted_labels = 0
    for level in (1, 2, 3):
        for old_label, leaves in grouped_leaves(rows, level).items():
            expected = f"{min(leaves) - 1}-{max(leaves) - 1}"
            require(old_label == expected, f"Unexpected pinned raw age label {old_label!r}")
            shifted_labels += 1
    return {
        "id": "H-AGE-001",
        "status": "resolved_by_protocol_derived_hierarchy",
        "finding": "All 35 raw intermediate labels are shifted by -1 relative to their leaf sets.",
        "shifted_unique_labels": shifted_labels,
        "changed_cells_in_derived_hierarchy": 300,
    }


def native_country_finding(rows: list[list[str]]) -> dict[str, object]:
    mapping = {row[0]: row[1] for row in rows}
    require(mapping.get("South") == "Africa", "Unexpected upstream mapping for native-country=South")
    return {
        "id": "H-NATIVE-001",
        "status": "documented_not_substantively_validated",
        "finding": "The source label 'South' is mapped by the pinned ARX hierarchy to 'Africa'.",
        "mapping": {"South": "Africa"},
        "interpretation": "No independent geographic meaning is inferred by this validator.",
    }


def validate(
    arx_dir: Path,
    uci_zip: Path,
    derived_age: Path,
    age_mapping_report: Path,
) -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    arx_bytes: dict[str, bytes] = {}
    for name, (size, digest) in EXPECTED_ARX_FILES.items():
        data = read_verified_file(arx_dir / name, size, digest)
        arx_bytes[name] = data
        inputs.append({"artifact": name, "bytes": len(data), "sha256": sha256(data), "verified": True})

    zip_data = read_verified_file(uci_zip, *EXPECTED_ZIP)
    inputs.append({"artifact": "adult.zip", "bytes": len(zip_data), "sha256": sha256(zip_data), "verified": True})
    derived_age_data = read_verified_file(derived_age, *EXPECTED_DERIVED_AGE)
    mapping_report_data = read_verified_file(age_mapping_report, *EXPECTED_AGE_MAPPING_REPORT)
    inputs.extend([
        {
            "artifact": "adult_hierarchy_age_semantic.csv",
            "role": "effective_age_hierarchy",
            "bytes": len(derived_age_data),
            "sha256": sha256(derived_age_data),
            "verified": True,
        },
        {
            "artifact": "adult_hierarchy_age_semantic_mapping.json",
            "role": "age_label_mapping",
            "bytes": len(mapping_report_data),
            "sha256": sha256(mapping_report_data),
            "verified": True,
        },
    ])
    member_bytes: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(zip_data), "r") as archive:
        names = archive.namelist()
        require(archive.testzip() is None, "ZIP CRC validation failed")
        for name, (size, digest) in EXPECTED_MEMBERS.items():
            require(names.count(name) == 1, f"Expected exactly one ZIP member: {name}")
            data = archive.read(name)
            require(len(data) == size, f"Unexpected ZIP member size: {name}")
            require(sha256(data) == digest, f"Unexpected ZIP member hash: {name}")
            member_bytes[name] = data
            inputs.append({"artifact": name, "archive_member": name, "bytes": len(data), "sha256": sha256(data), "verified": True})

    adult_rows = parse_semicolon(arx_bytes["adult.csv"], "adult.csv")
    require(tuple(adult_rows[0]) == EXPECTED_SCHEMA, "Unexpected adult.csv schema or order")
    train = adult_rows[1:]
    require(len(train) == 30_162, "Unexpected adult.csv record count")
    train_canonical = canonical_table(train)
    train_from_uci, data_cleaning = parse_uci(member_bytes["adult.data"], "adult.data", test=False)
    require(len(train_from_uci) == 30_162, "Unexpected complete-case adult.data count")
    require(train_from_uci == train, "adult.csv is not row-for-row equal to projected complete adult.data")

    holdout, test_cleaning = parse_uci(member_bytes["adult.test"], "adult.test", test=True)
    require(len(holdout) == 15_060, "Unexpected complete-case adult.test count")
    holdout_canonical = canonical_table(holdout)

    train_report = table_metrics(train, train_canonical)
    train_report["row_for_row_equal_to_projected_complete_adult_data"] = True
    holdout_report = table_metrics(holdout, holdout_canonical)
    require(train_report["canonical_sha256"] == "0711f26a4ba718f2eb8fa04395fc296cb3be1ba67135c828b93f6506bf4d8ca9",
            "Unexpected canonical training digest")
    require(holdout_report["canonical_sha256"] == "8e363515eda22f5b3545fdb427450c688b41f461d5eefce32eac9c515577019b",
            "Unexpected canonical holdout digest")

    hierarchy_rows: dict[str, list[list[str]]] = {}
    hierarchy_report: dict[str, dict[str, object]] = {}
    derived_age_rows = parse_semicolon(derived_age_data, "adult_hierarchy_age_semantic.csv")
    for attribute in QI_ORDER:
        name = f"adult_hierarchy_{attribute}.csv"
        rows = parse_semicolon(arx_bytes[name], name)
        hierarchy_rows[attribute] = rows
        effective_rows = derived_age_rows if attribute == "age" else rows
        report = hierarchy_metrics(attribute, effective_rows, train, holdout)
        report["source_sha256"] = EXPECTED_ARX_FILES[name][1]
        if attribute == "age":
            report["effective_artifact"] = "adult_hierarchy_age_semantic.csv"
            report["effective_sha256"] = sha256(derived_age_data)
        hierarchy_report[attribute] = report

    semantic_age_report = validate_semantic_age(hierarchy_rows["age"], derived_age_rows)
    mapping_validation = validate_age_mapping_report(
        mapping_report_data,
        derived_age_data,
        semantic_age_report["intermediate_label_mappings"],
    )
    country_assertions = native_country_assertions(
        hierarchy_rows["native-country"], train, holdout
    )

    factors = [hierarchy_report[name]["levels_including_leaf"] for name in QI_ORDER]
    lattice_nodes = math.prod(factors)
    require(factors == [5, 4, 3, 3, 3, 3, 2, 2], "Unexpected lattice factors")
    require(lattice_nodes == 6_480, "Unexpected lattice size")

    findings = [
        age_semantic_finding(hierarchy_rows["age"]),
        native_country_finding(hierarchy_rows["native-country"]),
        {
            "id": "H-OCCUPATION-001",
            "status": "documented_not_substantively_validated",
            "finding": "Occupation groupings are upstream benchmark conventions and are not validated as substantive classifications.",
        },
    ]

    require(data_cleaning == {
        "raw_records": 32_561,
        "complete_records": 30_162,
        "rejected_incomplete_records": 2_399,
        "missing_occurrences_by_field": {"native-country": 583, "occupation": 1_843, "workclass": 1_836},
        "target_counts_complete": {"<=50K": 22_654, ">50K": 7_508},
    }, "Unexpected adult.data cleaning metrics")
    require(test_cleaning == {
        "raw_records": 16_281,
        "complete_records": 15_060,
        "rejected_incomplete_records": 1_221,
        "missing_occurrences_by_field": {"native-country": 274, "occupation": 966, "workclass": 963},
        "target_counts_complete": {"<=50K": 11_360, ">50K": 3_700},
    }, "Unexpected adult.test cleaning metrics")

    return {
        "report_schema": "adult-source-and-hierarchy-preflight/1.2",
        "protocol_version": "v1.2.1",
        "protocol_steps": ["12.1.2", "12.1.3"],
        "validator_runtime_requirement": RUNTIME_REQUIREMENT,
        "status": {
            "source_identity": "PASS",
            "dataset_structure_and_derivation": "PASS",
            "hierarchy_structure_and_coverage": "PASS",
            "native_country_predeclared_assertions": "PASS",
            "age_semantic_derivation": "PASS",
            "age_static_partition_equivalence": "PASS",
            "benchmark_conventions": "DOCUMENTED_NOT_SUBSTANTIVELY_VALIDATED",
            "adult_hierarchy_static_preflight": "PASS",
            "scope_result": "PASS_WITHIN_DECLARED_STATIC_SCOPE",
        },
        "pinned_arx_data_commit": ARX_COMMIT,
        "inputs": inputs,
        "projection": {
            "source_columns": list(UCI_COLUMNS),
            "zero_based_indices": list(PROJECTION),
            "output_columns": list(EXPECTED_SCHEMA),
            "holdout_operations_in_order": [
                "remove exact metadata line",
                "parse 15 comma-separated fields",
                "trim surrounding whitespace",
                "mark '?' as missing",
                "reject records with at least one missing field",
                "remove exactly one terminal period from salary-class",
                "project and reorder nine fields while preserving source order",
            ],
        },
        "cleaning": {"adult.data": data_cleaning, "adult.test": test_cleaning},
        "training": train_report,
        "holdout": holdout_report,
        "native_country_predeclared_assertions": country_assertions,
        "hierarchies": hierarchy_report,
        "age_semantic_hierarchy": semantic_age_report,
        "age_mapping_report_validation": mapping_validation,
        "lattice": {
            "qi_order": list(QI_ORDER),
            "level_counts_including_leaf": factors,
            "formula": "5*4*3*3*3*3*2*2",
            "nodes": lattice_nodes,
        },
        "semantic_findings": findings,
        "holdout_governance": {
            "used_during_this_step_for": [
                "complete-case derivation and exact record-count assertion",
                "canonical holdout digest assertion",
                "schema, target-label, and missingness assertions",
                "predeclared target-class frequency assertions",
                "descriptive per-column distinct-value cardinalities",
                "predeclared native-country 40/0 and hierarchy leaf-coverage assertions",
            ],
            "this_validator_does_not_perform": [
                "hierarchy modification",
                "ARX configuration",
                "classifier selection",
            ],
        },
        "scope_limitations": {
            "api_pilot_equivalence": "NOT_EVALUATED",
            "full_section_12_1": "NOT_EVALUATED",
            "gate_a": "NOT_EVALUATED",
            "main_runs_authorized": False,
        },
    }


def serialize_report(report: dict[str, object]) -> bytes:
    return (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_report(path: Path, payload: bytes) -> str:
    if path.exists():
        require(path.is_file(), f"Report target is not a regular file: {path}")
        require(path.read_bytes() == payload,
                f"Existing report differs and was left unchanged: {path}")
        return "existing_verified"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    installed = False
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        require(temporary.read_bytes() == payload, "Temporary report verification failed")
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ValidationError(
                f"Report target appeared during validation and was left unchanged: {path}"
            ) from error
        installed = True
        require(path.read_bytes() == payload, "Final report verification failed")
    except Exception:
        if installed:
            try:
                if os.path.samefile(temporary, path):
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        temporary.unlink(missing_ok=True)
    return "created_verified"


def main(argv: Sequence[str] | None = None) -> int:
    validate_runtime()
    parser = argparse.ArgumentParser()
    parser.add_argument("--arx-dir", type=Path, required=True)
    parser.add_argument("--uci-zip", type=Path, required=True)
    parser.add_argument("--derived-age", type=Path, required=True)
    parser.add_argument("--age-mapping-report", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    arx_dir = args.arx_dir.resolve()
    uci_zip = args.uci_zip.resolve()
    derived_age = args.derived_age.resolve()
    age_mapping_report = args.age_mapping_report.resolve()
    report_path = args.report.resolve()
    input_paths = {
        uci_zip,
        derived_age,
        age_mapping_report,
        *(arx_dir / name for name in EXPECTED_ARX_FILES),
    }
    require(report_path not in input_paths, "Report path collides with a validated input")
    report = validate(arx_dir, uci_zip, derived_age, age_mapping_report)
    report_payload = serialize_report(report)
    report_status = write_report(report_path, report_payload)
    require(report_path.read_bytes() == report_payload,
            "Report changed before validation completed")
    print(f"REPORT={args.report}")
    print(f"REPORT_STATUS={report_status}")
    print(f"REPORT_SHA256={sha256(report_payload)}")
    print("SOURCE_IDENTITY=PASS")
    print("DATASET_VALIDATION=PASS")
    print("HIERARCHY_STRUCTURE=PASS")
    print("NATIVE_COUNTRY_DISTINCT=41,40")
    print("HOLAND_NETHERLANDS_COUNTS=1,0")
    print(f"DERIVED_AGE_SHA256={EXPECTED_DERIVED_AGE[1]}")
    print("STATIC_PARTITION_EQUIVALENCE=PASS")
    print("LATTICE_NODES=6480")
    print("ADULT_HIERARCHY_STATIC_PREFLIGHT=PASS")
    print("API_PILOT_EQUIVALENCE=NOT_EVALUATED")
    print("FULL_SECTION_12_1=NOT_EVALUATED")
    print("MAIN_RUNS_AUTHORIZED=false")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
