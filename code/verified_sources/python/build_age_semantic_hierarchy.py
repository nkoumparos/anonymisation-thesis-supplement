#!/usr/bin/env python3


from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Sequence


ARX_COMMIT = "4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f"
EXPECTED_SOURCE_BYTES = 2_232
EXPECTED_SOURCE_SHA256 = (
    "463f35372e8b1ad31fc624eb73c5da9297878a044ae5d61038eaf7b431ac55ca"
)
EXPECTED_DERIVED_BYTES = 2_282
EXPECTED_DERIVED_SHA256 = (
    "de2a5bdc9b0ad72a31ca8199e7be5d39346646da604bf1fb8954afc7626e0ba5"
)
EXPECTED_MAPPING_REPORT_BYTES = 6_547
EXPECTED_MAPPING_REPORT_SHA256 = (
    "a611a05b0deb35b6a578f50b32e887e0994fd30b9525f96f831aeec625e32775"
)
EXPECTED_ROWS = 100
EXPECTED_LEVELS = 5
EXPECTED_DISTINCT_NODES = [100, 20, 10, 5, 1]
EXPECTED_GROUP_WIDTHS = {1: 5, 2: 10, 3: 20}
GENERATOR_SCHEMA = "adult-age-semantic-hierarchy/1.1"
RUNTIME_REQUIREMENT = "CPython 3.12.x; standard library only"


class BuildError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_runtime() -> None:
    require(sys.implementation.name == "cpython", "This generator requires CPython")
    require(sys.version_info[:2] == (3, 12), "This generator requires CPython 3.12.x")


def parse_source(data: bytes) -> list[list[str]]:
    require(len(data) == EXPECTED_SOURCE_BYTES, "Unexpected source byte length")
    require(sha256(data) == EXPECTED_SOURCE_SHA256, "Unexpected source SHA-256")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise BuildError("The source hierarchy is not ASCII") from error
    require("\r" not in text, "The pinned source must use LF line endings")
    require(text.endswith("\n"), "The pinned source must end with LF")
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=";", strict=True))
    except csv.Error as error:
        raise BuildError(f"CSV parsing failed: {error}") from error
    require(len(rows) == EXPECTED_ROWS, "Expected exactly 100 hierarchy rows")
    require(all(len(row) == EXPECTED_LEVELS for row in rows), "Expected five columns")
    require(all(all(cell and cell == cell.strip() for cell in row) for row in rows),
            "Blank or untrimmed hierarchy cell")
    require([int(row[0]) for row in rows] == list(range(1, 101)),
            "Leaves must be the ordered integers 1..100")
    require(all(row[-1] == "*" for row in rows), "Every row must have universal root '*'")
    return rows


def groups_by_level(rows: Sequence[Sequence[str]], level: int) -> dict[str, tuple[int, ...]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        groups[row[level]].append(int(row[0]))
    result = {label: tuple(leaves) for label, leaves in groups.items()}
    for label, leaves in result.items():
        require(len(set(leaves)) == len(leaves), f"Duplicate leaf in group {label!r}")
        require(list(leaves) == list(range(min(leaves), max(leaves) + 1)),
                f"Non-contiguous group {label!r} at level {level}")
        if level in EXPECTED_GROUP_WIDTHS:
            require(len(leaves) == EXPECTED_GROUP_WIDTHS[level],
                    f"Unexpected group width for {label!r} at level {level}")
    return result


def partition_signature(rows: Sequence[Sequence[str]], level: int) -> tuple[tuple[int, ...], ...]:
    return tuple(sorted(groups_by_level(rows, level).values()))


def build_semantic_rows(
    source_rows: list[list[str]],
) -> tuple[list[list[str]], list[dict[str, object]]]:
    source_groups = {level: groups_by_level(source_rows, level) for level in range(5)}
    require([len(source_groups[level]) for level in range(5)] == EXPECTED_DISTINCT_NODES,
            "Unexpected source node counts")

    label_maps: dict[int, dict[str, str]] = {}
    mappings: list[dict[str, object]] = []
    for level in (1, 2, 3):
        mapping: dict[str, str] = {}
        for old_label, leaves in sorted(
            source_groups[level].items(), key=lambda item: min(item[1])
        ):
            new_label = f"{min(leaves)}-{max(leaves)}"
            expected_old_label = f"{min(leaves) - 1}-{max(leaves) - 1}"
            require(old_label == expected_old_label,
                    f"Unexpected raw label {old_label!r}; expected {expected_old_label!r}")
            require(new_label not in mapping.values(),
                    f"Derived label collision at level {level}: {new_label}")
            mapping[old_label] = new_label
            mappings.append({
                "level": level,
                "old_label": old_label,
                "new_label": new_label,
                "minimum_leaf": min(leaves),
                "maximum_leaf": max(leaves),
                "leaf_count": len(leaves),
            })
        label_maps[level] = mapping

    derived_rows = [
        [
            row[0],
            label_maps[1][row[1]],
            label_maps[2][row[2]],
            label_maps[3][row[3]],
            row[4],
        ]
        for row in source_rows
    ]

    require([row[0] for row in derived_rows] == [row[0] for row in source_rows],
            "Leaf order changed")
    require([row[4] for row in derived_rows] == [row[4] for row in source_rows],
            "Root labels changed")
    for level in range(5):
        require(partition_signature(source_rows, level) == partition_signature(derived_rows, level),
                f"Partition mismatch at level {level}")
    require(
        [len(groups_by_level(derived_rows, level)) for level in range(5)]
        == EXPECTED_DISTINCT_NODES,
        "Unexpected derived node counts",
    )
    for row in derived_rows:
        leaf = int(row[0])
        for level in (1, 2, 3):
            low, high = (int(value) for value in row[level].split("-", 1))
            require(low <= leaf <= high,
                    f"Leaf {leaf} is outside derived label {row[level]!r}")
    require(any(item["old_label"] != item["new_label"] for item in mappings),
            "No semantic label correction was produced")
    return derived_rows, mappings


def serialize_csv(rows: Sequence[Sequence[str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerows(rows)
    return stream.getvalue().encode("ascii")


def serialize_report(
    source_data: bytes,
    derived_data: bytes,
    mappings: list[dict[str, object]],
) -> bytes:
    report = {
        "report_schema": GENERATOR_SCHEMA,
        "generator_runtime_requirement": RUNTIME_REQUIREMENT,
        "pinned_arx_commit": ARX_COMMIT,
        "source_artifact": "adult_hierarchy_age.csv",
        "source_bytes": len(source_data),
        "source_sha256": sha256(source_data),
        "derived_artifact": "adult_hierarchy_age_semantic.csv",
        "derived_bytes": len(derived_data),
        "derived_sha256": sha256(derived_data),
        "rows": EXPECTED_ROWS,
        "levels_including_leaf": EXPECTED_LEVELS,
        "distinct_nodes_per_level": EXPECTED_DISTINCT_NODES,
        "static_partition_equivalence": "PASS",
        "api_pilot_equivalence": "NOT_EVALUATED",
        "full_section_12_1": "NOT_EVALUATED",
        "main_runs_authorized": False,
        "leaf_values_unchanged": True,
        "root_unchanged": True,
        "intermediate_label_mappings": mappings,
    }
    return (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def check_target(path: Path, payload: bytes) -> str:
    if not path.exists():
        return "pending_create"
    require(path.is_file(), f"Target is not a regular file: {path}")
    require(path.read_bytes() == payload,
            f"Existing target differs and was left unchanged: {path}")
    return "existing_verified"


def atomic_create(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    installed = False
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        require(temporary.read_bytes() == payload, f"Temporary write verification failed: {path}")
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise BuildError(f"Target appeared during generation and was left unchanged: {path}") from error
        installed = True
        require(path.read_bytes() == payload, f"Installed artifact verification failed: {path}")
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


def materialize(path: Path, payload: bytes, status: str) -> str:
    if status == "existing_verified":
        return status
    atomic_create(path, payload)
    require(path.read_bytes() == payload, f"Final write verification failed: {path}")
    return "created_verified"


def main(argv: Sequence[str] | None = None) -> int:
    validate_runtime()
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mapping-report", type=Path, required=True)
    args = parser.parse_args(argv)

    source = args.source.resolve()
    output = args.output.resolve()
    mapping_report = args.mapping_report.resolve()
    require(source != output, "Source and output paths must differ")
    require(source != mapping_report, "Source and mapping report paths must differ")
    require(output != mapping_report, "Output and mapping report paths must differ")
    require(output not in mapping_report.parents and mapping_report not in output.parents,
            "Output and mapping report paths must not be ancestors of one another")

    require(source.is_file(), f"Source is not a regular file: {source}")
    require(source.stat().st_size == EXPECTED_SOURCE_BYTES,
            "Unexpected source byte length")
    source_data = source.read_bytes()
    source_rows = parse_source(source_data)
    derived_rows, mappings = build_semantic_rows(source_rows)
    derived_data = serialize_csv(derived_rows)
    report_data = serialize_report(source_data, derived_data, mappings)
    require(len(derived_data) == EXPECTED_DERIVED_BYTES,
            "Unexpected derived byte length")
    require(sha256(derived_data) == EXPECTED_DERIVED_SHA256,
            "Unexpected derived SHA-256")
    require(len(report_data) == EXPECTED_MAPPING_REPORT_BYTES,
            "Unexpected mapping report byte length")
    require(sha256(report_data) == EXPECTED_MAPPING_REPORT_SHA256,
            "Unexpected mapping report SHA-256")

    output_status = check_target(output, derived_data)
    report_status = check_target(mapping_report, report_data)
    output_status = materialize(output, derived_data, output_status)
    report_status = materialize(mapping_report, report_data, report_status)
    require(output.read_bytes() == derived_data,
            "Final output changed before completion")
    require(mapping_report.read_bytes() == report_data,
            "Final mapping report changed before completion")

    print(f"SOURCE_SHA256={sha256(source_data)}")
    print(f"DERIVED_SHA256={sha256(derived_data)}")
    print(f"DERIVED_BYTES={len(derived_data)}")
    print(f"MAPPING_REPORT_SHA256={sha256(report_data)}")
    print(f"MAPPING_COUNT={len(mappings)}")
    print("ROWS=100")
    print("LEVELS=5")
    print("DISTINCT_NODES=100,20,10,5,1")
    print("STATIC_PARTITION_EQUIVALENCE=PASS")
    print("API_PILOT_EQUIVALENCE=NOT_EVALUATED")
    print("FULL_SECTION_12_1=NOT_EVALUATED")
    print("MAIN_RUNS_AUTHORIZED=false")
    print(f"OUTPUT_STATUS={output_status}")
    print(f"MAPPING_REPORT_STATUS={report_status}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
