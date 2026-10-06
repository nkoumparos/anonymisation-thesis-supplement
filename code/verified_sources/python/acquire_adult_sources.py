#!/usr/bin/env python3


from __future__ import annotations

import csv
import hashlib
import shutil
import sys
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
ARX_COMMIT = "4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f"
ARX_BASE_URL = (
    "https://raw.githubusercontent.com/arx-deidentifier/arx/"
    f"{ARX_COMMIT}/data"
)
UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/2/adult.zip"
UCI_ZIP_SHA256 = (
    "7537312dd56c2b98035880805ce99e68183a30ee468aa5329d6df0fbb3cc21bb"
)

ARX_FILES = (
    ("adult.csv", "benchmark_dataset", 2_516_935,
     "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5"),
    ("adult_hierarchy_age.csv", "qi_hierarchy_age", 2_232,
     "463f35372e8b1ad31fc624eb73c5da9297878a044ae5d61038eaf7b431ac55ca"),
    ("adult_hierarchy_education.csv", "qi_hierarchy_education", 692,
     "f22e5ee519c28b05538d4e5ddea0fbee5f0017fefb3abab3fa02272325bf9ce5"),
    ("adult_hierarchy_marital-status.csv", "qi_hierarchy_marital_status", 239,
     "3e7ba2c4a5cd4fec059b4e3a2c57fce6e7c34a20daee1e624990ddd7beba85e5"),
    ("adult_hierarchy_native-country.csv", "qi_hierarchy_native_country", 840,
     "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023"),
    ("adult_hierarchy_occupation.csv", "qi_hierarchy_occupation", 353,
     "16dc420d5d7f8ab4d1e6144eb1d19ab8314ef42523fe8c4ee202372db1c98126"),
    ("adult_hierarchy_race.csv", "qi_hierarchy_race", 66,
     "df11abf41fa0669455adc9c9f9fa88663afa0cee8327684ecca861cd32dc4209"),
    ("adult_hierarchy_sex.csv", "qi_hierarchy_sex", 16,
     "537d23f7b6969b916b5a5490eb1b32c273fefdc62ca050a7a813e23bbf3b78b2"),
    ("adult_hierarchy_workclass.csv", "qi_hierarchy_workclass", 211,
     "106f420349bf0071dbb25371795a78799edf24a64c3424619d563c3990ee8d02"),
)

UCI_MEMBERS = (
    ("adult.data", "original_training_source", 3_974_305,
     "5b00264637dbfec36bdeaab5676b0b309ff9eb788d63554ca0a249491c86603d"),
    ("adult.test", "original_holdout_source", 2_003_153,
     "a2a9044bc167a35b2361efbabec64e89d69ce82d9790d2980119aac5fd7e9c05"),
    ("adult.names", "data_dictionary", 5_229,
     "c248284c0b5de30c9e1958d6cdd168a34a654758b620e68f46aefa83fc0a576a"),
)

EXPECTED_HEADER = (
    "sex;age;race;marital-status;education;native-country;"
    "workclass;occupation;salary-class"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_file(path: Path, expected_bytes: int, expected_sha256: str) -> None:
    actual_bytes = path.stat().st_size
    actual_sha256 = sha256_file(path)
    if actual_bytes != expected_bytes or actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"Verification failed for {path}\n"
            f"Expected: bytes={expected_bytes}, sha256={expected_sha256}\n"
            f"Actual:   bytes={actual_bytes}, sha256={actual_sha256}\n"
            "The existing file was left unchanged."
        )


def acquire_file(
    url: str, destination: Path, expected_bytes: int, expected_sha256: str
) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_file(destination, expected_bytes, expected_sha256)
        return "existing_verified"

    temporary = destination.with_name(
        f".{destination.name}.{uuid.uuid4().hex}.download"
    )
    request = Request(url, headers={"User-Agent": "anonymisation-thesis/1.0"})

    try:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                with urlopen(request, timeout=180) as response, temporary.open("wb") as out:
                    shutil.copyfileobj(response, out)
                last_error = None
                break
            except (HTTPError, URLError, TimeoutError, OSError) as error:
                last_error = error
                temporary.unlink(missing_ok=True)
                if attempt < 3:
                    time.sleep(2 * attempt)
        if last_error is not None:
            raise RuntimeError(f"Download failed after three attempts: {url}") from last_error

        verify_file(temporary, expected_bytes, expected_sha256)
        temporary.rename(destination)
        return "downloaded_verified"
    finally:
        temporary.unlink(missing_ok=True)


def ensure_uci_members(zip_path: Path, destination: Path) -> list[dict[str, object]]:
    destination.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    missing: list[tuple[str, str, int, str]] = []

    for name, role, expected_bytes, expected_sha256 in UCI_MEMBERS:
        target = destination / name
        if target.exists():
            verify_file(target, expected_bytes, expected_sha256)
            results.append({
                "name": name,
                "role": role,
                "path": target,
                "bytes": expected_bytes,
                "sha256": expected_sha256,
                "status": "existing_verified",
            })
        else:
            missing.append((name, role, expected_bytes, expected_sha256))

    if not missing:
        return results

    with zipfile.ZipFile(zip_path, "r") as archive:
        members = archive.namelist()
        for name, role, expected_bytes, expected_sha256 in missing:
            if members.count(name) != 1:
                raise RuntimeError(
                    f"Expected exactly one archive member named {name!r}; "
                    f"found {members.count(name)}."
                )
            target = destination / name
            temporary = destination / f".{name}.{uuid.uuid4().hex}.extract"
            try:
                with archive.open(name, "r") as source, temporary.open("wb") as out:
                    shutil.copyfileobj(source, out)
                verify_file(temporary, expected_bytes, expected_sha256)
                temporary.rename(target)
                status = "extracted_verified"
            finally:
                temporary.unlink(missing_ok=True)

            results.append({
                "name": name,
                "role": role,
                "path": target,
                "bytes": expected_bytes,
                "sha256": expected_sha256,
                "status": status,
            })

    return results


def relative_posix(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def verify_adult_schema(adult_path: Path) -> tuple[int, int]:
    with adult_path.open("rb") as stream:
        first = stream.readline().rstrip(b"\r\n").decode("utf-8")
        line_count = 1 + sum(1 for _ in stream)
    if first != EXPECTED_HEADER:
        raise RuntimeError(f"Unexpected adult.csv header: {first!r}")
    if line_count != 30_163:
        raise RuntimeError(f"Unexpected adult.csv line count: {line_count}")
    return line_count, line_count - 1


def write_manifest(rows: list[dict[str, object]], verified_at: str) -> Path:
    manifest_path = REPO_ROOT / "manifest" / "adult_sources_candidate.tsv"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = manifest_path.with_name(f".{manifest_path.name}.{uuid.uuid4().hex}.tmp")
    fields = (
        "artifact", "role", "relative_path", "source_url", "pinned_revision",
        "archive_member", "verified_at_utc", "bytes", "sha256",
        "checksum_provenance", "license_note", "verification_status",
    )
    try:
        with temporary.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter="\t",
                                    lineterminator="\n")
            writer.writeheader()
            for row in rows:
                output = dict(row)
                output["verified_at_utc"] = verified_at
                writer.writerow(output)
        temporary.replace(manifest_path)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest_path


def main() -> int:
    if not (REPO_ROOT / ".git").is_dir():
        raise RuntimeError(f"Repository root was not found: {REPO_ROOT}")

    verified_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    arx_root = REPO_ROOT / "data" / "raw" / "arx-adult" / ARX_COMMIT
    uci_root = REPO_ROOT / "data" / "raw" / "uci-adult"
    rows: list[dict[str, object]] = []

    for name, role, expected_bytes, expected_sha256 in ARX_FILES:
        url = f"{ARX_BASE_URL}/{name}"
        target = arx_root / name
        status = acquire_file(url, target, expected_bytes, expected_sha256)
        rows.append({
            "artifact": name,
            "role": role,
            "relative_path": relative_posix(target),
            "source_url": url,
            "pinned_revision": ARX_COMMIT,
            "archive_member": "",
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "checksum_provenance": "researcher-computed; not publisher-published",
            "license_note": "ARX repository Apache-2.0; Adult origin UCI Adult",
            "verification_status": status,
        })

    zip_path = uci_root / "adult.zip"
    zip_status = acquire_file(UCI_ZIP_URL, zip_path, 620_237, UCI_ZIP_SHA256)
    rows.append({
        "artifact": "adult.zip",
        "role": "official_source_archive",
        "relative_path": relative_posix(zip_path),
        "source_url": UCI_ZIP_URL,
        "pinned_revision": f"sha256:{UCI_ZIP_SHA256}",
        "archive_member": "",
        "bytes": 620_237,
        "sha256": UCI_ZIP_SHA256,
        "checksum_provenance": "researcher-computed; not UCI-published",
        "license_note": "UCI Adult metadata: CC BY 4.0",
        "verification_status": zip_status,
    })

    member_results = ensure_uci_members(zip_path, uci_root)
    member_by_name = {str(item["name"]): item for item in member_results}
    for name, role, expected_bytes, expected_sha256 in UCI_MEMBERS:
        item = member_by_name[name]
        target = Path(item["path"])
        rows.append({
            "artifact": name,
            "role": role,
            "relative_path": relative_posix(target),
            "source_url": UCI_ZIP_URL,
            "pinned_revision": f"sha256:{UCI_ZIP_SHA256}",
            "archive_member": name,
            "bytes": expected_bytes,
            "sha256": expected_sha256,
            "checksum_provenance": "researcher-computed from verified archive member",
            "license_note": "UCI Adult metadata: CC BY 4.0",
            "verification_status": item["status"],
        })

    line_count, record_count = verify_adult_schema(arx_root / "adult.csv")
    manifest_path = write_manifest(rows, verified_at)

    for row in rows:
        print(
            f"{row['artifact']}\t{row['verification_status']}\t"
            f"{row['bytes']}\t{row['sha256']}"
        )
    print(f"ARX_DATA_COMMIT={ARX_COMMIT}")
    print(f"ARX_SELECTED_FILES={len(ARX_FILES)}")
    print("ARX_SALARY_CLASS_HIERARCHY_INCLUDED=false")
    print(f"ADULT_LINES={line_count}")
    print(f"ADULT_RECORDS={record_count}")
    print(f"UCI_VERIFIED_ARTIFACTS={1 + len(UCI_MEMBERS)}")
    print(f"MANIFEST={relative_posix(manifest_path)}")
    print("DATA_SOURCE_VERIFICATION=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
