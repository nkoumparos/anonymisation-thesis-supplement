from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from utility_compute import (
    BOOTSTRAP_SCHEMA, PARTIAL_SCHEMA, POINT_SCHEMA, validate_receipt_bytes,
)


class PublicationError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise PublicationError(message)


def _identity(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _plain(path):
    for entry in (path, *path.parents):
        if not entry.exists() and not entry.is_symlink():
            continue
        info = entry.lstat()
        _require(not stat.S_ISLNK(info.st_mode) and not
                 (getattr(info, "st_file_attributes", 0) & 0x400),
                 "Symlink/reparse output is forbidden")


def _exclusive(path, data):
    _plain(path)
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def publish_new_receipt(output_directory, receipt_data, *, expected_receipt_identity):

    _require(type(receipt_data) is bytes and receipt_data, "Immutable receipt bytes required")
    _require(type(expected_receipt_identity) is dict and
             set(expected_receipt_identity) == {"bytes", "sha256"} and
             type(expected_receipt_identity["bytes"]) is int and
             type(expected_receipt_identity["sha256"]) is str and
             _identity(receipt_data) == expected_receipt_identity,
             "Receipt identity differs")
    receipt = validate_receipt_bytes(receipt_data)
    stage = receipt["record_schema"]
    _require(stage in (POINT_SCHEMA, BOOTSTRAP_SCHEMA, PARTIAL_SCHEMA), "Unknown receipt stage")
    output = Path(output_directory)
    _require(output.is_absolute(), "Absolute output directory required")
    _plain(output)
    _require(output.parent.is_dir() and not output.exists() and not output.is_symlink(),
             "Output must be new under an existing directory")
    output.mkdir(mode=0o700, exist_ok=False)


    try:
        (output / "public").mkdir(mode=0o700)
        (output / "private").mkdir(mode=0o700)
        public_name = "failure_receipt.json" if stage == PARTIAL_SCHEMA else "utility_receipt.json"
        _exclusive(output / "public" / public_name, receipt_data)
        session = {"record_schema": "rtm-prediction-only-utility-session/1",
                   "result": receipt["result"], "mode": receipt["mode"],
                   "receipt_schema": stage, "public_receipt": _identity(receipt_data),
                   "private_arrays_written": False, "authorization_conferred": False,
                   "acl_protection_not_established_by_this_writer": True}
        session_data = _bytes(session)
        _exclusive(output / "private/SESSION.json", session_data)
        marker = {"record_schema": "rtm-utility-bundle-completion/1",
                  "result": receipt["result"], "receipt": _identity(receipt_data),
                  "session": _identity(session_data), "authorization_conferred": False,
                  "stage_completed": stage != PARTIAL_SCHEMA}
        marker_name = "FAILED.json" if stage == PARTIAL_SCHEMA else "COMPLETED.json"
        _exclusive(output / marker_name, _bytes(marker))
    except Exception as error:
        raise PublicationError("Publication incomplete; preserve the new directory; no retry/overwrite") from error
    return marker
