import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import risk_windows_acl as ACL
from risk_admission import canonical, identity
from risk_bootstrap_compute import validate_public_bytes, AUDIT_SCHEMA


class PublicationError(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise PublicationError(code)


def plain(path):
    for entry in (path, *path.parents):
        if entry.exists() or entry.is_symlink():
            info = entry.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info,"st_file_attributes",0) & 0x400,
                    "OUTPUT_REPARSE_OR_SYMLINK")


def _write(path, raw):
    plain(path)
    with path.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and s.st_size == len(raw), "EXCLUSIVE_FILE_IDENTITY")


def _protect(directory, mode):
    require(directory.is_dir() and not any(directory.iterdir()), "PROTECT_FRESH_EMPTY_DIRECTORY")
    if sys.platform == "win32":
        return ACL.protect_new_directory(str(directory))
    require(mode == "synthetic", "OPERATIONAL_NATIVE_WINDOWS_REQUIRED")
    os.chmod(directory, 0o700)
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700, "SYNTHETIC_POSIX_PROTECTION")
    return {"kind":"synthetic_posix", "mode":"0700", "native_windows_acl_verified":False}


def _postcheck(paths, mode):
    for p in paths:
        plain(p)
    if sys.platform == "win32":
        return ACL.inspect_private_paths([str(p) for p in paths])
    require(mode == "synthetic", "OPERATIONAL_NATIVE_WINDOWS_REQUIRED")
    require(all(stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600) for p in paths), "SYNTHETIC_POSIX_POSTCHECK")
    return {"kind":"synthetic_posix", "native_windows_acl_verified":False, "checked_paths":len(paths)}


def validate_pair(public_raw, private_raw):
    receipt = validate_public_bytes(public_raw)
    require(type(private_raw) is bytes and 0 < len(private_raw) <= 150000000
            and identity(private_raw) == receipt["private_audit"], "PRIVATE_AUDIT_BINDING")
    def pairs(items):
        value = {}
        for k,v in items:
            require(k not in value, "DUPLICATE_PRIVATE_JSON_KEY")
            value[k] = v
        return value
    def invalid(_):
        raise PublicationError("NONFINITE_PRIVATE_JSON")
    try:
        private = json.loads(private_raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationError("INVALID_PRIVATE_AUDIT") from None
    require(type(private) is dict and set(private) == {"schema","mode","visibility","public_input_binding",
        "canonical_cluster_order","target_cluster_membership","cluster_multiplicities","sampling","risk_consumer_result"}
        and private["schema"] == AUDIT_SCHEMA and private["visibility"] == "PRIVATE_DO_NOT_UPLOAD"
        and private["mode"] == receipt["mode"] and private["public_input_binding"] == receipt["public_input_binding"], "PRIVATE_AUDIT_SCOPE")
    return receipt


def publish_new(output_directory, public_raw, private_raw):
    receipt = validate_pair(public_raw, private_raw)
    require(sys.platform == "win32" or receipt["mode"] == "synthetic", "OPERATIONAL_NATIVE_WINDOWS_REQUIRED")
    output = Path(output_directory)
    require(output.is_absolute() and ".." not in output.parts and output.parent.is_dir(), "ABSOLUTE_NEW_OUTPUT_REQUIRED")
    plain(output)
    require(not output.exists() and not output.is_symlink(), "OUTPUT_ALREADY_EXISTS")
    output.mkdir(mode=0o700, exist_ok=False)
    try:
        root_acl = _protect(output, receipt["mode"])
        private_dir, public_dir = output/"private", output/"public"
        private_dir.mkdir(mode=0o700)
        private_acl = _protect(private_dir, receipt["mode"])
        public_dir.mkdir(mode=0o700)

        private_path = private_dir/"risk_bootstrap_audit.json"
        _write(private_path, private_raw)
        if sys.platform != "win32":
            os.chmod(private_path, 0o600)
        post = _postcheck([output, private_dir, private_path], receipt["mode"])
        public_path = public_dir/"risk_bootstrap_receipt.json"
        _write(public_path, public_raw)

        require(identity(private_path.read_bytes()) == receipt["private_audit"]
                and identity(public_path.read_bytes()) == identity(public_raw), "PUBLISHED_BYTES_CHANGED")
        marker = {"schema":"rtm-risk-bootstrap-publication-completion/1.0", "result":"PASS",
            "mode":receipt["mode"], "public_receipt":identity(public_raw), "private_audit":identity(private_raw),
            "new_root_protection":root_acl, "new_private_protection":private_acl, "postcheck":post,
            "existing_acls_changed":False, "execution_authorization_conferred":False}
        _write(output/"COMPLETED.json", canonical(marker))
        return marker
    except Exception:
        raise PublicationError("PUBLICATION_INCOMPLETE_PRESERVE_DIRECTORY_NO_AUTOMATIC_RETRY") from None
