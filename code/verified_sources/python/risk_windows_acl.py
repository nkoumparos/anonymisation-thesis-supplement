from __future__ import annotations

import base64
import ctypes
import json
import ntpath
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "rtm-point-windows-acl/1.0"
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
MAX_PATHS = 16
MAX_OUTPUT_BYTES = 65536
FULL_CONTROL = 2032127


class ACLValidationError(RuntimeError):
    pass


_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'Stop'
try {
    $payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('__PAYLOAD_BASE64__'))
    $request = ConvertFrom-Json -InputObject $payload
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $currentSid = $current.Value
    if ($currentSid -notmatch '^S-1-(5-21|12-1)-[0-9]+-[0-9]+-[0-9]+-[0-9]+$') { throw 'user-identity' }
    $allowed = @($currentSid, 'S-1-5-18', 'S-1-5-32-544')

    function Assert-PlainPath([string] $path) {
        $full = [System.IO.Path]::GetFullPath($path)
        if ($full -ne $path -or $full.StartsWith('\\')) { throw 'path' }
        $cursor = $full
        $count = 0
        while ($cursor) {
            $attributes = [System.IO.File]::GetAttributes($cursor)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
            $count += 1
            $next = [System.IO.Path]::GetDirectoryName($cursor)
            if ($next -eq $cursor) { throw 'path' }
            $cursor = $next
        }
        return $count
    }

    function Read-BoundedAcl([string] $path, [int] $index) {
        $ancestors = Assert-PlainPath $path
        $attributes = [System.IO.File]::GetAttributes($path)
        if (($attributes -band [System.IO.FileAttributes]::Device) -ne 0) { throw 'type' }
        $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
        $sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
        if ($isDirectory) {
            $acl = [System.IO.Directory]::GetAccessControl($path, $sections)
            $kind = 'directory'
        } else {
            $acl = [System.IO.File]::GetAccessControl($path, $sections)
            $kind = 'file'
        }
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($allowed -notcontains $owner) { throw 'owner' }
        $binary = $acl.GetSecurityDescriptorBinaryForm()
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($binary, 0)
        $present = ($descriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0
        if (-not $present -or $null -eq $descriptor.DiscretionaryAcl) { throw 'dacl' }
        if ($descriptor.DiscretionaryAcl.Count -gt 256) { throw 'acl-size' }
        $allowSids = [System.Collections.Generic.HashSet[string]]::new()
        $fullControlSids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) { throw 'ace-type' }
            if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
                $sid = $ace.SecurityIdentifier.Value
                if ($allowed -notcontains $sid) { throw 'allow-principal' }
                [void] $allowSids.Add($sid)
                if ($ace.AccessMask -eq 2032127 -and [int]$ace.AceFlags -eq 3 -and -not $ace.IsCallback) {
                    [void] $fullControlSids.Add($sid)
                }
            } elseif ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessDenied) {
                throw 'ace-qualifier'
            }
        }
        $allowList = [string[]]@($allowSids)
        $fullList = [string[]]@($fullControlSids)
        [System.Array]::Sort($allowList, [System.StringComparer]::Ordinal)
        [System.Array]::Sort($fullList, [System.StringComparer]::Ordinal)
        return [ordered]@{
            index = $index; kind = $kind; owner_sid = $owner
            dacl_present = $true; dacl_null = $false; reparse = $false
            dacl_protected = [bool]$acl.AreAccessRulesProtected
            allow_sids = @($allowList); full_control_inheritable_sids = @($fullList)
            ace_count = [int]$descriptor.DiscretionaryAcl.Count
            checked_ancestors = [int]$ancestors
        }
    }

    if ($request.operation -eq 'protect') {
        if (@($request.paths).Count -ne 1) { throw 'request' }
        $target = [string]$request.paths[0]
        [void](Assert-PlainPath $target)
        if (-not [System.IO.Directory]::Exists($target)) { throw 'directory' }
        if ([System.IO.Directory]::GetFileSystemEntries($target).Length -ne 0) { throw 'not-empty' }
        $newAcl = [System.Security.AccessControl.DirectorySecurity]::new()
        $newAcl.SetOwner($current)
        $newAcl.SetAccessRuleProtection($true, $false)
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach ($sidText in $allowed) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidText)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $inherit, [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            [void]$newAcl.AddAccessRule($rule)
        }
        [void](Assert-PlainPath $target)
        if ([System.IO.Directory]::GetFileSystemEntries($target).Length -ne 0) { throw 'not-empty' }
        [System.IO.Directory]::SetAccessControl($target, $newAcl)
    } elseif ($request.operation -ne 'inspect') {
        throw 'request'
    }
    $records = @()
    for ($i = 0; $i -lt @($request.paths).Count; $i++) {
        $records += (Read-BoundedAcl ([string]$request.paths[$i]) $i)
    }
    $response = [ordered]@{ schema = 'rtm-point-windows-acl/1.0'; operation = $request.operation;
        success = $true; current_user_sid = $currentSid; records = @($records) }
    $response | ConvertTo-Json -Depth 8 -Compress
    exit 0
} catch {
    [System.Console]::Error.WriteLine('BOUNDARY_ACL_CHECK_FAILED')
    exit 71
}
'''


def _paths(paths):
    if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= MAX_PATHS:
        raise ACLValidationError("ACL path list is invalid")
    checked = []
    for supplied in paths:
        try:
            path = os.fspath(supplied)
        except TypeError as exc:
            raise ACLValidationError("ACL path is invalid") from exc
        if not isinstance(path, str) or not 4 <= len(path) <= 4096:
            raise ACLValidationError("ACL path is invalid")
        drive, tail = ntpath.splitdrive(path)
        if (not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\")
                or "/" in path or any(ord(c) < 32 for c in path)
                or ":" in tail or ntpath.normpath(path) != path
                or any(part.endswith((" ", ".")) for part in tail.split("\\") if part)):
            raise ACLValidationError("ACL path must be a canonical local Windows path")
        checked.append(path)
    if len({p.casefold() for p in checked}) != len(checked):
        raise ACLValidationError("Duplicate ACL path")
    return checked


def _powershell():
    if sys.platform != "win32":
        raise ACLValidationError("Native Windows ACL verification is required")
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ACLValidationError("Windows system directory is unavailable")
    root = buffer.value
    configured = os.environ.get("SystemRoot", "")
    if ntpath.normcase(ntpath.normpath(configured)) != ntpath.normcase(root):
        raise ACLValidationError("Windows system directory does not match SystemRoot")
    program = ntpath.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if not Path(program).is_file() or Path(program).is_symlink():
        raise ACLValidationError("Trusted Windows PowerShell is unavailable")
    return program, root


def _strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))


def _validate_response(response, operation, count):
    keys = {"schema", "operation", "success", "current_user_sid", "records"}
    if (not isinstance(response, dict) or set(response) != keys or response["schema"] != SCHEMA
            or response["operation"] != operation or response["success"] is not True):
        raise ACLValidationError("ACL response schema is invalid")
    current = response["current_user_sid"]
    if (not isinstance(current, str) or len(current) > 128
            or not re.fullmatch(r"S-1-(?:5-21|12-1)-[0-9]+-[0-9]+-[0-9]+-[0-9]+", current)
            or any(int(component) > 4294967295 for component in current.split("-")[4:])):
        raise ACLValidationError("ACL identity response is invalid")
    allowed = {current, SYSTEM_SID, ADMINISTRATORS_SID}
    records = response["records"]
    if not isinstance(records, list) or len(records) != count:
        raise ACLValidationError("ACL record count is invalid")
    record_keys = {"index", "kind", "owner_sid", "dacl_present", "dacl_null", "reparse",
                   "dacl_protected", "allow_sids", "full_control_inheritable_sids", "ace_count", "checked_ancestors"}
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != record_keys:
            raise ACLValidationError("ACL record schema is invalid")
        if (type(record["index"]) is not int or record["index"] != index
                or record["kind"] not in ("file", "directory")
                or record["owner_sid"] not in allowed
                or record["dacl_present"] is not True or record["dacl_null"] is not False
                or record["reparse"] is not False or type(record["dacl_protected"]) is not bool
                or type(record["ace_count"]) is not int or not 0 <= record["ace_count"] <= 256
                or type(record["checked_ancestors"]) is not int or not 1 <= record["checked_ancestors"] <= 2048):
            raise ACLValidationError("ACL record failed boundary validation")
        for field in ("allow_sids", "full_control_inheritable_sids"):
            value = record[field]
            if (not isinstance(value, list) or any(not isinstance(s, str) for s in value)
                    or value != sorted(set(value)) or not set(value).issubset(allowed)):
                raise ACLValidationError("ACL allowed principals are invalid")
        if (not set(record["full_control_inheritable_sids"]).issubset(record["allow_sids"])
                or len(record["allow_sids"]) > record["ace_count"]):
            raise ACLValidationError("ACL response is inconsistent")
        if operation == "protect" and (record["kind"] != "directory" or record["owner_sid"] != current
                or not record["dacl_protected"] or set(record["allow_sids"]) != allowed
                or set(record["full_control_inheritable_sids"]) != allowed
                or record["ace_count"] != len(allowed)):
            raise ACLValidationError("New directory ACL protection was not verified")
    return response


def _invoke(operation, paths):
    checked = _paths(paths)
    program, windows_root = _powershell()
    request = {"operation": operation, "paths": checked}
    encoded = base64.b64encode(json.dumps(request, sort_keys=True, ensure_ascii=True,
                                        separators=(",", ":")).encode("ascii")).decode("ascii")

    script = _SCRIPT.replace("__PAYLOAD_BASE64__", encoded) + "\n"
    environment = dict(os.environ)
    environment["PSModulePath"] = ntpath.join(windows_root, "System32", "WindowsPowerShell", "v1.0", "Modules")
    try:
        completed = subprocess.run([program, "-NoProfile", "-NonInteractive", "-Command", "-"],
                                   input=script, text=True, encoding="ascii", errors="strict",
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                   timeout=60, check=False, env=environment)
        if (completed.returncode != 0 or completed.stderr.strip()
                or len(completed.stdout.encode("ascii")) > MAX_OUTPUT_BYTES):
            raise ACLValidationError("Native ACL operation failed; private input permissions were not changed")
        result = _strict_json(completed.stdout)
        return _validate_response(result, operation, len(checked))
    except ACLValidationError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        raise ACLValidationError("Native ACL verification did not return bounded valid evidence") from exc


def inspect_private_paths(paths):

    return _invoke("inspect", paths)


def protect_new_directory(path):

    return _invoke("protect", [path])
