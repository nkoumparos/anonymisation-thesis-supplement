from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import types

OVERLAY_SCHEMA = "gate-c-compatibility-overlay-v1.2.4/1.0"
TOOL_REVISION = "1.1"
EXPECTED_HEAD = "f479fbabe2422315f98dd0d39ade2f26d92aef04"
EXPECTED_TREE = "82dcf163bf1a1123c2bf2e7bec54ac0a002b1e52"
EXPECTED_TRACKED_PATHS = 138
RUNNER_NAME = "attack_runner"
RUNNER_RELATIVE = "python/" + RUNNER_NAME + ".py"
RUNNER_SHA256 = "59a4e12cf232f8f1e1175c6a8c9c86537b5e37c9473093160504ef86ba5253a2"
GATE_B_RELATIVE = "python/section_12_1_gate_b_v1_2_4.py"
OLD_GATE_B_SHA256 = "ceae0e480bf338d0650629ec1ff40413167ffbcc353f1f2ebef3343aa8ce9c86"
NEW_GATE_B_SHA256 = "8e6fcc86a4b8849037c0ed64041262df6ed6cd1e72a59d56e4a96bf595539f7e"
SOURCE_RELATIVE = "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult.csv"
SOURCE_IDENTITY = (2516935, "c700df9304fbf3c4d4db5938bffc510561bd4a2dfad285a3feef9a20619391c5")
NATIVE_RELATIVE = "data/raw/arx-adult/4e0a5f5340fe9a58c44b34c2f9acd2d68f1dad5f/adult_hierarchy_native-country.csv"
NATIVE_IDENTITY = (840, "696d3b53973311c096b33f98bb56e526016910b1a1cd5a1e904cb799d1077023")
NATIVE_VIEW_IDENTITY = (841, "1a09af0a6ca6d463cba5e193ecdc3f0719e334350f39e91af47dff357a0c3076")
PHYSICAL_SCHEMA = ("sex", "age", "race", "marital-status", "education",
                   "native-country", "workclass", "occupation", "salary-class")
AUTHORIZATION_ID = "AUTH-2026-09-13-GATE_B_F479FBAB"
AUTHORIZATION_SHA256 = "035cb52ad4c3c677f9fac8456442050338fa024f6cd09afe37b3b4d81d5276a6"


MODULE_HASHES = {
    "common": "2c77c6e9822a587fd5fe55ac47e504777e392b79f69e1989006069b840b87967",
    "attack_scorer": "bff7e6b3d8741902d7d53d662bfb4bf4293780f3a71c7a6747f6c55f37a2c930",
    "pre_output_targets": "274ebc302fddb48880eafe7cde6f99cebb53917a36252d64ed23374f7b842509",
    "permutation_control": "f627bba105a3b2300495e420c2d3327ad5c8aed7d42c2319cfa0e7b279a46c60",
    "attack_adapter": "5fd25372768e3c1a48219d68bb2a4eb7c1eb3c40aed15e1057ab86929c68f8a4",
    "risk_metrics": "4b942d98e8330dc74193c8fea948f0372ca6312be05f31e7a489c1f38ef900dd",
    "risk_consumer": "b056498ca251a68049b2db47055ec3d406962945c6a0f44034b34568aabf868d",
    "attack_results_collector": "be60d6a35149757a3574c4b6e6fa893386ab7377c31e3bfab395ce2fcc6aee63",
    "anonymization_checks": NEW_GATE_B_SHA256,
    RUNNER_NAME: RUNNER_SHA256,
}
DEPENDENCY_HASHES_AFTER = {
    "configurations.csv": "ae28a3ac91dd733c5561a6f4d887c48d4b792915531d72a5e2158bc0bce72d2e",
    "manifest/protocol_effective_v1_2_4.txt": "77ef91e9691eef8f271598b357f27f14650b52ea0f9bb6ebe5c1f4a0e4fd78e5",
    **{"python/" + name + ".py": MODULE_HASHES[name] for name in (
        "common", "pre_output_targets",
        "anonymization_checks", "attack_scorer",
        "permutation_control", "attack_adapter",
        "attack_results_collector",
    )},
}


class OverlayError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise OverlayError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def identity(data):
    return {"bytes": len(data), "sha256": sha256(data)}


def git(repository, *arguments):
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments), cwd=repository,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"),
    )
    require(result.returncode == 0,
            "Git read-only check failed: " + result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def safe_file(repository, relative):
    root = Path(repository).resolve(strict=True)
    relative = Path(relative)
    require(not relative.is_absolute() and ".." not in relative.parts,
            "Unsafe relative file path")
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink() and not current.is_junction(),
                "Symbolic links/junctions are not allowed: " + str(current))
    require(current.is_file() and current.resolve(strict=True).is_relative_to(root),
            "Missing or unsafe file: " + str(relative))
    return current


def check_repository(repository):
    repository = Path(repository).resolve(strict=True)
    top = Path(git(repository, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(strict=True)
    require(top == repository, "Repository argument must be the worktree root")
    require(git(repository, "rev-parse", "HEAD").decode("ascii").strip() == EXPECTED_HEAD,
            "Overlay is bound to a different HEAD")
    require(git(repository, "rev-parse", "HEAD^{tree}").decode("ascii").strip() == EXPECTED_TREE,
            "Overlay is bound to a different tree")
    require(git(repository, "status", "--porcelain=v1", "--untracked-files=all") == b"",
            "Repository must be clean; nothing will be staged or reverted")
    tracked = git(repository, "ls-tree", "-r", "--name-only", "-z", "HEAD")
    require(len([x for x in tracked.split(b"\0") if x]) == EXPECTED_TRACKED_PATHS,
            "HEAD tracked-path count mismatch")
    require(git(repository, "ls-files", "--unmerged", "-z") == b"",
            "Unmerged index entries are not allowed")
    expected = dict(DEPENDENCY_HASHES_AFTER)
    expected.update({"python/" + name + ".py": digest for name, digest in MODULE_HASHES.items()})
    payloads = {}
    for relative, digest in expected.items():
        data = safe_file(repository, relative).read_bytes()
        require(sha256(data) == digest, "Source identity mismatch: " + relative)
        require(data == git(repository, "show", "HEAD:" + relative),
                "Working and committed bytes differ: " + relative)
        payloads[relative] = data
    return repository, payloads


def _load_verified_modules(repository, payloads):
    require(not any(name in sys.modules for name in MODULE_HASHES),
            "Use a fresh isolated process; reviewed modules are already loaded")
    loaded = {}
    for name, digest in MODULE_HASHES.items():
        relative = "python/" + name + ".py"
        data = payloads[relative]
        require(sha256(data) == digest, "Verified source buffer changed: " + relative)
        module = types.ModuleType(name)
        module.__file__ = str(repository / relative)
        module.__package__ = ""
        module.__spec__ = importlib.util.spec_from_loader(name, loader=None, origin=module.__file__)
        sys.modules[name] = module


        exec(compile(data, module.__file__, "exec", dont_inherit=True), module.__dict__)
        loaded[name] = module
    return loaded


def _make_source_reader(repository, original_reader, frozen_reader):
    source_path = repository / SOURCE_RELATIVE

    def read_table(path, delimiter, expected_schema, name, *, identity=None):

        resolved = Path(path).resolve(strict=True)
        if resolved != source_path:
            return original_reader(path, delimiter, expected_schema, name, identity=identity)
        require(Path(path).absolute() == source_path,
                "Frozen source must use its canonical repository path")
        canonical = safe_file(repository, SOURCE_RELATIVE)
        require(delimiter == ";" and tuple(expected_schema) == PHYSICAL_SCHEMA
                and name == "Adult training input" and identity == SOURCE_IDENTITY,
                "Frozen-source invocation differs from the exact runner contract")


        return frozen_reader(canonical, delimiter, expected_schema)

    return read_table


class _HierarchyMemoryView:

    __slots__ = ("_data",)

    def __init__(self, data):
        self._data = data

    def read_bytes(self):
        return self._data


def _make_hierarchy_reader(repository, original_reader):
    source_path = repository / NATIVE_RELATIVE

    def read_hierarchy(path, attribute, expected_bytes, expected_hash, width):
        resolved = Path(path).resolve(strict=True)
        if resolved != source_path:
            return original_reader(path, attribute, expected_bytes, expected_hash, width)
        require(Path(path).absolute() == source_path,
                "Native-country hierarchy must use its canonical repository path")
        require(attribute == "native-country"
                and type(expected_bytes) is int and type(width) is int and width == 3
                and (expected_bytes, expected_hash) == NATIVE_IDENTITY,
                "Native-country invocation differs from the exact runner contract")
        data = safe_file(repository, NATIVE_RELATIVE).read_bytes()
        require((len(data), sha256(data)) == NATIVE_IDENTITY,
                "Native-country hierarchy differs from the original 840-byte identity")
        require(not data.endswith(b"\n"),
                "Native-country adaptation requires absence of the terminal LF")
        view_data = data + b"\n"
        require((len(view_data), sha256(view_data)) == NATIVE_VIEW_IDENTITY,
                "Native-country in-memory view differs from the approved identity")


        return original_reader(_HierarchyMemoryView(view_data), attribute,
                               NATIVE_VIEW_IDENTITY[0], NATIVE_VIEW_IDENTITY[1], width)

    return read_hierarchy


def verify_delta(runner, before, dependency_before, replacement, hierarchy_replacement):
    require(set(vars(runner)) == set(before), "Unexpected runner global added/removed")
    for name, value in before.items():
        if name not in {"_read_table", "_read_hierarchy"}:
            require(vars(runner)[name] is value, "Unexpected runner global replacement: " + name)
    require(runner._read_table is replacement, "Source-reader replacement mismatch")
    require(runner._read_hierarchy is hierarchy_replacement, "Hierarchy-reader replacement mismatch")
    expected_before = dict(DEPENDENCY_HASHES_AFTER)
    expected_before[GATE_B_RELATIVE] = OLD_GATE_B_SHA256
    require(dependency_before == expected_before, "Unexpected original dependency table")
    require(runner.DEPENDENCY_HASHES == DEPENDENCY_HASHES_AFTER,
            "Unexpected adapted dependency table")
    changed = [key for key in dependency_before
               if dependency_before[key] != runner.DEPENDENCY_HASHES[key]]
    require(changed == [GATE_B_RELATIVE], "Only one dependency identity may change")


def install(repository):

    require(sys.flags.isolated == 1 and sys.dont_write_bytecode,
            "Load the overlay with Python flags -I -B")
    repository, payloads = check_repository(repository)
    loaded = _load_verified_modules(repository, payloads)
    runner = loaded[RUNNER_NAME]
    gate_b = loaded["anonymization_checks"]
    expected_before = dict(DEPENDENCY_HASHES_AFTER)
    expected_before[GATE_B_RELATIVE] = OLD_GATE_B_SHA256
    require(runner.DEPENDENCY_HASHES == expected_before,
            "Runner dependency table is not the exact approved original")
    require((gate_b.EXPECTED_SOURCE_BYTES, gate_b.EXPECTED_SOURCE_SHA256) == SOURCE_IDENTITY
            and gate_b.PHYSICAL_SCHEMA == PHYSICAL_SCHEMA
            and runner.SOURCE_RELATIVE == SOURCE_RELATIVE
            and (runner.EXPECTED_SOURCE_BYTES, runner.SOURCE_INPUT_SHA256) == SOURCE_IDENTITY,
            "Frozen source contracts disagree")
    require(runner.HIERARCHY_SPECS.get("native-country")
            == (NATIVE_RELATIVE, NATIVE_IDENTITY[0], NATIVE_IDENTITY[1], 3),
            "Original native-country hierarchy contract differs")
    before = dict(vars(runner))
    dependency_before = dict(runner.DEPENDENCY_HASHES)
    replacement = _make_source_reader(repository, runner._read_table,
                                      gate_b._read_frozen_source_table)
    hierarchy_replacement = _make_hierarchy_reader(repository, runner._read_hierarchy)
    runner.DEPENDENCY_HASHES[GATE_B_RELATIVE] = NEW_GATE_B_SHA256
    runner._read_table = replacement
    runner._read_hierarchy = hierarchy_replacement
    verify_delta(runner, before, dependency_before, replacement, hierarchy_replacement)
    evidence = {
        "record_schema": OVERLAY_SCHEMA,
        "revision": TOOL_REVISION,
        "repository_head": EXPECTED_HEAD,
        "repository_tree": EXPECTED_TREE,
        "runner_sha256": RUNNER_SHA256,
        "source_identities": {path: identity(data) for path, data in payloads.items()},
        "changes": [
            {"target": "DEPENDENCY_HASHES[" + GATE_B_RELATIVE + "]",
             "before": OLD_GATE_B_SHA256, "after": NEW_GATE_B_SHA256},
            {"target": "_read_table", "scope": SOURCE_RELATIVE,
             "delegate": "anonymization_checks._read_frozen_source_table",
             "source_bytes": SOURCE_IDENTITY[0], "source_sha256": SOURCE_IDENTITY[1],
             "other_table_reads": "ORIGINAL_READER_UNCHANGED"},
            {"target": "_read_hierarchy", "scope": NATIVE_RELATIVE,
             "delegate": "ORIGINAL_GATE_C_HIERARCHY_READER",
             "original_bytes": NATIVE_IDENTITY[0], "original_sha256": NATIVE_IDENTITY[1],
             "requires_absent_terminal_lf": True,
             "memory_only_operation": "APPEND_EXACTLY_ONE_LF",
             "view_bytes": NATIVE_VIEW_IDENTITY[0], "view_sha256": NATIVE_VIEW_IDENTITY[1],
             "other_hierarchy_reads": "ORIGINAL_READER_UNCHANGED"},
        ],
        "runner_global_delta_verified": True,
        "repository_files_modified": False,
        "scientific_functions_replaced": False,
        "execution_authorization_granted": False,
    }
    return runner, evidence


if __name__ == "__main__":
    print("RESULT=STOP")
    print("ERROR=This overlay is not an execution launcher. Use the preflight only.")
    raise SystemExit(2)
