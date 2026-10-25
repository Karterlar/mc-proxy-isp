#!/usr/bin/env python3
"""Prepare the pinned public Chromium tree; never compile, package or activate it.

The default invocation only reads. --prepare requires the manifest digest pinned
in build-windows.ps1. A failed mutating stage is deliberately not auto-replayed:
its journal and source remain available for inspection without a destructive reset.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
from datetime import datetime, timezone

HERE = Path(__file__).absolute().parent
PROJECT = HERE.parents[2]
CHROMIUM = "0fcdce5f4fdec8d442d7df760cb541f1ca6e446d"
VERSION = "150.0.7871.186"
SOURCE_ARCHIVE_REGULAR_MAX_BYTES = 9613834240
WINDOWS_RECIPE = "da7182041a5101844ec2e9444bfead1dd3ebc70f"
UG_RECIPE = "fd0378e4f20fa09e21b09beca71573d435d787cf"
STATE_NAME = ".mc-native-prepare.json"
RECEIPT_NAME = ".mc-native-source.json"


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    hasher = hashlib.sha256()
    with io_path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def ordinary(path):
    """Check lexical parents before resolving; reject Windows junctions as well."""
    path = Path(os.path.abspath(path))
    for candidate in (path, *path.parents):
        try:
            info = io_path(candidate).lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("LINK_OR_JUNCTION_REFUSED: " + str(candidate))
    return path


def relative(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.+/-]+", value):
        raise ValueError("RELATIVE_PATH_INVALID: " + str(value))
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("RELATIVE_PATH_INVALID: " + value)
    return path


def scoped(root, value):
    path = ordinary(root.joinpath(*relative(value).parts))
    if not path.is_relative_to(root):
        raise ValueError("PATH_OUTSIDE_OWNED_ROOT")
    return path


def archive_scoped(root, value):
    # Source archives include real Unicode, spaces, parentheses and @ names.
    # These are literal file I/O paths, not manifest-selected command arguments.
    if (not isinstance(value, str) or not value
            or re.search(r'[\x00-\x1f\x7f<>:"\\|?*]', value)):
        raise ValueError("ARCHIVE_PATH_INVALID")
    relative_path = PurePosixPath(value)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("ARCHIVE_PATH_OUTSIDE_SOURCE")
    path = ordinary(root.joinpath(*relative_path.parts))
    if path != root and not path.is_relative_to(root):
        raise ValueError("ARCHIVE_PATH_OUTSIDE_SOURCE")
    return path


def build_root(path, project=PROJECT):
    path, project = ordinary(path), ordinary(project)
    if path == Path(path.anchor) or path == project or path in project.parents:
        raise ValueError("BUILD_ROOT_PROTECTED")
    for protected in ("backend/runtime", "deliverables", ".git", ".agents", ".codex"):
        target = project.joinpath(*protected.split("/"))
        if path == target or path.is_relative_to(target):
            raise ValueError("BUILD_ROOT_PROTECTED")
    if any(part.lower() == "browser-profiles" or part.lower().startswith("fingerprint-browser")
           for part in path.parts):
        raise ValueError("BUILD_ROOT_PROTECTED")
    if os.name == "nt" and (not re.match(r"^[A-Za-z]:[\\/]", str(path)) or str(path).startswith("\\\\")):
        raise ValueError("BUILD_ROOT_MUST_BE_LOCAL")
    if re.search(r'[\x00-\x1f\x7f"%!?&|<>^]', str(path)) or not str(path).isascii() or " " in str(path):
        raise ValueError("BUILD_ROOT_COMMAND_UNSAFE")
    return path


def read_json(path):
    ordinary(path)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save_json(path, value):
    ordinary(path)
    temporary = ordinary(path.with_name(path.name + ".tmp"))
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def reviewed_manifest(here=HERE, requested_hash=None):
    runner = (here / "build-windows.ps1").read_text(encoding="utf-8-sig")
    pin = re.search(r"\$ExpectedManifestSha256\s*=\s*'([a-f0-9]{64})'", runner)
    if not pin:
        raise ValueError("SOURCE_MANIFEST_NOT_REVIEWED")
    path = ordinary(here / "source-manifest.json")
    actual = digest(path)
    if actual != pin[1] or requested_hash is not None and requested_hash != pin[1]:
        raise ValueError("SOURCE_MANIFEST_NOT_REVIEWED_OR_CHANGED")
    manifest = read_json(path)
    if (manifest.get("schemaVersion") != 1 or manifest.get("chromium", {}).get("revision") != CHROMIUM
            or manifest["chromium"].get("version") != VERSION
            or manifest.get("build", {}).get("target") != "chrome"
            or manifest["build"].get("ready") is not True
            or manifest.get("recipe", {}).get("windowsRevision") != WINDOWS_RECIPE
            or manifest["recipe"].get("ungoogledRevision") != UG_RECIPE):
        raise ValueError("SOURCE_MANIFEST_CONTRACT_INVALID")
    archive = manifest["chromium"].get("archive", {})
    if (archive.get("filename") != "chromium-" + VERSION + "-lite.tar.xz"
            or not isinstance(archive.get("bytes"), int) or archive["bytes"] < 1
            or not re.fullmatch(r"[a-f0-9]{64}", archive.get("sha256", ""))):
        raise ValueError("SOURCE_ARCHIVE_CONTRACT_INVALID")
    patches = manifest.get("patches", [])
    if not patches or len({patch["path"] for patch in patches}) != len(patches):
        raise ValueError("CUSTOM_PATCH_SET_INVALID")
    for patch in patches:
        path = scoped(here, patch["path"])
        if path.suffix != ".patch" or digest(path) != patch.get("sha256"):
            raise ValueError("SOURCE_PATCH_CHANGED: " + patch["path"])
    return manifest, actual


def verify_recipe(recipe):
    for root, expected in ((recipe, WINDOWS_RECIPE), (recipe / "ungoogled-chromium", UG_RECIPE)):
        ordinary(root)
        head = subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], text=True)
        if head != expected or dirty:
            raise ValueError("RECIPE_REVISION_OR_WORKTREE_CHANGED: " + str(root))


def verify_archive(root, archive):
    path = scoped(root / "downloads", archive["filename"])
    if path.stat().st_size != archive["bytes"] or digest(path) != archive["sha256"]:
        raise ValueError("CHROMIUM_ARCHIVE_CHANGED")
    return path


def load_state(root, manifest_hash, project=PROJECT, restart_extraction=False):
    path = root / STATE_NAME
    if path.exists():
        state = read_json(path)
        if (state.get("schemaVersion") != 1 or state.get("buildRoot") != str(root)
                or state.get("projectRoot") != str(project)
                or state.get("sourceManifestSha256") != manifest_hash):
            raise ValueError("PREPARATION_OWNERSHIP_MISMATCH")
        if state.get("recoveryPending"):
            raise ValueError("EXTRACTION_RECOVERY_INTERRUPTED")
        restarting = (restart_extraction and state.get("activeStage") == "extract-source"
                      and state.get("completedStages") == ["download-dependencies"] and state.get("failure"))
        if restart_extraction and not restarting:
            raise ValueError("EXTRACTION_RESTART_SCOPE_INVALID")
        if state.get("activeStage") and state["activeStage"] != "download-dependencies" and not restarting:
            raise ValueError("INTERRUPTED_MUTATION_REFUSED: " + state["activeStage"])
        return state
    allowed = {"bootstrap", "downloads", "msvc", "vs", "recipe", "standalone", "tools",
               "sdk-layout", "sdk-debug", "sdk-overlay", "sdk-debug-extract.log", "dependency-download.log",
               ".mc-native-prepare.lock"}
    if root.exists() and any(entry.name not in allowed for entry in root.iterdir()):
        raise ValueError("FOREIGN_BUILD_ROOT_REFUSED")
    if root != project / ".cache" / "native-engine-build" and root.exists() and any(root.iterdir()):
        raise ValueError("FOREIGN_BUILD_ROOT_REFUSED")
    return {"schemaVersion": 1, "buildRoot": str(root), "projectRoot": str(project),
            "sourceManifestSha256": manifest_hash, "createdAt": now(), "completedStages": [],
            "activeStage": None, "preparedFiles": [], "removedFiles": []}


def io_path(path):
    """Use native extended paths for source extraction, without registry changes."""
    text = os.path.abspath(path)
    if os.name == "nt" and not text.startswith("\\\\?\\"):
        if not re.match(r"^[A-Za-z]:[\\/]", text):
            raise ValueError("EXTENDED_PATH_REQUIRES_LOCAL_VOLUME")
        return Path("\\\\?\\" + text)
    return Path(text)


def source_tree_size(source):
    total, files, longest = 0, 0, 0
    for parent, directories, names in os.walk(io_path(source), followlinks=False):
        for name in (*directories, *names):
            entry = Path(parent) / name
            ordinary(entry)
            info = entry.lstat()
            longest = max(longest, len(str(entry).removeprefix("\\\\?\\")))
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
                files += 1
    return {"bytes": total, "files": files, "longestAbsolutePath": longest}


def check_capacity(root, state):
    if "extract-source" in state["completedStages"]:
        return
    free = shutil.disk_usage(root).free
    reserved = sum(item["preservedSource"]["bytes"] for item in state.get("recoveries", []))
    if reserved:
        # The first full-source guard already reserved room for the interrupted
        # extraction. Preserve that accounting, while still reserving a whole
        # redo, conservative dependency expansion and 30 GB for release output.
        minimum = max(60000000000, state["recoveries"][-1]["preservedSource"]["bytes"] * 2 + 30000000000)
        if free < minimum or free + reserved < 100000000000:
            raise ValueError("EXTRACTION_RECOVERY_CAPACITY_INSUFFICIENT")
    elif free < 100000000000:
        raise ValueError("FRESH_SOURCE_REQUIRES_100_GB_FREE")


def restart_source_extraction(root, state):
    if (state.get("activeStage") != "extract-source" or state.get("completedStages") != ["download-dependencies"]
            or not state.get("failure") or state.get("recoveryPending") or (root / RECEIPT_NAME).exists()):
        raise ValueError("EXTRACTION_RESTART_SCOPE_INVALID")
    source = ordinary(root / "src")
    wrapper = ordinary(source / ("chromium-" + VERSION))
    if not source.is_dir() or sorted(item.name for item in source.iterdir()) != [wrapper.name] or not wrapper.is_dir():
        raise ValueError("EXTRACTION_RESTART_FOREIGN_SOURCE")
    version = wrapper / "chrome" / "VERSION"
    values = dict(line.split("=", 1) for line in version.read_text(encoding="utf-8").splitlines() if "=" in line)
    if ".".join(values.get(key, "") for key in ("MAJOR", "MINOR", "BUILD", "PATCH")) != VERSION:
        raise ValueError("EXTRACTION_RESTART_FOREIGN_SOURCE")
    record = {"backup": "source-backups/extract-source-" + uuid.uuid4().hex, "startedAt": now(),
              "failure": state["failure"], "preservedSource": source_tree_size(source)}
    if not record["preservedSource"]["files"] or record["preservedSource"]["bytes"] > SOURCE_ARCHIVE_REGULAR_MAX_BYTES:
        raise ValueError("EXTRACTION_RESTART_FOREIGN_SOURCE_SIZE")
    destination = scoped(root, record["backup"])
    if destination.exists():
        raise ValueError("EXTRACTION_RECOVERY_BACKUP_EXISTS")
    prospective = dict(state, recoveries=[*state.get("recoveries", []), record])
    check_capacity(root, prospective)
    state["recoveryPending"] = record
    save_json(root / STATE_NAME, state)
    destination.parent.mkdir(parents=True, exist_ok=True)
    io_path(source).rename(io_path(destination))
    record["completedAt"] = now()
    state.setdefault("failureHistory", []).append({"stage": "extract-source", **state["failure"]})
    state.setdefault("recoveries", []).append(record)
    state.update(activeStage=None, failure=None)
    state.pop("recoveryPending")
    save_json(root / STATE_NAME, state)


def materialize_tar_links(archive, output, leading):
    """Copy only safe internal file targets; report directories/cycles explicitly."""
    prefix = PurePosixPath(leading) if leading else None
    links = []

    class DiscardMembers(list):
        def append(self, value):
            pass

    def source_name(value):
        path = PurePosixPath(posixpath.normpath(value))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("TAR_LINK_ESCAPES_SOURCE")
        if prefix:
            try:
                path = path.relative_to(prefix)
            except ValueError as exc:
                raise ValueError("TAR_LINK_ESCAPES_SOURCE") from exc
        # Validate with the archive boundary, which permits literal filename
        # characters that are intentionally forbidden in patch/manifest paths.
        archive_scoped(output, str(path))
        return str(path)

    with tarfile.open(str(archive), "r|*") as stream:
        stream.members = DiscardMembers()
        for member in stream:
            if member.issym() or member.islnk():
                name = source_name(member.name)
                target = source_name(posixpath.join(posixpath.dirname(member.name), member.linkname)
                                     if member.issym() else member.linkname)
                links.append({"path": name, "target": target, "kind": "symlink" if member.issym() else "hardlink"})
    pending, results = list(links), []
    while pending:
        remaining = []
        for link in pending:
            target = io_path(archive_scoped(output, link["target"]))
            destination = io_path(archive_scoped(output, link["path"]))
            if target.is_file():
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    shutil.copy2(target, destination)
                elif not destination.is_file() or digest(destination) != digest(target):
                    raise ValueError("TAR_LINK_DESTINATION_CONFLICT: " + link["path"])
                results.append({**link, "status": "materialized-file"})
            elif target.is_dir():
                results.append({**link, "status": "skipped-directory"})
            else:
                remaining.append(link)
        if len(remaining) == len(pending):
            results.extend({**link, "status": "skipped-missing-or-cycle"} for link in remaining)
            break
        pending = remaining
    return results


def extract_tar_regular_files(archive, output, leading):
    """Stream regular files only; never probe for or create Windows symlinks.

    The pinned utility's empty-path symlink probe gives a false positive on this
    non-admin host, and its private tarfile API cannot resolve streaming links
    with Python 3.12. Public stdlib reads plus explicit internal copies avoid both.
    """
    prefix = PurePosixPath(leading) if leading else None

    class DiscardMembers(list):
        def append(self, value):
            pass

    with tarfile.open(str(archive), "r|*") as stream:
        stream.members = DiscardMembers()
        for member in stream:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError("TAR_MEMBER_ESCAPES_SOURCE")
            if prefix:
                try:
                    name = name.relative_to(prefix)
                except ValueError as exc:
                    raise ValueError("TAR_MEMBER_ESCAPES_SOURCE") from exc
            if str(name) == "." and member.isdir():
                continue
            destination = io_path(archive_scoped(output, str(name)))
            if member.issym() or member.islnk():
                continue
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() and not destination.is_file():
                    raise ValueError("TAR_MEMBER_TARGET_NOT_FILE")
                with stream.extractfile(member) as source, destination.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                os.utime(destination, (member.mtime, member.mtime))
            else:
                raise ValueError("TAR_SPECIAL_MEMBER_REFUSED: " + member.name)


def unpack_component(downloads, common, info, name, properties, cache, output, seven_zip):
    is_tar = (properties.extractor or common.ExtractorEnum.TAR) == common.ExtractorEnum.TAR
    extractors = {common.ExtractorEnum.SEVENZIP: None if is_tar else str(seven_zip),
                  common.ExtractorEnum.WINRAR: None}
    # TAR uses public stdlib APIs, without a symlink privilege probe. Keep the
    # pinned upstream extractor for ZIP and NSIS executable toolchain archives.
    if is_tar:
        archive = scoped(cache, properties.download_filename)
        destination = scoped(output, properties.output_path) if properties.output_path not in (".", "./") else output
        extract_tar_regular_files(archive, destination, properties.strip_leading_dirs)
        return materialize_tar_links(archive, destination, properties.strip_leading_dirs)
    downloads.unpack_downloads(info, cache, [name], io_path(output), extractors)
    return []


def verify_prepared_files(root, state):
    for item in state.get("preparedFiles", []):
        if digest(archive_scoped(root / "src", item["path"])) != item["sha256"]:
            raise ValueError("PREPARED_SOURCE_CHANGED: " + item["path"])
    for name in state.get("removedFiles", []):
        if io_path(archive_scoped(root / "src", name)).exists():
            raise ValueError("REMOVED_SOURCE_REAPPEARED: " + name)


def remember_files(root, state, names):
    names = set(names) | {item["path"] for item in state["preparedFiles"]} | set(state["removedFiles"])
    present, absent = [], []
    for name in sorted(names):
        path = io_path(archive_scoped(root / "src", name))
        if path.is_file():
            present.append({"path": name, "sha256": digest(path)})
        elif not path.exists():
            absent.append(name)
        else:
            raise ValueError("PATCH_TARGET_IS_NOT_FILE: " + name)
    state["preparedFiles"], state["removedFiles"] = present, absent


def run_stage(root, state, name, operation):
    if name in state["completedStages"]:
        return
    state.update(activeStage=name, stageStartedAt=now())
    state.pop("failure", None)
    save_json(root / STATE_NAME, state)
    print(json.dumps({"stage": name, "status": "started", "at": now()}), flush=True)
    try:
        operation()
    except BaseException as exc:
        state["failure"] = {"at": now(), "type": type(exc).__name__, "message": str(exc)}
        save_json(root / STATE_NAME, state)
        raise
    state["completedStages"].append(name)
    state.update(activeStage=None, stageCompletedAt=now())
    save_json(root / STATE_NAME, state)
    print(json.dumps({"stage": name, "status": "completed", "at": now()}), flush=True)


def patch_targets(patch):
    names = set()
    for line in patch.read_text(encoding="utf-8").splitlines():
        if line.startswith(("--- ", "+++ ")):
            name = line[4:].split("\t")[0].split(" ")[0]
            if name == "/dev/null":
                continue
            if not name.startswith(("a/", "b/")):
                raise ValueError("PATCH_TARGET_PATH_INVALID: " + name)
            names.add(str(relative(name[2:])))
    if not names:
        raise ValueError("PATCH_HAS_NO_TARGETS: " + str(patch))
    return names


def preserve_directory(root, relative_name):
    source = scoped(root / "src", relative_name)
    backup = scoped(root / "source-backups", relative_name)
    if backup.exists():
        raise ValueError("SOURCE_BACKUP_ALREADY_EXISTS")
    if source.exists():
        if not source.is_dir():
            raise ValueError("SOURCE_REPLACEMENT_NOT_DIRECTORY")
        backup.parent.mkdir(parents=True, exist_ok=True)
        source.rename(backup)
    source.mkdir(parents=True, exist_ok=True)


def _prepare(root, manifest, manifest_hash, seven_zip, here=HERE, project=PROJECT):
    root = build_root(root, project)
    checked_manifest, checked_hash = reviewed_manifest(here)
    if checked_hash != manifest_hash or checked_manifest != manifest:
        raise ValueError("SOURCE_MANIFEST_CHANGED_BEFORE_PREPARATION")
    recipe = ordinary(root / "recipe")
    verify_recipe(recipe)
    verify_archive(root, manifest["chromium"]["archive"])
    seven_zip = ordinary(seven_zip)
    if not seven_zip.is_file():
        raise ValueError("SEVEN_ZIP_NOT_FOUND")
    subprocess.run([str(seven_zip), "i"], check=True, stdout=subprocess.DEVNULL)
    state = load_state(root, manifest_hash, project)
    verify_prepared_files(root, state)
    check_capacity(root, state)
    root.mkdir(parents=True, exist_ok=True)
    (root / "downloads").mkdir(exist_ok=True)
    save_json(root / STATE_NAME, state)
    # -B keeps both pinned recipe working trees clean for the next invocation.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(recipe / "ungoogled-chromium" / "utils"))
    downloads, patches, pruning, domains, common = [importlib.import_module(name) for name in
        ("downloads", "patches", "prune_binaries", "domain_substitution", "_common")]
    source, cache = root / "src", root / "downloads"
    ug = recipe / "ungoogled-chromium"
    chromium_download = downloads.DownloadInfo([ug / "downloads.ini"])
    dependencies = downloads.DownloadInfo([recipe / "downloads.ini"])
    extras = {item["name"]: item["sha256"] for item in manifest.get("dependencyHashes", [])}
    for name, properties in dependencies.properties_iter():
        relative(properties.download_filename)
        relative(properties.output_path)
        if properties.strip_leading_dirs:
            relative(properties.strip_leading_dirs)
        if not properties.url.startswith("https://"):
            raise ValueError("DEPENDENCY_REQUIRES_HTTPS: " + name)
        if not properties.hashes and not re.fullmatch(r"[a-f0-9]{64}", extras.get(name, "")):
            raise ValueError("DEPENDENCY_HASH_MISSING: " + name)

    def fetch_dependencies():
        for _, properties in dependencies.properties_iter():
            ordinary(cache / properties.download_filename)
            ordinary(cache / (properties.download_filename + ".partial"))
        downloads.retrieve_downloads(dependencies, cache, None, True, False)
        downloads.check_downloads(dependencies, cache, None)
        actual = []
        for name, properties in dependencies.properties_iter():
            hashed = digest(scoped(cache, properties.download_filename))
            if name in extras and hashed != extras[name]:
                raise ValueError("DEPENDENCY_EXTRA_HASH_MISMATCH: " + name)
            actual.append({"name": name, "filename": properties.download_filename, "sha256": hashed})
        state["dependenciesVerified"] = actual

    run_stage(root, state, "download-dependencies", fetch_dependencies)
    for item in state["dependenciesVerified"]:
        if digest(scoped(cache, item["filename"])) != item["sha256"]:
            raise ValueError("CACHED_DEPENDENCY_CHANGED: " + item["name"])

    def extract_source():
        if source.exists():
            raise ValueError("SOURCE_ALREADY_EXISTS_WITHOUT_COMPLETED_EXTRACTION")
        source.mkdir()
        for name, properties in chromium_download.properties_iter():
            state.setdefault("tarLinks", {})[name] = unpack_component(
                downloads, common, chromium_download, name, properties, cache, source, seven_zip)
        state["sourceExtraction"] = {"method": "stdlib-streaming-files-and-safe-internal-file-copies",
                                     **source_tree_size(source)}
        version = (source / "chrome" / "VERSION").read_text(encoding="utf-8")
        values = dict(line.split("=", 1) for line in version.splitlines() if "=" in line)
        if ".".join(values[key] for key in ("MAJOR", "MINOR", "BUILD", "PATCH")) != VERSION:
            raise ValueError("EXTRACTED_CHROMIUM_VERSION_MISMATCH")

    run_stage(root, state, "extract-source", extract_source)

    def prune_source():
        names = list(filter(None, (ug / "pruning.list").read_text(encoding="utf-8").splitlines()))
        for name in names:
            archive_scoped(source, name)
        missing = pruning.prune_files(io_path(source), names)
        if missing:
            raise ValueError("PRUNING_TARGETS_MISSING: " + str(sorted(map(str, missing))[:12]))
        remember_files(root, state, names)

    run_stage(root, state, "prune-source", prune_source)

    def extract_dependencies():
        for name in ("third_party/microsoft_dxheaders/src", "third_party/devtools-frontend/src/third_party/esbuild"):
            preserve_directory(root, name)
        for _, properties in dependencies.properties_iter():
            scoped(source, properties.output_path).mkdir(parents=True, exist_ok=True)
        for name, properties in dependencies.properties_iter():
            state.setdefault("tarLinks", {})[name] = unpack_component(
                downloads, common, dependencies, name, properties, cache, source, seven_zip)
        # Toolchain archives intentionally replace some files removed by pruning.
        remember_files(root, state, [])

    run_stage(root, state, "extract-dependencies", extract_dependencies)
    patch_binary = scoped(source, "third_party/git/usr/bin/patch.exe")
    groups = [("patch-ungoogled", list(patches.generate_patches_from_series(ug / "patches", resolve=True))),
              ("patch-windows", list(patches.generate_patches_from_series(recipe / "patches", resolve=True))),
              ("patch-custom", [scoped(here, item["path"]) for item in manifest["patches"]])]
    order = []
    for name, files in groups:
        for file in files:
            ordinary(file)
            order.append({"stage": name, "path": str(file.relative_to(here)) if file.is_relative_to(here)
                          else str(file.relative_to(recipe)), "sha256": digest(file)})

        def apply_group(files=files):
            if reviewed_manifest(here)[1] != manifest_hash:
                raise ValueError("SOURCE_MANIFEST_CHANGED_DURING_PREPARATION")
            targets = set().union(*(patch_targets(file) for file in files))
            for target in targets:
                scoped(source, target)
            # Batch mode must fail instead of prompting, reversing or applying
            # fuzzy context to a different source revision. Offsets remain valid.
            for file in files:
                subprocess.run([str(patch_binary), "-p1", "--batch", "--forward", "--fuzz=0",
                                "--ignore-whitespace", "--no-backup-if-mismatch", "-i", str(file),
                                "-d", str(source)], check=True)
            remember_files(root, state, targets)

        run_stage(root, state, name, apply_group)

    def substitute_domains():
        names = list(filter(None, (ug / "domain_substitution.list").read_text(encoding="utf-8").splitlines()))
        before = {name: digest(archive_scoped(source, name)) for name in names if io_path(archive_scoped(source, name)).is_file()}
        domains.apply_substitution(ug / "domain_regex.list", ug / "domain_substitution.list", io_path(source), None)
        changed = [name for name, value in before.items() if digest(archive_scoped(source, name)) != value]
        remember_files(root, state, changed)

    run_stage(root, state, "substitute-domains", substitute_domains)

    def merge_rust():
        destination = scoped(source, "third_party/rust-toolchain")
        if destination.exists():
            raise ValueError("RUST_MERGE_DESTINATION_ALREADY_EXISTS")
        destination.mkdir()
        for architecture in ("x64", "x86", "arm"):
            base = scoped(source, "third_party/rust-toolchain-" + architecture)
            for directory in ("bin", "lib"):
                if directory == "bin" and architecture != "x64":
                    continue
                target = destination / directory
                target.mkdir(exist_ok=True)
                for origin in base.glob("*/" + directory + "/*"):
                    ordinary(origin)
                    output = ordinary(target / origin.name)
                    if origin.is_dir():
                        for parent, directories, files in os.walk(origin, followlinks=False):
                            for child in (*directories, *files):
                                ordinary(Path(parent) / child)
                        shutil.copytree(origin, output, dirs_exist_ok=True, symlinks=False)
                    else:
                        shutil.copy2(origin, output)
        rust = scoped(source, "third_party/rust-toolchain/bin/rustc.exe")
        version = subprocess.check_output([str(rust), "--version"], text=True)
        (destination / "INSTALLED_VERSION").write_text(version, encoding="utf-8")
        remember_files(root, state, ["third_party/rust-toolchain/INSTALLED_VERSION"])

    run_stage(root, state, "merge-rust", merge_rust)
    for name in ("BUILD.gn", ".gn", "chrome/VERSION", "tools/gn/bootstrap/bootstrap.py",
                 "third_party/ninja/ninja.exe", "third_party/node/win/node.exe",
                 "third_party/git/usr/bin/patch.exe",
                 "third_party/llvm-build/Release+Asserts/bin/clang-cl.exe",
                 "third_party/rust-toolchain/bin/rustc.exe"):
        if not scoped(source, name).is_file():
            raise ValueError("PREPARED_SOURCE_INCOMPLETE: " + name)
    verify_recipe(recipe)
    if reviewed_manifest(here)[1] != manifest_hash:
        raise ValueError("SOURCE_MANIFEST_CHANGED_DURING_PREPARATION")
    verify_prepared_files(root, state)
    receipt = {"schemaVersion": 1, "sourceManifestSha256": manifest_hash, "headChromium": CHROMIUM,
               "sourceReady": True, "preparedAt": now(), "patchesVerified": manifest["patches"],
               "patchOrder": order, "preparedFiles": state["preparedFiles"], "removedFiles": state["removedFiles"],
               "dependenciesVerified": state["dependenciesVerified"], "compiled": False, "activated": False,
               "packaged": False, "tarLinks": state.get("tarLinks", {}),
               "sourceExtraction": state.get("sourceExtraction"), "recoveries": state.get("recoveries", [])}
    save_json(root / RECEIPT_NAME, receipt)
    return {"prepared": True, "source": str(source), "receipt": str(root / RECEIPT_NAME),
            "compiled": False, "activated": False, "packaged": False}


def prepare(root, manifest, manifest_hash, seven_zip, here=HERE, project=PROJECT, restart=False):
    root = build_root(root, project)
    state = load_state(root, manifest_hash, project, restart_extraction=restart)
    if not restart:
        check_capacity(root, state)
    # The verified cache must already exist. An exclusive, owned lock also
    # prevents two launchers from both passing a stage-completion check.
    lock = ordinary(root / ".mc-native-prepare.lock")
    token = json.dumps({"pid": os.getpid(), "token": uuid.uuid4().hex, "at": now()})
    with lock.open("x", encoding="utf-8") as stream:
        stream.write(token)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        if restart:
            restart_source_extraction(root, state)
        return _prepare(root, manifest, manifest_hash, seven_zip, here, project)
    finally:
        if ordinary(lock).read_text(encoding="utf-8") == token:
            lock.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--build-root", type=Path, default=PROJECT / ".cache" / "native-engine-build")
    parser.add_argument("--seven-zip", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--restart-extraction", action="store_true",
                        help="Preserve and restart only a journaled failed initial source extraction")
    args = parser.parse_args(argv)
    try:
        root = build_root(args.build_root)
        if args.restart_extraction and not args.prepare:
            raise ValueError("--restart-extraction requires --prepare")
        manifest, manifest_hash = reviewed_manifest(requested_hash=args.manifest_sha256)
        verify_recipe(root / "recipe")
        verify_archive(root, manifest["chromium"]["archive"])
        state = load_state(root, manifest_hash, restart_extraction=args.restart_extraction)
        verify_prepared_files(root, state)
        if args.prepare:
            if not args.seven_zip:
                raise ValueError("--seven-zip is required for preparation")
            result = prepare(root, manifest, manifest_hash, args.seven_zip, restart=args.restart_extraction)
        else:
            result = {"mode": "read-only-preflight", "readOnly": True, "sourceManifestSha256": manifest_hash,
                      "buildRoot": str(root), "completedStages": state["completedStages"],
                      "receiptPresent": (root / RECEIPT_NAME).is_file(), "prepared": False}
        print(json.dumps(result, indent=2))
        return 0
    except BaseException as exc:
        print(json.dumps({"mode": "prepare" if args.prepare else "read-only-preflight", "prepared": False,
                          "readOnly": not args.prepare, "error": type(exc).__name__ + ": " + str(exc)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
