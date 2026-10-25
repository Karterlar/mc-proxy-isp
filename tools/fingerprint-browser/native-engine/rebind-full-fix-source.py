#!/usr/bin/env python3
"""One-off, reviewed 150 r2 source-proof transition; default is read-only.

Never compiles, downloads, promotes a component, or touches browser profiles.
The old candidate is preserved before a later build creates the r2 candidate.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).absolute().parent
PROJECT = HERE.parents[2]
ROOT = PROJECT / '.cache' / 'native-engine-build'
PROOF = PROJECT / 'deliverables' / 'verification' / '2026-10-18-fingerprint-full-fix'
BASE = PROOF / 'before-native-build'
SPEC = importlib.util.spec_from_file_location('native_prepare', HERE / 'prepare-source.py')
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)
OLD_MANIFEST = '03f72bc4c0044b62c97877db556b412698adf8a88aa1f6b07ef6149d4af28847'
OLD_SOURCE = '5976cd5e90b887636729622bcad91972e60b2fa1c812d932ccacdc754c373b19'
OLD_JOURNAL = 'cbd305184483c2d010d4492ca8631d1e212376d68d4ad5b2d7fe6c02f9c3716f'
OLD_RUNNER = 'bac9e387725ff21570468bd44041b33868a0111d5c1ebf0029f438fe79946d60'
OLD_CANDIDATE = 'f08993583a11407383ac6ea473bfc2a6a002083e0a8f2513d48a03a5f0604597'
OLD_BUILD = 'cd01996c745df88c45cf6200cd8fc7f2af0a99ba45cfb83baef69c3e02a98e0d'
OLD_MARKERS = {
    'MCProxy': 'fdfb429625a6b9b12cbd4f01f8eb36619383340ccc567abc9e78504238365562',
    'PatchCheck': '4d3f48f8d43012711cab80769519c3dd5986f3cda5a671bbc02d2de65946e096',
}
GN_SHA256 = '3d80509bad9d1aa618bb1dd27c9658b7b24f161e2753a17b4b67ea959b295d75'
ALLOWED = frozenset([
    'third_party/blink/renderer/core/frame/navigator_device_memory.cc',
    'third_party/blink/renderer/platform/graphics/mc_canvas_noise.h',
    'third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint_test.cc',
])
PATCHES = ('identity/001-public-identity-150.patch', 'canvas/0002-canvas-owned-native-150.patch')
# Canvas review pins are copied from its final source-ready evidence.
REVIEWED_AFTER = {
    'third_party/blink/renderer/core/frame/navigator_device_memory.cc': '69c4a6d2796ecefbb8ebeab82f866da33b5eda285612f9125d7242ed4a6bc993',
    'third_party/blink/renderer/platform/graphics/mc_canvas_noise.h': 'b73e45e989f90d7cc59b3b1a057bc4edb7ed8b69e69b15c90d4504192e24b417',
    'third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint_test.cc': '7662c757ea6a73b8952534233dd5fbf800b7f15249ef6210efc3e178c846ec9a',
}
REVIEWED_PATCHES = {
    PATCHES[0]: 'fe8b2085d98663fb94d89abc3cfe12fbc5995a89079ae3fd6bd10676742a1131',
    PATCHES[1]: '4ce0789a5a4f59a13d54e3ff1bfc54f4dd8682eaefa74d289708afdb5e62cc11',
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + '\n').encode('utf-8')


def file_bytes(path):
    prepare.ordinary(path)
    return path.read_bytes()


def pinned(path, sha):
    value = file_bytes(path)
    require(sha_bytes(value) == sha, 'PINNED_FILE_CHANGED: ' + str(path))
    return value


def verify_files(source, files, allowed=ALLOWED):
    """Only previously recorded paths may be rebound; all others stay exact."""
    seen = set()
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == {'path', 'sha256'}
                and isinstance(entry['path'], str) and entry['path'] not in seen
                and re.fullmatch(r'[a-f0-9]{64}', entry['sha256']), 'PREPARED_LIST_INVALID')
        seen.add(entry['path'])
        prepare.archive_scoped(source, entry['path'])
    require(allowed.issubset(seen), 'REVIEWED_CHANGE_PATH_MISSING')

    def inspect(entry):
        path = prepare.archive_scoped(source, entry['path'])
        require(path.is_file(), 'PREPARED_FILE_MISSING: ' + entry['path'])
        actual = prepare.digest(path)
        if actual != entry['sha256']:
            require(entry['path'] in allowed, 'UNEXPECTED_SOURCE_CHANGE: ' + entry['path'])
            return {'path': entry['path'], 'before': entry['sha256'], 'after': actual}
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        changes = [value for value in executor.map(inspect, files) if value]
    require({value['path'] for value in changes} == allowed, 'REVIEWED_CHANGES_NOT_ALL_READY')
    return changes


def check_idle():
    # Read-only CIM inspection. Never stops a process or changes build state.
    command = ("$p = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { "
               "$_.Name -in @('ninja.exe','cmd.exe','clang-cl.exe','lld-link.exe','link.exe','cl.exe','gn.exe') "
               "-and ($_.ExecutablePath -like '*native-engine-build*' -or $_.CommandLine -like '*native-engine-build*') }); "
               "ConvertTo-Json -InputObject @($p | Select-Object ProcessId,Name) -Compress")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                            check=True, capture_output=True, text=True)
    require(json.loads(result.stdout or '[]') == [], 'NATIVE_BUILD_OR_COMPILER_ACTIVE')


def plan():
    prepare.build_root(ROOT)
    for path in (HERE, BASE, ROOT / 'src', ROOT / 'candidate-runtime'):
        require(prepare.ordinary(path).is_dir(), 'OWNED_DIRECTORY_MISSING: ' + str(path))
    source_bytes = pinned(ROOT / '.mc-native-source.json', OLD_SOURCE)
    journal_bytes = pinned(ROOT / '.mc-native-prepare.json', OLD_JOURNAL)
    pinned(BASE / '.mc-native-source.json', OLD_SOURCE)
    pinned(BASE / '.mc-native-prepare.json', OLD_JOURNAL)
    manifest_bytes = pinned(HERE / 'source-manifest.json', OLD_MANIFEST)
    runner_bytes = pinned(HERE / 'build-windows.ps1', OLD_RUNNER)
    pinned(ROOT / '.mc-native-candidate.json', OLD_CANDIDATE)
    pinned(ROOT / '.mc-native-build.json', OLD_BUILD)
    pinned(BASE / '.mc-native-candidate.json', OLD_CANDIDATE)
    pinned(BASE / '.mc-native-build.json', OLD_BUILD)
    source, journal, manifest = map(json.loads, (source_bytes, journal_bytes, manifest_bytes))
    require(source['schemaVersion'] == journal['schemaVersion'] == 1
            and source['sourceReady'] is True and source['headChromium'] == prepare.CHROMIUM
            and source['sourceManifestSha256'] == journal['sourceManifestSha256'] == OLD_MANIFEST
            and journal['buildRoot'] == str(ROOT) and journal['activeStage'] is None
            and source['preparedFiles'] == journal['preparedFiles']
            and len(source['preparedFiles']) == 18209
            and [value['path'] for value in manifest['patches']] == list(PATCHES), 'OLD_PROOF_CONTRACT_INVALID')
    changes = verify_files(ROOT / 'src', source['preparedFiles'])
    require(all(REVIEWED_AFTER[value['path']] == value['after'] for value in changes),
            'SOURCE_CHANGE_NOT_PINNED_BY_FINAL_REVIEW')
    require((ROOT / 'src/chrome/VERSION').read_text().splitlines()
            == ['MAJOR=150', 'MINOR=0', 'BUILD=7871', 'PATCH=186'], 'CHROMIUM_VERSION_CHANGED')
    markers = []
    for name in ('MCProxy', 'PatchCheck'):
        output = ROOT / 'src/out' / name
        pinned(output / 'args.gn', GN_SHA256)
        marker_file = output / '.mc-native-output.json'
        before = pinned(marker_file, OLD_MARKERS[name])
        marker = json.loads(before)
        require(marker['schemaVersion'] == 1 and marker['buildRoot'] == str(ROOT)
                and marker['sourceManifestSha256'] == OLD_MANIFEST, 'OUTPUT_OWNERSHIP_CHANGED')
        markers.append((marker_file, before, marker))
    require((ROOT / 'src/out/MCProxy/args.gn').read_text(encoding='utf-8-sig').splitlines()
            == manifest['build']['gnArgs'], 'GN_ARGS_CHANGED')
    for value in manifest['patches']:
        value['sha256'] = prepare.digest(HERE / value['path'])
        require(value['sha256'] == REVIEWED_PATCHES[value['path']], 'FINAL_PATCH_REVIEW_HASH_MISMATCH')
        subprocess.run(['git', '-c', 'core.autocrlf=false', '-C', str(ROOT / 'src'), 'apply',
                        '--reverse', '--check', str(HERE / value['path'])], check=True, capture_output=True)
    after_manifest = json_bytes(manifest)
    after_hash = sha_bytes(after_manifest)
    require(after_hash != OLD_MANIFEST, 'PATCHES_HAVE_NOT_CHANGED')
    runner_text = runner_bytes.decode('utf-8-sig')
    old_pin = "$ExpectedManifestSha256 = '" + OLD_MANIFEST + "'"
    require(runner_text.count(old_pin) == 1, 'RUNNER_PIN_CONTRACT_CHANGED')
    after_runner = runner_text.replace(old_pin, "$ExpectedManifestSha256 = '" + after_hash + "'").encode('utf-8')
    changed = {value['path']: value['after'] for value in changes}
    rebound = [{**entry, 'sha256': changed.get(entry['path'], entry['sha256'])} for entry in source['preparedFiles']]
    transition = {'kind': 'reviewed-full-fix-r2-rebind', 'at': prepare.now(),
                  'previousManifestSha256': OLD_MANIFEST, 'previousSourceReceiptSha256': OLD_SOURCE,
                  'previousPrepareJournalSha256': OLD_JOURNAL, 'sourceManifestSha256': after_hash,
                  'preparedFilesChecked': 18209, 'changes': changes, 'sameChromiumAndGnArgs': True}
    source.update(sourceManifestSha256=after_hash, preparedAt=transition['at'], preparedFiles=rebound,
                  patchesVerified=manifest['patches'], compiled=False, activated=False, packaged=False)
    by_patch = {value['path']: value['sha256'] for value in manifest['patches']}
    for value in source['patchOrder']:
        if value['stage'] == 'patch-custom':
            name = value['path'].replace('\\', '/')
            require(name in by_patch, 'CUSTOM_PATCH_ORDER_CHANGED')
            value['sha256'] = by_patch[name]
    source.setdefault('recoveries', []).append(transition)
    journal.update(sourceManifestSha256=after_hash, preparedFiles=rebound)
    journal.setdefault('recoveries', []).append(transition)
    writes = [(HERE / 'source-manifest.json', manifest_bytes, after_manifest),
              (HERE / 'build-windows.ps1', runner_bytes, after_runner),
              (ROOT / '.mc-native-source.json', source_bytes, json_bytes(source)),
              (ROOT / '.mc-native-prepare.json', journal_bytes, json_bytes(journal))]
    for path, before, marker in markers:
        marker.update(sourceManifestSha256=after_hash)
        writes.append((path, before, json_bytes(marker)))
    moves = [(ROOT / 'candidate-runtime', ROOT / 'candidate-runtime.before-full-fix'),
             (ROOT / '.mc-native-candidate.json', ROOT / '.mc-native-candidate.before-full-fix.json')]
    for before, after in moves:
        require(before.is_relative_to(ROOT) and after.is_relative_to(ROOT)
                and before != ROOT and after != ROOT, 'MOVE_OUTSIDE_OWNED_ROOT')
        prepare.ordinary(before); prepare.ordinary(after)
        require(not after.exists(), 'PRESERVED_CANDIDATE_ALREADY_EXISTS')
    return transition, writes, moves


def apply_plan(transition, writes, moves):
    check_idle()
    require(verify_files(ROOT / 'src', json.loads(writes[2][1])['preparedFiles'])
            == transition['changes'], 'SOURCE_CHANGED_AFTER_REVIEW')
    backup = PROOF / 'rebind-backups'
    prepare.ordinary(backup)
    backup.mkdir(exist_ok=False)
    chain = {**transition, 'compiled': False, 'promoted': False,
             'writes': [{'path': str(path.relative_to(PROJECT)), 'before': sha_bytes(before), 'after': sha_bytes(after)}
                        for path, before, after in writes],
             'moves': [{'before': str(before), 'after': str(after)} for before, after in moves]}
    for index, (path, before, _) in enumerate(writes):
        require(file_bytes(path) == before, 'TARGET_CHANGED_BEFORE_REBIND')
        (backup / (str(index) + '-' + path.name)).write_bytes(before)
    prepare.save_json(backup / 'transition-plan.json', chain)
    completed, moved = [], []
    try:
        for path, before, after in writes:
            require(file_bytes(path) == before, 'TARGET_CHANGED_DURING_REBIND')
            temporary = prepare.ordinary(path.with_name(path.name + '.full-fix.tmp'))
            with temporary.open('xb') as stream:
                stream.write(after); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            completed.append((path, before, after))
        for before, after in moves:
            prepare.ordinary(before); prepare.ordinary(after)
            require(not after.exists(), 'PRESERVED_CANDIDATE_ALREADY_EXISTS')
            before.rename(after); moved.append((before, after))
        require(all(file_bytes(path) == after for path, _, after in writes), 'POST_WRITE_HASH_MISMATCH')
        chain['status'] = 'source-proof-rebound-awaiting-recompile'
        prepare.save_json(PROOF / 'native-source-rebind.json', chain)
    except BaseException:
        # Restore only bytes still owned by this transition, never an external edit.
        for before, after in reversed(moved):
            if not before.exists() and after.exists():
                prepare.ordinary(after); after.rename(before)
        for path, before, after in reversed(completed):
            if file_bytes(path) == after:
                path.write_bytes(before)
        raise
    return chain


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.apply:
            lock = prepare.ordinary(ROOT / '.mc-native-prepare.lock')
            with lock.open('x', encoding='utf-8') as stream:
                stream.write(json.dumps({'pid': os.getpid(), 'kind': 'reviewed-r2-rebind'}))
            try:
                transition, writes, moves = plan()
                result = apply_plan(transition, writes, moves)
            finally:
                lock.unlink()
        else:
            transition, writes, moves = plan()
            result = {**transition, 'readOnly': True, 'compiled': False, 'readyToApply': True}
        print(json.dumps(result, indent=2))
        return 0
    except BaseException as cause:
        print(json.dumps({'status': 'refused', 'readOnly': not args.apply,
                          'error': type(cause).__name__ + ': ' + str(cause)}, indent=2))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
