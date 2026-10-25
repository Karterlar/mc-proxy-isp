"""Focused source-preparation safety checks; no network, extraction or build."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("native_prepare", Path(__file__).with_name("prepare-source.py"))
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PreparationSafety(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mc-native-prepare-")
        self.addCleanup(self.temporary.cleanup)
        self.project = Path(self.temporary.name)
        self.root = self.project / ".cache" / "native-engine-build"
        self.root.mkdir(parents=True)
        self.hash = "a" * 64

    def state(self):
        return prepare.load_state(self.root, self.hash, self.project)

    def test_readonly_validation_failure_returns_nonzero_without_preparation(self):
        output = io.StringIO()
        with patch.object(prepare, "reviewed_manifest", side_effect=ValueError("SOURCE_MANIFEST_CHANGED")), \
                patch.object(prepare, "prepare") as mutate, redirect_stdout(output):
            self.assertEqual(prepare.main([]), 1)
        self.assertEqual(json.loads(output.getvalue())["error"], "ValueError: SOURCE_MANIFEST_CHANGED")
        self.assertFalse(json.loads(output.getvalue())["prepared"])
        mutate.assert_not_called()

    def test_path_boundaries_and_link_parents(self):
        for name in ("../customer", "/etc/passwd", "C:/Windows", "name\\escape", "a/../../b"):
            with self.assertRaises(ValueError):
                prepare.relative(name)
        for name in (self.project, self.project / "backend/runtime/customer", self.project / "deliverables/copy"):
            with self.assertRaises(ValueError):
                prepare.build_root(name, self.project)
        link = self.root / "source-link"
        try:
            link.symlink_to(self.project, target_is_directory=True)
        except OSError:
            return  # Windows accounts without link privilege still exercise junction attribute below.
        with self.assertRaises(ValueError):
            prepare.ordinary(link / "child")

    def test_junction_attribute_refused_without_following_it(self):
        info = type("Info", (), {"st_mode": 0o40755, "st_file_attributes": 0x400})()
        with patch.object(Path, "lstat", return_value=info):
            with self.assertRaisesRegex(ValueError, "LINK_OR_JUNCTION"):
                prepare.ordinary(self.root / "junction/child")

    def test_reading_new_state_does_not_write_and_foreign_root_refused(self):
        self.assertEqual(self.state()["completedStages"], [])
        self.assertFalse((self.root / prepare.STATE_NAME).exists())
        (self.root / "src").mkdir()
        with self.assertRaisesRegex(ValueError, "FOREIGN_BUILD_ROOT"):
            self.state()

    def test_owner_and_manifest_cannot_be_changed(self):
        state = self.state()
        prepare.save_json(self.root / prepare.STATE_NAME, state)
        with self.assertRaisesRegex(ValueError, "OWNERSHIP_MISMATCH"):
            prepare.load_state(self.root, "b" * 64, self.project)

    def test_completed_stage_is_never_replayed(self):
        state, calls = self.state(), []
        prepare.run_stage(self.root, state, "extract-source", lambda: calls.append(1))
        prepare.run_stage(self.root, state, "extract-source", lambda: calls.append(2))
        self.assertEqual(calls, [1])
        self.assertEqual(self.state()["completedStages"], ["extract-source"])

    def test_failed_patch_journal_is_preserved_and_restart_refused(self):
        state = self.state()
        evidence = self.root / "partial-patch-evidence.txt"

        def fail():
            evidence.write_text("first hunk applied", encoding="utf-8")
            raise RuntimeError("second hunk refused")

        with self.assertRaises(RuntimeError):
            prepare.run_stage(self.root, state, "patch-custom", fail)
        recorded = prepare.read_json(self.root / prepare.STATE_NAME)
        self.assertEqual(recorded["activeStage"], "patch-custom")
        self.assertEqual(recorded["failure"]["message"], "second hunk refused")
        self.assertEqual(evidence.read_text(), "first hunk applied")
        with self.assertRaisesRegex(ValueError, "INTERRUPTED_MUTATION_REFUSED"):
            self.state()
        self.assertFalse((self.root / prepare.RECEIPT_NAME).exists())

    def test_only_download_stage_can_resume_after_interruption(self):
        state = self.state()
        state["activeStage"] = "download-dependencies"
        prepare.save_json(self.root / prepare.STATE_NAME, state)
        self.assertEqual(self.state()["activeStage"], "download-dependencies")
        calls = []
        prepare.run_stage(self.root, state, "download-dependencies", lambda: calls.append(1))
        self.assertEqual(calls, [1])

    def test_actual_changed_bytes_and_deleted_files_are_verified(self):
        source = self.root / "src"
        source.mkdir()
        state = {"preparedFiles": [], "removedFiles": []}
        (source / "changed.cc").write_bytes(bytes([0, 255, 128]))
        prepare.remember_files(self.root, state, {"changed.cc", "deleted.cc"})
        self.assertEqual(state["removedFiles"], ["deleted.cc"])
        prepare.verify_prepared_files(self.root, state)
        (source / "changed.cc").write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "PREPARED_SOURCE_CHANGED"):
            prepare.verify_prepared_files(self.root, state)
        (source / "changed.cc").write_bytes(bytes([0, 255, 128]))
        (source / "deleted.cc").write_text("back", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "REMOVED_SOURCE_REAPPEARED"):
            prepare.verify_prepared_files(self.root, state)

    def test_replacement_preserves_original_directory_without_deleting(self):
        original = self.root / "src/third_party/esbuild"
        original.mkdir(parents=True)
        (original / "keep").write_bytes(b"original")
        prepare.preserve_directory(self.root, "third_party/esbuild")
        self.assertEqual((self.root / "source-backups/third_party/esbuild/keep").read_bytes(), b"original")
        self.assertEqual(list(original.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "BACKUP_ALREADY_EXISTS"):
            prepare.preserve_directory(self.root, "third_party/esbuild")

    def test_patch_targets_reject_escape_and_accept_new_files(self):
        candidate = self.root / "candidate.patch"
        candidate.write_text("--- /dev/null\n+++ b/third_party/new.cc\n@@ -0,0 +1 @@\n+x\n", encoding="utf-8")
        self.assertEqual(prepare.patch_targets(candidate), {"third_party/new.cc"})
        candidate.write_text("--- a/../../customer\n+++ b/../../customer\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            prepare.patch_targets(candidate)

    def test_cached_source_hash_and_size_are_both_required(self):
        downloads = self.root / "downloads"
        downloads.mkdir()
        archive = downloads / "test.tar.xz"
        archive.write_bytes(b"verified cache")
        contract = {"filename": archive.name, "bytes": archive.stat().st_size, "sha256": prepare.digest(archive)}
        self.assertEqual(prepare.verify_archive(self.root, contract), archive)
        contract["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "CHROMIUM_ARCHIVE_CHANGED"):
            prepare.verify_archive(self.root, contract)

    def test_cli_hash_is_not_a_review_bypass(self):
        fixture = self.root / "engine"
        fixture.mkdir()
        (fixture / "build-windows.ps1").write_text("$ExpectedManifestSha256 = 'SOURCE_MANIFEST_NOT_YET_REVIEWED'", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "NOT_REVIEWED"):
            prepare.reviewed_manifest(fixture, requested_hash=self.hash)

    def test_concurrent_or_stale_lock_is_not_removed(self):
        lock = self.root / ".mc-native-prepare.lock"
        lock.write_text("another owner", encoding="utf-8")
        with patch.object(prepare.shutil, "disk_usage", return_value=type("Space", (), {"free": 100000000001})()):
            with self.assertRaises(FileExistsError):
                prepare.prepare(self.root, {}, self.hash, Path("7z.exe"), project=self.project)
        self.assertEqual(lock.read_text(), "another owner")

    def failed_extraction(self):
        state = self.state()
        state.update(activeStage="extract-source", completedStages=["download-dependencies"],
                     failure={"type": "ChildProcessError", "message": "symbolic-link privilege"})
        source = self.root / "src" / ("chromium-" + prepare.VERSION)
        (source / "chrome").mkdir(parents=True)
        (source / "chrome/VERSION").write_text("MAJOR=150\nMINOR=0\nBUILD=7871\nPATCH=186\n", encoding="utf-8")
        (source / "keep.txt").write_bytes(b"failed extraction evidence")
        prepare.save_json(self.root / prepare.STATE_NAME, state)
        return state

    def test_explicit_extraction_restart_preserves_every_byte_and_failure_history(self):
        state = self.failed_extraction()
        admitted = prepare.load_state(self.root, self.hash, self.project, restart_extraction=True)
        self.assertEqual(admitted["activeStage"], "extract-source")
        with patch.object(prepare.shutil, "disk_usage", return_value=SimpleNamespace(free=110000000000)):
            prepare.restart_source_extraction(self.root, state)
        self.assertFalse((self.root / "src").exists())
        backup = self.root / state["recoveries"][0]["backup"] / ("chromium-" + prepare.VERSION)
        self.assertEqual((backup / "keep.txt").read_bytes(), b"failed extraction evidence")
        self.assertEqual(state["completedStages"], ["download-dependencies"])
        self.assertIsNone(state["activeStage"])
        self.assertEqual(state["failureHistory"][0]["message"], "symbolic-link privilege")
        self.assertGreater(state["recoveries"][0]["preservedSource"]["bytes"], 0)
        self.assertFalse((self.root / prepare.RECEIPT_NAME).exists())

    def test_restart_refuses_wrong_stage_and_foreign_source_without_moving(self):
        state = self.failed_extraction()
        state["activeStage"] = "patch-custom"
        prepare.save_json(self.root / prepare.STATE_NAME, state)
        with self.assertRaisesRegex(ValueError, "RESTART_SCOPE_INVALID"):
            prepare.load_state(self.root, self.hash, self.project, restart_extraction=True)
        state["activeStage"] = "extract-source"
        foreign = self.root / "src/customer-data.txt"
        foreign.write_bytes(b"must stay")
        with self.assertRaisesRegex(ValueError, "FOREIGN_SOURCE"):
            prepare.restart_source_extraction(self.root, state)
        self.assertEqual(foreign.read_bytes(), b"must stay")
        self.assertFalse((self.root / "source-backups").exists())

    def test_interrupted_preservation_refuses_any_automatic_recovery(self):
        state = self.failed_extraction()
        with patch.object(prepare.shutil, "disk_usage", return_value=SimpleNamespace(free=110000000000)):
            with patch.object(Path, "rename", side_effect=OSError("rename refused")):
                with self.assertRaisesRegex(OSError, "rename refused"):
                    prepare.restart_source_extraction(self.root, state)
        self.assertTrue((self.root / "src").exists())
        with self.assertRaisesRegex(ValueError, "RECOVERY_INTERRUPTED"):
            prepare.load_state(self.root, self.hash, self.project, restart_extraction=True)

    def test_recovery_budget_credits_only_verified_preserved_source_and_keeps_output_room(self):
        state = self.state()
        with patch.object(prepare.shutil, "disk_usage", return_value=SimpleNamespace(free=95000000000)):
            with self.assertRaisesRegex(ValueError, "100_GB"):
                prepare.check_capacity(self.root, state)
            state["recoveries"] = [{"preservedSource": {"bytes": 9600000000}}]
            prepare.check_capacity(self.root, state)
        with patch.object(prepare.shutil, "disk_usage", return_value=SimpleNamespace(free=55000000000)):
            with self.assertRaisesRegex(ValueError, "CAPACITY_INSUFFICIENT"):
                prepare.check_capacity(self.root, state)

    def tar_fixture(self, links):
        archive = self.root / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            member = tarfile.TarInfo("wrapper/license")
            member.size = 8
            stream.addfile(member, io.BytesIO(b"license!"))
            for name, target in links:
                member = tarfile.TarInfo("wrapper/" + name)
                member.type, member.linkname = tarfile.SYMTYPE, target
                stream.addfile(member)
        output = self.root / "output"
        output.mkdir()
        (output / "license").write_bytes(b"license!")
        return archive, output

    def test_tar_file_links_are_copied_and_chains_resolved_without_native_links(self):
        archive, output = self.tar_fixture([("chain", "nested/link"), ("nested/link", "../license")])
        result = prepare.materialize_tar_links(archive, output, "wrapper")
        self.assertEqual((output / "chain").read_bytes(), b"license!")
        self.assertEqual((output / "nested/link").read_bytes(), b"license!")
        self.assertTrue(all(item["status"] == "materialized-file" for item in result))
        self.assertFalse((output / "chain").is_symlink())

    def test_tar_escape_refused_and_directory_or_cycle_reported(self):
        archive, output = self.tar_fixture([("escape", "../../outside")])
        with self.assertRaisesRegex(ValueError, "TAR_LINK_ESCAPES_SOURCE"):
            prepare.materialize_tar_links(archive, output, "wrapper")
        self.assertFalse((self.root / "outside").exists())
        archive.unlink()
        (output / "license").unlink()
        output.rmdir()
        archive, output = self.tar_fixture([("one", "two"), ("two", "one"), ("folder-link", "folder")])
        (output / "folder").mkdir()
        result = prepare.materialize_tar_links(archive, output, "wrapper")
        self.assertEqual(sum(item["status"] == "skipped-missing-or-cycle" for item in result), 2)
        self.assertEqual(sum(item["status"] == "skipped-directory" for item in result), 1)

    def test_only_tar_uses_python_fallback_zip_retains_seven_zip(self):
        calls = []
        downloads = SimpleNamespace(unpack_downloads=lambda *args: calls.append(args))
        common = SimpleNamespace(ExtractorEnum=SimpleNamespace(TAR="tar", SEVENZIP="7z", WINRAR="winrar"))
        properties = SimpleNamespace(extractor=None, download_filename="fixture.tar", output_path="third_party", strip_leading_dirs="wrapper")
        extraction_calls = []
        with patch.object(prepare, "materialize_tar_links", return_value=[]):
            with patch.object(prepare, "extract_tar_regular_files", side_effect=lambda *args: extraction_calls.append(args)):
                prepare.unpack_component(downloads, common, None, "source", properties, self.root, self.root, Path("7z.exe"))
                properties.extractor = "7z"
                prepare.unpack_component(downloads, common, None, "llvm", properties, self.root, self.root, Path("7z.exe"))
        self.assertEqual(len(extraction_calls), 1)
        self.assertEqual(extraction_calls[0][0].name, "fixture.tar")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][-1], {"7z": "7z.exe", "winrar": None})

    def test_real_streaming_tgz_extractor_materializes_internal_file_link_without_privilege(self):
        source, unused = self.tar_fixture([("link", "license")])
        archive = self.root / "fixture.tgz"
        source.rename(archive)
        output = self.root / "real-extraction"
        output.mkdir()
        common = SimpleNamespace(ExtractorEnum=SimpleNamespace(TAR="tar", SEVENZIP="7z", WINRAR="winrar"))
        properties = SimpleNamespace(extractor=None, download_filename=archive.name, output_path=".", strip_leading_dirs="wrapper")
        result = prepare.unpack_component(None, common, None, "source", properties, self.root, output, Path("unused-7z.exe"))
        self.assertEqual((output / "link").read_bytes(), b"license!")
        self.assertFalse((output / "link").is_symlink())
        self.assertEqual(result[0]["status"], "materialized-file")

    def test_streaming_tar_refuses_archive_member_escape_before_writing(self):
        archive = self.root / "escape.tar"
        with tarfile.open(archive, "w") as stream:
            member = tarfile.TarInfo("wrapper/../../customer")
            member.size = 4
            stream.addfile(member, io.BytesIO(b"nope"))
        output = self.root / "extract"
        output.mkdir()
        with self.assertRaisesRegex(ValueError, "TAR_MEMBER_ESCAPES_SOURCE"):
            prepare.extract_tar_regular_files(archive, output, "wrapper")
        self.assertFalse((self.root / "customer").exists())

    def test_real_archive_names_allow_unicode_spaces_and_at_without_shell_expansion(self):
        archive = self.root / "names.tar"
        expected = "docs/中文 Screen shot (1)@2x.png.sha1"
        with tarfile.open(archive, "w") as stream:
            member = tarfile.TarInfo("wrapper/" + expected)
            member.size = 4
            stream.addfile(member, io.BytesIO(b"safe"))
        output = self.root / "names"
        output.mkdir()
        prepare.extract_tar_regular_files(archive, output, "wrapper")
        self.assertEqual((output / expected).read_bytes(), b"safe")
        for value in ("../customer", "file:stream", "folder\\escape", "file\x00suffix"):
            with self.assertRaises(ValueError):
                prepare.archive_scoped(output, value)

    def test_prepared_source_paths_accept_real_prune_domain_and_unicode_names(self):
        source = self.root / "src"
        names = ["chrome/updater/test/data/ChromiumMSI/{7D12A56B-CB3A-4C74-A482-64A75E9F4CB2}/test file.txt",
                 "third_party/node/node_modules/@npmcli/package-json/lib/index.js",
                 "docs/中文,截图 (1)@2x.txt"]
        state = {"preparedFiles": [], "removedFiles": []}
        for name in names:
            file = source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"actual source bytes")
        prepare.remember_files(self.root, state, names)
        self.assertEqual(len(state["preparedFiles"]), 3)
        prepare.verify_prepared_files(self.root, state)
        state["preparedFiles"][0]["path"] = "../../customer"
        with self.assertRaises(ValueError):
            prepare.verify_prepared_files(self.root, state)


if __name__ == "__main__":
    unittest.main(verbosity=2)
