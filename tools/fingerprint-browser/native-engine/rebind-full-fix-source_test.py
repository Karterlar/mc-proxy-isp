"""Source transition guards, using synthetic source files only."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('rebind', Path(__file__).with_name('rebind-full-fix-source.py'))
rebind = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rebind)


class SourceTransitionGuards(unittest.TestCase):
    def setUp(self):
        fixture_root = rebind.prepare.ordinary(rebind.PROJECT / '.cache/rebind-full-fix-tests')
        fixture_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='mc-source-rebind-check-', dir=fixture_root)
        self.assertTrue(Path(self.temporary.name).resolve().is_relative_to(fixture_root.resolve()))
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name)
        (self.source / 'changed.cc').write_text('before')
        (self.source / 'untouched.cc').write_text('stable')
        self.entries = [{'path': name, 'sha256': rebind.prepare.digest(self.source / name)}
                        for name in ('changed.cc', 'untouched.cc')]
        self.allowed = frozenset(['changed.cc'])

    def test_only_explicit_changes_are_accepted(self):
        (self.source / 'changed.cc').write_text('after')
        changes = rebind.verify_files(self.source, self.entries, self.allowed)
        self.assertEqual([entry['path'] for entry in changes], ['changed.cc'])
        (self.source / 'untouched.cc').write_text('unexpected edit')
        with self.assertRaisesRegex(ValueError, 'UNEXPECTED_SOURCE_CHANGE'):
            rebind.verify_files(self.source, self.entries, self.allowed)

    def test_missing_planned_change_is_not_ready(self):
        with self.assertRaisesRegex(ValueError, 'REVIEWED_CHANGES_NOT_ALL_READY'):
            rebind.verify_files(self.source, self.entries, self.allowed)

    def test_forged_duplicate_and_traversing_paths_fail(self):
        for entries in (self.entries + [self.entries[0]],
                        [{'path': '../outside.cc', 'sha256': 'a' * 64}],
                        [{'path': 'changed.cc:stream', 'sha256': 'a' * 64}]):
            with self.assertRaises(ValueError):
                rebind.verify_files(self.source, entries, self.allowed)


if __name__ == '__main__':
    unittest.main()
