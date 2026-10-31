import tempfile
from pathlib import Path
import unittest

from update_firefox_version import stable_version, update_pin


class FirefoxVersionTests(unittest.TestCase):
    def test_selects_only_stable_release(self):
        self.assertEqual(
            stable_version({"LATEST_FIREFOX_VERSION": "159.0.2", "FIREFOX_NIGHTLY": "161.0a1"}),
            "159.0.2",
        )
        for value in [None, 159, "159.0b1", "159.0esr", "159.0\n", "159.0\"; malicious", ""]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                stable_version({"LATEST_FIREFOX_VERSION": value})
        with self.assertRaises(ValueError):
            stable_version({})

    def test_update_is_narrow_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.go"
            source = 'package vpnclient\n\nconst defaultFirefoxVersion = "158.0.2"\n// unchanged\n'
            path.write_text(source)
            self.assertTrue(update_pin(path, "159.0"))
            expected = source.replace('"158.0.2"', '"159.0"')
            self.assertEqual(path.read_text(), expected)
            self.assertFalse(update_pin(path, "159.0"))
            self.assertEqual(path.read_text(), expected)
            self.assertTrue(update_pin(path, "159.0.1"))

    def test_refuses_downgrades_and_invalid_pins_without_writing(self):
        for source in [
            'const defaultFirefoxVersion = "160.0"\n',
            'const defaultFirefoxVersion = "159.0"\n' * 2,
            "package vpnclient\n",
        ]:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "identity.go"
                path.write_text(source)
                with self.assertRaises(ValueError):
                    update_pin(path, "159.0.1")
                self.assertEqual(path.read_text(), source)

    def test_refuses_invalid_candidate_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.go"
            source = 'const defaultFirefoxVersion = "159.0"\n'
            path.write_text(source)
            with self.assertRaises(ValueError):
                update_pin(path, '160.0"\nmalicious')
            self.assertEqual(path.read_text(), source)


if __name__ == "__main__":
    unittest.main()
