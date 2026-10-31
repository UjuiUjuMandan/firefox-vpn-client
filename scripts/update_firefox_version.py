#!/usr/bin/env python3
"""Update the pinned Firefox identity from Mozilla's stable-release metadata."""

import json
from pathlib import Path
import re
from urllib.request import urlopen


METADATA_URL = "https://product-details.mozilla.org/1.0/firefox_versions.json"
IDENTITY_FILE = Path(__file__).resolve().parents[1] / "firefox_identity.go"
VERSION_PATTERN = r"[1-9][0-9]*\.0(?:\.[1-9][0-9]*)?"
PIN_PATTERN = re.compile(
    rf'^(const defaultFirefoxVersion = ")({VERSION_PATTERN})(")$', re.MULTILINE
)


def stable_version(metadata):
    version = metadata.get("LATEST_FIREFOX_VERSION")
    if not isinstance(version, str) or not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError("Mozilla metadata does not contain a valid stable Firefox version")
    return version


def version_key(version):
    parts = tuple(int(part) for part in version.split("."))
    return parts + (0,) * (3 - len(parts))


def update_pin(path, version):
    if not re.fullmatch(VERSION_PATTERN, version):
        raise ValueError("Invalid stable Firefox version")
    source = path.read_text(encoding="utf-8")
    matches = list(PIN_PATTERN.finditer(source))
    if len(matches) != 1:
        raise ValueError("Expected exactly one Firefox version pin")
    current = matches[0].group(2)
    if version_key(version) < version_key(current):
        raise ValueError(f"Refusing Firefox version downgrade: {current} -> {version}")
    if version_key(version) == version_key(current):
        return False
    updated = PIN_PATTERN.sub(lambda m: m.group(1) + version + m.group(3), source)
    path.write_text(updated, encoding="utf-8")
    return True


def main():
    with urlopen(METADATA_URL, timeout=30) as response:
        metadata = json.load(response)
    version = stable_version(metadata)
    if update_pin(IDENTITY_FILE, version):
        print(f"Updated Firefox identity to {version}")
    else:
        print(f"Firefox identity already matches stable {version}")


if __name__ == "__main__":
    main()
