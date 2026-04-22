#!/usr/bin/env python3
import json
import subprocess
import sys
import unittest
from pathlib import Path

HEXDIG_BIN = None
TEST_WORKDIR = None


def ar_member(name: str, content: bytes) -> bytes:
    name_field = f"{name}/".ljust(16)
    mtime = "0".ljust(12)
    uid = "0".ljust(6)
    gid = "0".ljust(6)
    mode = "100644".ljust(8)
    size = str(len(content)).ljust(10)
    header = (name_field + mtime + uid + gid + mode + size + "`\n").encode("ascii")
    data = content + (b"\n" if len(content) % 2 else b"")
    return header + data


def make_minimal_deb(path: Path) -> None:
    blob = b"!<arch>\n"
    blob += ar_member("debian-binary", b"2.0\n")
    blob += ar_member("control.tar", b"control-content\n")
    blob += ar_member("data.tar", b"payload-content\n")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


class DebTests(unittest.TestCase):
    hexdig = Path()
    workdir = Path()
    fixture = Path()

    @classmethod
    def setUpClass(cls):
        if HEXDIG_BIN is None or TEST_WORKDIR is None:
            raise SystemExit("DebTests not configured")

        cls.hexdig = Path(HEXDIG_BIN).resolve()
        cls.workdir = Path(TEST_WORKDIR).resolve()
        if not cls.hexdig.is_file():
            raise SystemExit("DebTests not configured")

        cls.workdir.mkdir(parents=True, exist_ok=True)
        cls.fixture = cls.workdir / "minimal.deb"
        make_minimal_deb(cls.fixture)

    def test_parser_detects_deb(self):
        json_out = self.workdir / "result.json"
        cmd = [str(self.hexdig), "-v", "-O", str(json_out), str(self.fixture)]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        results = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertTrue(results, "scanner returned no findings")

        deb = next((x for x in results if x.get("type") == "DEB"), None)
        self.assertIsNotNone(deb, "DEB result not found")
        info = deb.get("info", "")
        self.assertIn("Debian package (.deb)", info)
        self.assertIn("control.tar", info)
        self.assertIn("data.tar", info)

    def test_extractor_extracts_members(self):
        extract_root = self.workdir / "out"
        cmd = [str(self.hexdig), "-e", "-C", str(extract_root), str(self.fixture)]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        out_dir = extract_root / f"{self.fixture.name}.extracted" / "0"
        self.assertTrue(out_dir.is_dir(), "expected extraction output directory")
        self.assertTrue((out_dir / "debian-binary").is_file())
        self.assertTrue((out_dir / "control.tar").is_file())
        self.assertTrue((out_dir / "data.tar").is_file())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: test_deb.py <hexdig_bin> <workdir>")
    HEXDIG_BIN = sys.argv[1]
    TEST_WORKDIR = sys.argv[2]
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
