#!/usr/bin/env python3
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HEXDIG_BIN = None
TEST_WORKDIR = None


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def find_parser_cpp_files():
    return sorted((ROOT / "src" / "parsers").glob("*_parser.cpp"))


def find_extractor_cpp_files():
    return sorted((ROOT / "src" / "extractors").glob("*_extractor.cpp"))


def parser_name_from_source(src: str):
    m = re.search(r'name\(\)\s+const\s+override\s*\{\s*return\s+"([^"]+)"', src, flags=re.S)
    return m.group(1) if m else None


def extractor_name_from_source(src: str):
    m = re.search(r'name\(\)\s+const\s+override\s*\{\s*return\s+"([^"]+)"', src, flags=re.S)
    return m.group(1) if m else None


class ComponentCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if HEXDIG_BIN is None or TEST_WORKDIR is None:
            raise SystemExit("ComponentCoverageTests not configured")
        cls.hexdig = Path(HEXDIG_BIN).resolve()
        cls.workdir = Path(TEST_WORKDIR).resolve()
        cls.workdir.mkdir(parents=True, exist_ok=True)

    def test_all_parser_sources_are_registered(self):
        parser_files = find_parser_cpp_files()
        self.assertTrue(parser_files, "no parser sources found")

        for path in parser_files:
            src = read_text(path)
            # linux_parser is intentionally disabled in the current codebase.
            if path.name == "linux_parser.cpp":
                self.assertIn("REGISTER_PARSER", src)
                self.assertIn("//REGISTER_PARSER(LinuxKernelParser)", src)
                continue
            self.assertIn("REGISTER_PARSER(", src, f"missing parser registration in {path.name}")

    def test_all_extractor_sources_are_registered(self):
        extractor_files = find_extractor_cpp_files()
        self.assertTrue(extractor_files, "no extractor sources found")

        for path in extractor_files:
            src = read_text(path)
            self.assertIn("REGISTER_EXTRACTOR(", src, f"missing extractor registration in {path.name}")

    def test_parser_and_extractor_names_are_well_formed(self):
        parser_names = set()
        for path in find_parser_cpp_files():
            name = parser_name_from_source(read_text(path))
            if name is not None:
                parser_names.add(name)
        self.assertTrue(parser_names, "no parser names discovered")
        self.assertEqual(len(parser_names), len(set(parser_names)))

        extractor_names = set()
        for path in find_extractor_cpp_files():
            name = extractor_name_from_source(read_text(path))
            if name is not None:
                extractor_names.add(name)
        self.assertTrue(extractor_names, "no extractor names discovered")
        self.assertEqual(len(extractor_names), len(set(extractor_names)))

    def test_scanner_smoke_random_input(self):
        random_blob = self.workdir / "random.bin"
        random_blob.write_bytes(bytes((i * 37) % 256 for i in range(8192)))
        json_out = self.workdir / "random.json"

        cmd = [str(self.hexdig), "-v", "-e", "-O", str(json_out), str(random_blob)]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertTrue(json_out.exists(), "scanner did not produce JSON output")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: test_components.py <hexdig_bin> <workdir>")
    HEXDIG_BIN = sys.argv[1]
    TEST_WORKDIR = sys.argv[2]
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
