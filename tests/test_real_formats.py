#!/usr/bin/env python3
import base64
import bz2
import binascii
import gzip
import io
import json
import lzma
import shutil
import struct
import subprocess
import sys
import tarfile
import unittest
import zipfile
import zlib
from pathlib import Path


HEXDIG_BIN = None
TEST_WORKDIR = None


def run_scan(hexdig: Path, sample: Path, json_out: Path, extract: bool = False, extract_root: Path | None = None):
    cmd = [str(hexdig), "-v", "-O", str(json_out)]
    if extract:
        if extract_root is None:
            raise RuntimeError("extract_root is required when extract=True")
        cmd += ["-e", "-C", str(extract_root)]
    cmd += [str(sample)]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return json.loads(json_out.read_text(encoding="utf-8"))


def all_results(results):
    out = []

    def rec(item):
        out.append(item)
        for c in item.get("children", []):
            rec(c)

    for r in results:
        rec(r)
    return out


def find_result(results, file_type: str):
    for r in all_results(results):
        if r.get("type") == file_type:
            return r
    return None


def write_ar_member(name: str, content: bytes) -> bytes:
    header = f"{name}/".ljust(16)
    header += "0".ljust(12) + "0".ljust(6) + "0".ljust(6) + "100644".ljust(8)
    header += str(len(content)).ljust(10) + "`\n"
    data = content + (b"\n" if (len(content) % 2) else b"")
    return header.encode("ascii") + data


def build_rpm(path: Path, name: str = "test-rpm-1.0-1"):
    # Minimal RPM: 96-byte lead + signature header + main header. The headers
    # carry zero index entries, which is enough for the parser (it validates the
    # lead magic and the header-structure magic that follows the lead).
    lead = bytearray(96)
    lead[0:4] = bytes([0xED, 0xAB, 0xEE, 0xDB])  # magic
    lead[4] = 3                                   # major version
    lead[5] = 0                                   # minor version
    struct.pack_into(">H", lead, 0x06, 0)         # type: binary
    struct.pack_into(">H", lead, 0x08, 1)         # archnum
    enc = name.encode("ascii")[:65]
    lead[0x0A:0x0A + len(enc)] = enc              # name (NUL-padded)
    struct.pack_into(">H", lead, 0x4C, 1)         # osnum
    struct.pack_into(">H", lead, 0x4E, 5)         # signature type

    def header():  # rpm header structure with no entries
        return bytes([0x8E, 0xAD, 0xE8, 0x01]) + b"\x00" * 4 + struct.pack(">II", 0, 0)

    payload = b"\x1f\x8b\x08\x00payload"          # stand-in compressed cpio
    path.write_bytes(bytes(lead) + header() + header() + payload)


def build_apfs(path: Path, block_size: int = 4096, block_count: int = 8):
    # Minimal APFS container superblock (nx_superblock_t). The 32-byte obj_phys_t
    # header is followed by the 'NXSB' magic at 0x20; all fields little-endian.
    blk = bytearray(block_size)
    struct.pack_into("<8sQQII", blk, 0, b"\x00" * 8, 1, 4, 0x80000001, 0)  # obj_phys_t
    struct.pack_into("<I", blk, 0x20, 0x4253584E)   # nx_magic 'NXSB'
    struct.pack_into("<I", blk, 0x24, block_size)   # nx_block_size
    struct.pack_into("<Q", blk, 0x28, block_count)  # nx_block_count
    blk[0x48:0x58] = bytes(range(16))               # nx_uuid
    # Pad out to the full advertised container size.
    path.write_bytes(bytes(blk) + b"\x00" * (block_size * block_count - block_size))


def build_lzo(path: Path, payload: bytes):
    # Minimal lzop (.lzo) container with a single STORED block (src_len ==
    # dst_len), so no LZO compressor is needed to produce a valid file. All
    # multi-byte fields are big-endian; flags=0 means no per-block checksums.
    blob = bytes([0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a])
    blob += struct.pack(">H", 0x1040)  # version (>= 0x0940)
    blob += struct.pack(">H", 0x2090)  # lib version
    blob += struct.pack(">H", 0x0940)  # version needed to extract
    blob += struct.pack(">B", 1)       # method (LZO1X-1)
    blob += struct.pack(">B", 5)       # level
    blob += struct.pack(">I", 0)       # flags
    blob += struct.pack(">I", 0)       # mode
    blob += struct.pack(">I", 0)       # mtime low
    blob += struct.pack(">I", 0)       # mtime high
    blob += struct.pack(">B", 0)       # name length (no name)
    blob += struct.pack(">I", 0)       # header checksum (not validated)
    # one stored block
    blob += struct.pack(">I", len(payload))  # uncompressed length
    blob += struct.pack(">I", len(payload))  # compressed length (== stored)
    blob += payload
    blob += struct.pack(">I", 0)       # end-of-stream marker
    path.write_bytes(blob)


def build_deb(path: Path):
    blob = b"!<arch>\n"
    blob += write_ar_member("debian-binary", b"2.0\n")
    blob += write_ar_member("control.tar", b"control-content\n")
    blob += write_ar_member("data.tar", b"payload-content\n")
    path.write_bytes(blob)


def cpio_newc_entry(name: str, data: bytes, mode: int = 0o100644, ino: int = 1) -> bytes:
    namesize = len(name.encode("utf-8")) + 1
    header_fields = [
        "070701",
        f"{ino:08x}",
        f"{mode:08x}",
        f"{0:08x}",  # uid
        f"{0:08x}",  # gid
        f"{1:08x}",  # nlink
        f"{0:08x}",  # mtime
        f"{len(data):08x}",
        f"{0:08x}",  # devmajor
        f"{0:08x}",  # devminor
        f"{0:08x}",  # rdevmajor
        f"{0:08x}",  # rdevminor
        f"{namesize:08x}",
        f"{0:08x}",  # check
    ]
    header = "".join(header_fields).encode("ascii")
    return header + name.encode("utf-8") + b"\x00" + data


def build_cpio(path: Path):
    blob = bytearray()
    for name, data, mode, ino in [
        ("cpio_hello.txt", b"hello-cpio\n", 0o100644, 1),
        ("TRAILER!!!", b"", 0, 2),
    ]:
        entry = cpio_newc_entry(name, data, mode=mode, ino=ino)
        blob += entry
        while len(blob) % 4:
            blob += b"\x00"
    path.write_bytes(bytes(blob))


def build_png(path: Path):
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data
    ihdr += struct.pack(">I", binascii.crc32(ihdr[4:]) & 0xFFFFFFFF)

    raw = b"\x00\x00\x00\x00"  # filter byte + one black RGB pixel
    idat_data = zlib.compress(raw)
    idat = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data
    idat += struct.pack(">I", binascii.crc32(idat[4:]) & 0xFFFFFFFF)

    iend = struct.pack(">I", 0) + b"IEND"
    iend += struct.pack(">I", binascii.crc32(b"IEND") & 0xFFFFFFFF)

    path.write_bytes(sig + ihdr + idat + iend)


def build_uimage(path: Path):
    payload = b"uimage-payload\n"
    name = b"test-uimage"
    name = name + (b"\x00" * (32 - len(name)))
    header = struct.pack(
        ">IIIIIIIBBBB32s",
        0x27051956,  # magic
        0,           # hcrc
        0,           # timestamp
        len(payload),
        0,           # load
        0,           # ep
        0,           # dcrc
        5,           # os=linux
        2,           # arch=arm
        2,           # type=kernel
        0,           # comp=none
        name,
    )
    path.write_bytes(header + payload)


def build_dtb(path: Path):
    FDT_BEGIN_NODE = 0x1
    FDT_END_NODE = 0x2
    FDT_PROP = 0x3
    FDT_END = 0x9

    strings = b"compatible\x00"
    struct_block = b""
    struct_block += struct.pack(">I", FDT_BEGIN_NODE)
    struct_block += b"\x00\x00\x00\x00"  # root node name + padding
    struct_block += struct.pack(">I", FDT_PROP)
    struct_block += struct.pack(">I", 4)  # len
    struct_block += struct.pack(">I", 0)  # nameoff -> "compatible"
    struct_block += b"test"
    struct_block += struct.pack(">I", FDT_END_NODE)
    struct_block += struct.pack(">I", FDT_END)

    rsvmap = b"\x00" * 16
    off_mem_rsvmap = 40
    off_dt_struct = off_mem_rsvmap + len(rsvmap)
    off_dt_strings = off_dt_struct + len(struct_block)
    totalsize = off_dt_strings + len(strings)

    header = struct.pack(
        ">IIIIIIIIII",
        0xD00DFEED,
        totalsize,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        17,  # version
        16,  # last compatible version
        0,
        len(strings),
        len(struct_block),
    )
    path.write_bytes(header + rsvmap + struct_block + strings)


def build_romfs(path: Path):
    # Minimal empty ROMFS image: superblock only.
    fs_size = 16
    blob = b"-rom1fs-" + struct.pack(">I", fs_size) + struct.pack(">I", 0)
    path.write_bytes(blob)


def build_mbr(path: Path):
    b = bytearray(512)
    part = 446
    b[part + 4] = 0x83  # Linux
    b[part + 8:part + 12] = struct.pack("<I", 2048)
    b[part + 12:part + 16] = struct.pack("<I", 4096)
    b[510] = 0x55
    b[511] = 0xAA
    path.write_bytes(bytes(b))


def build_fat(path: Path):
    b = bytearray(512)
    b[0:3] = b"\xEB\x3C\x90"
    b[11:13] = struct.pack("<H", 512)
    b[13] = 1
    b[14:16] = struct.pack("<H", 1)
    b[16] = 2
    b[17:19] = struct.pack("<H", 224)
    b[19:21] = struct.pack("<H", 2880)
    b[21] = 0xF0
    b[22:24] = struct.pack("<H", 9)
    b[54:62] = b"FAT12   "
    path.write_bytes(bytes(b))


def build_ext(path: Path):
    b = bytearray(4096)
    sb = 1024
    b[sb + 0x00:sb + 0x04] = struct.pack("<I", 1)  # s_inodes_count
    b[sb + 0x04:sb + 0x08] = struct.pack("<I", 8)  # s_blocks_count
    b[sb + 0x14:sb + 0x18] = struct.pack("<I", 1)  # s_first_data_block (1 for bs=1024)
    b[sb + 0x18:sb + 0x1C] = struct.pack("<I", 0)  # s_log_block_size=0 -> bs=1024
    b[sb + 0x20:sb + 0x24] = struct.pack("<I", 8)  # s_blocks_per_group
    b[sb + 0x28:sb + 0x2C] = struct.pack("<I", 1)  # s_inodes_per_group
    # Signature pattern expected by match() at offset+0x38
    b[sb + 0x38:sb + 0x40] = bytes([0x53, 0xEF, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00])
    b[sb + 0x78:sb + 0x80] = b"TESTVOL\x00"
    path.write_bytes(bytes(b))


def build_cab(path: Path):
    b = bytearray(64)
    b[0:4] = b"MSCF"
    b[8:12] = struct.pack("<I", len(b))
    b[20:24] = struct.pack("<I", 40)  # coffFiles
    b[24:28] = struct.pack("<I", 1)   # nFolders
    b[28:32] = struct.pack("<I", 1)   # nFiles
    b[32:34] = struct.pack("<H", 0)   # flags
    b[34:36] = struct.pack("<H", 1)   # setID
    b[36:38] = struct.pack("<H", 0)   # iCabinet
    path.write_bytes(bytes(b))


def build_rar(path: Path):
    sig = bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00])  # RAR4
    main = struct.pack("<H B H H", 0, 0x73, 0, 7)            # main header block
    endm = struct.pack("<H B H H", 0, 0x7B, 0, 7)            # end marker
    path.write_bytes(sig + main + endm)


def build_dmg(path: Path):
    b = bytearray(512)
    b[0:4] = b"koly"
    b[4:8] = struct.pack(">I", 4)
    b[8:12] = struct.pack(">I", 512)
    path.write_bytes(bytes(b))


def build_crc(path: Path):
    # CRC32 IEEE reflected LE prefix from src/common/crc.hpp
    path.write_bytes(bytes([
        0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
        0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99,
    ]))


def build_aes(path: Path):
    # AES S-Box prefix from src/common/aes.hpp
    path.write_bytes(bytes([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    ]))


def build_pe(path: Path):
    b = bytearray(512)
    b[0:2] = b"MZ"
    b[0x3C:0x40] = struct.pack("<I", 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    b[0x84:0x86] = struct.pack("<H", 0x014C)  # x86
    path.write_bytes(bytes(b))


def build_arj(path: Path):
    def crc16(data: bytes) -> int:
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc & 0xFFFF

    main_data = bytearray(20)
    main_data[0] = 1  # version
    main_data[1] = 0  # flags
    main_crc = crc16(main_data[:18])

    file_data = bytearray(20)
    file_data[0] = 1
    file_data[1] = 0
    file_crc = crc16(file_data[:18])

    blob = bytearray()
    blob += struct.pack("<H", 0xEA60)
    blob += struct.pack("<H", 20)
    blob += struct.pack("<H", main_crc)
    blob += main_data

    blob += struct.pack("<H", 0xEA60)
    blob += struct.pack("<H", 20)
    blob += struct.pack("<H", file_crc)
    blob += file_data

    blob += struct.pack("<H", 0xEA60)
    blob += struct.pack("<H", 0)  # trailer
    path.write_bytes(bytes(blob))


class RealFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if HEXDIG_BIN is None or TEST_WORKDIR is None:
            raise SystemExit("RealFormatTests not configured")
        cls.hexdig = Path(HEXDIG_BIN).resolve()
        cls.workdir = Path(TEST_WORKDIR).resolve()
        cls.workdir.mkdir(parents=True, exist_ok=True)
        cls.fixtures = cls.workdir / "fixtures"
        cls.fixtures.mkdir(parents=True, exist_ok=True)

    def _scan_expect_type(self, sample: Path, expected_type: str):
        json_out = self.workdir / f"{sample.stem}.json"
        results = run_scan(self.hexdig, sample, json_out)
        match = find_result(results, expected_type)
        self.assertIsNotNone(match, f"{expected_type} not detected for {sample.name}")
        return match, results

    def test_real_parsers(self):
        # Archives and compressed formats
        zip_path = self.fixtures / "sample.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("hello.txt", "hello-zip\n")
        self._scan_expect_type(zip_path, "ZIP")

        tar_path = self.fixtures / "sample.tar"
        with tarfile.open(tar_path, "w") as tf:
            data = b"hello-tar\n"
            info = tarfile.TarInfo("hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self._scan_expect_type(tar_path, "TAR")

        gz_path = self.fixtures / "sample.gz"
        with gzip.open(gz_path, "wb") as f:
            f.write(b"hello-gzip\n")
        self._scan_expect_type(gz_path, "GZIP")

        bz2_path = self.fixtures / "sample.bz2"
        bz2_path.write_bytes(bz2.compress(b"hello-bzip2\n"))
        self._scan_expect_type(bz2_path, "Bzip2")

        xz_path = self.fixtures / "sample.xz"
        xz_path.write_bytes(lzma.compress(b"hello-xz\n", format=lzma.FORMAT_XZ))
        self._scan_expect_type(xz_path, "XZ")

        lzma_path = self.fixtures / "sample.lzma"
        lzma_path.write_bytes(lzma.compress(b"hello-lzma\n", format=lzma.FORMAT_ALONE))
        self._scan_expect_type(lzma_path, "LZMA")

        lzo_path = self.fixtures / "sample.lzo"
        build_lzo(lzo_path, b"hello-lzo\n")
        self._scan_expect_type(lzo_path, "LZO")

        apfs_path = self.fixtures / "sample.apfs"
        build_apfs(apfs_path)
        self._scan_expect_type(apfs_path, "APFS")

        rpm_path = self.fixtures / "sample.rpm"
        build_rpm(rpm_path)
        self._scan_expect_type(rpm_path, "RPM")

        cpio_path = self.fixtures / "sample.cpio"
        build_cpio(cpio_path)
        self._scan_expect_type(cpio_path, "CPIO")

        deb_path = self.fixtures / "sample.deb"
        build_deb(deb_path)
        self._scan_expect_type(deb_path, "DEB")

        # Images/docs/text
        png_path = self.fixtures / "sample.png"
        build_png(png_path)
        self._scan_expect_type(png_path, "PNG")

        bmp_path = self.fixtures / "sample.bmp"
        # 1x1 24bpp BMP
        bmp = bytearray()
        bmp += b"BM"
        bmp += struct.pack("<I", 54 + 4)
        bmp += b"\x00\x00\x00\x00"
        bmp += struct.pack("<I", 54)
        bmp += struct.pack("<I", 40)
        bmp += struct.pack("<i", 1) + struct.pack("<i", 1)
        bmp += struct.pack("<H", 1) + struct.pack("<H", 24)
        bmp += struct.pack("<I", 0) + struct.pack("<I", 4)
        bmp += struct.pack("<I", 2835) + struct.pack("<I", 2835)
        bmp += struct.pack("<I", 0) + struct.pack("<I", 0)
        bmp += b"\x00\x00\x00\x00"
        bmp_path.write_bytes(bytes(bmp))
        self._scan_expect_type(bmp_path, "BMP")

        jpg_path = self.fixtures / "sample.jpg"
        jpg_path.write_bytes(base64.b64decode(
            "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxAQEBAQEA8PDw8PDw8NDQ8PDw8NDQ8QFREWFhURFRUYHSggGBolGxUVITEhJSorLi4uFx8zODMsNygtLisBCgoKDQ0NDg0NDisZFRkrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAAEAAQMBIgACEQEDEQH/xAAVAAEBAAAAAAAAAAAAAAAAAAAABv/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhADEAAAAdQf/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABBQJ//8QAFBEBAAAAAAAAAAAAAAAAAAAAEP/aAAgBAwEBPwF//8QAFBEBAAAAAAAAAAAAAAAAAAAAEP/aAAgBAgEBPwF//8QAFBABAAAAAAAAAAAAAAAAAAAAEP/aAAgBAQAGPwJ//8QAFBABAAAAAAAAAAAAAAAAAAAAEP/aAAgBAQABPyF//9k="
        ))
        self._scan_expect_type(jpg_path, "JPG")

        pdf_path = self.fixtures / "sample.pdf"
        pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
        self._scan_expect_type(pdf_path, "PDF")

        svg_path = self.fixtures / "sample.svg"
        svg_path.write_text("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'></svg>", encoding="utf-8")
        self._scan_expect_type(svg_path, "SVG")

        # System/firmware-style blobs
        mbr_path = self.fixtures / "sample.mbr.bin"
        build_mbr(mbr_path)
        self._scan_expect_type(mbr_path, "MBR")

        fat_path = self.fixtures / "sample.fat.bin"
        build_fat(fat_path)
        self._scan_expect_type(fat_path, "FAT")

        ext_path = self.fixtures / "sample.ext.bin"
        build_ext(ext_path)
        self._scan_expect_type(ext_path, "EXT4")

        uimage_path = self.fixtures / "sample.uimage"
        build_uimage(uimage_path)
        self._scan_expect_type(uimage_path, "UIMAGE")

        dtb_path = self.fixtures / "sample.dtb"
        build_dtb(dtb_path)
        self._scan_expect_type(dtb_path, "DTB")

        romfs_path = self.fixtures / "sample.romfs"
        build_romfs(romfs_path)
        self._scan_expect_type(romfs_path, "ROMFS")

        cab_path = self.fixtures / "sample.cab"
        build_cab(cab_path)
        self._scan_expect_type(cab_path, "CAB")

        rar_path = self.fixtures / "sample.rar"
        build_rar(rar_path)
        self._scan_expect_type(rar_path, "RAR")

        dmg_path = self.fixtures / "sample.dmg"
        build_dmg(dmg_path)
        self._scan_expect_type(dmg_path, "DMG")

        crc_path = self.fixtures / "sample.crc.bin"
        build_crc(crc_path)
        self._scan_expect_type(crc_path, "CRC")

        aes_path = self.fixtures / "sample.aes.bin"
        build_aes(aes_path)
        self._scan_expect_type(aes_path, "AES")

        cr_path = self.fixtures / "sample.copyright.txt"
        cr_path.write_text("Copyright 2026 HexDig tests\n", encoding="utf-8")
        self._scan_expect_type(cr_path, "COPYRIGHT")

        pe_path = self.fixtures / "sample.pe.exe"
        build_pe(pe_path)
        self._scan_expect_type(pe_path, "EXE")

        self._scan_expect_type(self.hexdig, "ELF")

        arj_path = self.fixtures / "sample.arj"
        build_arj(arj_path)
        self._scan_expect_type(arj_path, "ARJ")

        if shutil.which("7z"):
            seven_path = self.fixtures / "sample.7z"
            src = self.fixtures / "seven-input.txt"
            src.write_text("hello-7z\n", encoding="utf-8")
            subprocess.run(["7z", "a", "-t7z", str(seven_path), str(src)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._scan_expect_type(seven_path, "7Z")

    def _extract_case(self, sample: Path, expected_type: str, expected_files):
        extract_root = self.workdir / "extract"
        json_out = self.workdir / f"{sample.stem}.extract.json"
        results = run_scan(self.hexdig, sample, json_out, extract=True, extract_root=extract_root)
        hit = find_result(results, expected_type)
        self.assertIsNotNone(hit, f"{expected_type} not detected during extraction")
        offset_hex = f"{int(hit['offset']):x}"
        out_dir = extract_root / f"{sample.name}.extracted" / offset_hex
        self.assertTrue(out_dir.is_dir(), f"missing extraction dir for {expected_type}")
        for rel in expected_files:
            self.assertTrue((out_dir / rel).exists(), f"missing extracted file: {rel}")
        return out_dir

    def test_real_extractors(self):
        deb_path = self.fixtures / "extract.deb"
        build_deb(deb_path)
        self._extract_case(deb_path, "DEB", ["debian-binary", "control.tar", "data.tar"])

        tar_path = self.fixtures / "extract.tar"
        with tarfile.open(tar_path, "w") as tf:
            data = b"hello-tar\n"
            info = tarfile.TarInfo("hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self._extract_case(tar_path, "TAR", ["hello.txt"])

        gz_path = self.fixtures / "extract.gz"
        with gzip.open(gz_path, "wb") as f:
            f.write(b"hello-gzip\n")
        out_dir = self._extract_case(gz_path, "GZIP", ["decompressed.bin"])
        self.assertEqual((out_dir / "decompressed.bin").read_bytes(), b"hello-gzip\n")

        lzo_path = self.fixtures / "extract.lzo"
        build_lzo(lzo_path, b"hello-lzo\n")
        out_dir = self._extract_case(lzo_path, "LZO", ["decompressed.bin"])
        self.assertEqual((out_dir / "decompressed.bin").read_bytes(), b"hello-lzo\n")

        uimage_path = self.fixtures / "extract.uimage"
        build_uimage(uimage_path)
        self._extract_case(uimage_path, "UIMAGE", ["test-uimage.bin"])

        dtb_path = self.fixtures / "extract.dtb"
        build_dtb(dtb_path)
        self._extract_case(dtb_path, "DTB", ["tree.dts"])

        romfs_path = self.fixtures / "extract.romfs"
        build_romfs(romfs_path)
        self._extract_case(romfs_path, "ROMFS", [])

        # RAW extractor path: embed PNG at offset 1 so RAW extraction is triggered.
        png = (self.fixtures / "sample.png").read_bytes()
        raw_path = self.fixtures / "extract_raw.bin"
        raw_path.write_bytes(b"\x00" + png)
        self._extract_case(raw_path, "PNG", ["file.PNG"])

        if shutil.which("7z"):
            zip_path = self.fixtures / "extract.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("hello.txt", "hello-zip\n")
            self._extract_case(zip_path, "ZIP", ["hello.txt"])

    @unittest.expectedFailure
    def test_gif_parser_real_file_known_issue(self):
        gif_path = self.fixtures / "sample.gif"
        gif_path.write_bytes(base64.b64decode("R0lGODlhAQABAIABAP///wAAACwAAAAAAQABAAACAkQBADs="))
        self._scan_expect_type(gif_path, "GIF")

    @unittest.expectedFailure
    def test_cpio_extractor_real_file_known_issue(self):
        cpio_path = self.fixtures / "extract.cpio"
        build_cpio(cpio_path)
        out_dir = self._extract_case(cpio_path, "CPIO", ["cpio_hello.txt"])
        self.assertEqual((out_dir / "cpio_hello.txt").read_bytes(), b"hello-cpio\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: test_real_formats.py <hexdig_bin> <workdir>")
    HEXDIG_BIN = sys.argv[1]
    TEST_WORKDIR = sys.argv[2]
    sys.argv = [sys.argv[0]]
    unittest.main(verbosity=2)
