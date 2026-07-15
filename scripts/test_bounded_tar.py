# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import gzip
import io
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import zlib

import bounded_tar


class BoundedTarTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_tar(self, members, *, fmt=tarfile.USTAR_FORMAT, name="archive.tar.gz"):
        path = self.root / name
        with tarfile.open(path, "w:gz", format=fmt) as package:
            for member_name, data in members:
                member = tarfile.TarInfo(member_name)
                member.size = len(data)
                package.addfile(member, io.BytesIO(data))
        return path

    def write_plain_tar(self, members, *, name="archive.tar"):
        path = self.root / name
        with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as package:
            for member_name, data in members:
                member = tarfile.TarInfo(member_name)
                member.size = len(data)
                package.addfile(member, io.BytesIO(data))
        return path

    def write_xz_tar(self, members, *, name="archive.tar.xz"):
        plain = self.write_plain_tar(members, name=f"{name}.source.tar")
        path = self.root / name
        path.write_bytes(lzma.compress(plain.read_bytes(), format=lzma.FORMAT_XZ))
        return path, plain.stat().st_size

    def with_xz_dictionary_property(self, data: bytes, property_value: int) -> bytes:
        result = bytearray(data)
        header_offset = 12
        header_size = (result[header_offset] + 1) * 4
        header = bytearray(result[header_offset : header_offset + header_size])
        self.assertEqual(header[2:4], b"\x21\x01")
        header[4] = property_value
        header[-4:] = zlib.crc32(header[:-4]).to_bytes(4, "little")
        result[header_offset : header_offset + header_size] = header
        return bytes(result)

    def limits(self, archive: Path, **overrides):
        values = {
            "compressed_size": archive.stat().st_size,
            "decompressed_size": 2 * 1024 * 1024,
            "raw_members": 10,
            "member_size": 2 * 1024 * 1024,
            "content_size": 2 * 1024 * 1024,
        }
        values.update(overrides)
        return bounded_tar.TarLimits(**values)

    def test_validates_gzip_tar_and_exact_interpreted_manifest(self):
        archive = self.write_tar([("root/LICENSE", b"text")])
        with bounded_tar.open_validated_tar(archive, self.limits(archive)) as (
            package,
            records,
        ):
            members = list(bounded_tar.validated_tar_members(package, records))
        self.assertEqual(
            [(member.name, member.size) for member in members], [("root/LICENSE", 4)]
        )

    def test_preserves_plain_tar_support(self):
        archive = self.write_plain_tar([("root/LICENSE", b"plain")])
        with bounded_tar.open_validated_tar(archive, self.limits(archive)) as (
            package,
            records,
        ):
            members = list(bounded_tar.validated_tar_members(package, records))
        self.assertEqual(members[0].name, "root/LICENSE")

    def test_supports_bounded_gnu_longname_and_counts_its_raw_record(self):
        long_name = "root/" + "segment/" * 20 + "LICENSE"
        archive = self.write_tar([(long_name, b"text")], fmt=tarfile.GNU_FORMAT)
        records = bounded_tar.validate_tar_archive(
            archive, self.limits(archive, raw_members=2)
        )
        self.assertEqual(records[0].name, long_name)
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "too many members"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, raw_members=1)
            )

    def test_rejects_local_and_global_pax_before_consuming_metadata(self):
        local = self.root / "local.tar.gz"
        with tarfile.open(local, "w:gz", format=tarfile.PAX_FORMAT) as package:
            member = tarfile.TarInfo("root/LICENSE")
            member.pax_headers = {"comment": "metadata"}
            member.size = 4
            package.addfile(member, io.BytesIO(b"text"))
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "PAX extension"):
            bounded_tar.validate_tar_archive(local, self.limits(local))

        info = tarfile.TarInfo("pax-global")
        info.type = tarfile.XGLTYPE
        info.size = 128 * 1024 * 1024
        header = info.tobuf(format=tarfile.GNU_FORMAT)
        global_pax = self.root / "huge-global-pax.tar.gz"
        with gzip.open(global_pax, "wb") as output:
            output.write(header)
        self.assertLess(global_pax.stat().st_size, 1024)
        with self.assertRaisesRegex(
            bounded_tar.TarValidationError, "PAX metadata exceeds"
        ):
            bounded_tar.validate_tar_archive(global_pax, self.limits(global_pax))

    def test_rejects_gnu_longlink_records(self):
        archive = self.root / "longlink.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.GNU_FORMAT) as package:
            link = tarfile.TarInfo("root/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "target/" + "segment/" * 20
            package.addfile(link)
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "longlink"):
            bounded_tar.validate_tar_archive(archive, self.limits(archive))

    def test_enforces_exact_gzip_output_boundary(self):
        archive = self.write_tar([("root/LICENSE", b"text")])
        with gzip.open(archive, "rb") as source:
            decompressed_size = len(source.read())
        bounded_tar.validate_tar_archive(
            archive, self.limits(archive, decompressed_size=decompressed_size)
        )
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "decompressed"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, decompressed_size=decompressed_size - 1)
            )

    def test_opens_before_fstat_and_keeps_the_validated_descriptor(self):
        archive = self.write_tar([("root/LICENSE", b"original")])
        replacement = self.root / "replacement"
        replacement.write_bytes(b"not a tar archive")
        real_fstat = os.fstat
        replaced = False

        def replace_after_open(descriptor):
            nonlocal replaced
            metadata = real_fstat(descriptor)
            if not replaced:
                replacement.replace(archive)
                replaced = True
            return metadata

        with mock.patch.object(bounded_tar.os, "fstat", side_effect=replace_after_open):
            records = bounded_tar.validate_tar_archive(archive, self.limits(archive))
        self.assertTrue(replaced)
        self.assertEqual(records[0].name, "root/LICENSE")
        self.assertEqual(archive.read_bytes(), b"not a tar archive")

    def test_counts_appended_compressed_bytes_and_enforces_exact_cap(self):
        archive = self.write_tar([("root/LICENSE", b"text")])
        exact_size = archive.stat().st_size
        bounded_tar.validate_tar_archive(
            archive, self.limits(archive, compressed_size=exact_size)
        )
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "compressed size"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, compressed_size=exact_size - 1)
            )

        real_read = bounded_tar.BoundedCompressedReader.read
        read_count = 0

        def append_during_read(reader, size=-1):
            nonlocal read_count
            read_count += 1
            if read_count == 2:
                with archive.open("ab") as output:
                    output.write(b"appended")
            return real_read(reader, size)

        with mock.patch.object(
            bounded_tar.BoundedCompressedReader,
            "read",
            append_during_read,
        ), self.assertRaisesRegex(bounded_tar.TarValidationError, "compressed data"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, compressed_size=exact_size)
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation requires POSIX")
    def test_rejects_fifo_without_blocking(self):
        fifo = self.root / "archive.fifo"
        os.mkfifo(fifo)
        finished = threading.Event()
        errors = []

        def validate():
            try:
                bounded_tar.validate_tar_archive(
                    fifo,
                    bounded_tar.TarLimits(1024, 1024, 1, 1, 1),
                )
            except Exception as error:  # noqa: BLE001 - asserted below
                errors.append(error)
            finally:
                finished.set()

        thread = threading.Thread(target=validate, daemon=True)
        thread.start()
        self.assertTrue(finished.wait(1), "FIFO validation blocked while opening")
        self.assertIsInstance(errors[0], bounded_tar.TarValidationError)
        self.assertRegex(str(errors[0]), "not a regular file")

    def test_rejects_longname_over_bound_and_manifest_drift(self):
        long_name = "root/" + "x" * 120
        archive = self.write_tar([(long_name, b"text")], fmt=tarfile.GNU_FORMAT)
        with gzip.open(archive, "rb") as source:
            longname_header = source.read(bounded_tar.BLOCK_SIZE)
        longname_size = bounded_tar.parse_octal(longname_header[124:136], "member size")
        with mock.patch.object(bounded_tar, "MAX_GNU_LONGNAME_SIZE", longname_size):
            bounded_tar.validate_tar_archive(archive, self.limits(archive))
        with mock.patch.object(
            bounded_tar, "MAX_GNU_LONGNAME_SIZE", longname_size - 1
        ), self.assertRaisesRegex(bounded_tar.TarValidationError, "longname metadata"):
            bounded_tar.validate_tar_archive(archive, self.limits(archive))

        with bounded_tar.open_validated_tar(archive, self.limits(archive)) as (
            package,
            records,
        ):
            changed = tarfile.TarInfo(records[0].name)
            changed.size = records[0].size + 1
            with mock.patch.object(
                tarfile.TarFile, "__iter__", return_value=iter([changed])
            ), self.assertRaisesRegex(bounded_tar.TarValidationError, "differs"):
                list(bounded_tar.validated_tar_members(package, records))

    def test_xz_rejects_high_dictionary_tiny_archive(self):
        archive, _size = self.write_xz_tar([("root/LICENSE", b"text")])
        archive.write_bytes(self.with_xz_dictionary_property(archive.read_bytes(), 30))
        self.assertLess(archive.stat().st_size, 1024)
        with self.assertRaisesRegex(
            bounded_tar.TarValidationError, "XZ decompression failed"
        ):
            bounded_tar.validate_tar_archive(archive, self.limits(archive))

    def test_xz_rejects_output_bomb_truncation_and_concatenated_streams(self):
        archive, output_size = self.write_xz_tar([("root/payload", b"0" * 1024 * 1024)])
        self.assertLess(archive.stat().st_size, 2048)
        with mock.patch.object(
            bounded_tar, "SPOOL_MEMORY_LIMIT", 1
        ), self.assertRaisesRegex(bounded_tar.TarValidationError, "decompressed"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, decompressed_size=output_size - 1)
            )

        truncated = self.root / "truncated.tar.xz"
        truncated.write_bytes(archive.read_bytes()[:-8])
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "truncated|failed"):
            bounded_tar.validate_tar_archive(truncated, self.limits(truncated))

        concatenated = self.root / "concatenated.tar.xz"
        concatenated.write_bytes(archive.read_bytes() + archive.read_bytes())
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "concatenated"):
            bounded_tar.validate_tar_archive(concatenated, self.limits(concatenated))

    def test_xz_accepts_exact_memory_and_output_boundaries(self):
        archive, output_size = self.write_xz_tar([("root/LICENSE", b"text")])
        compressed = archive.read_bytes()

        def accepts(memory_limit):
            try:
                decoder = lzma.LZMADecompressor(
                    format=lzma.FORMAT_XZ, memlimit=memory_limit
                )
                decoder.decompress(compressed)
                return True
            except lzma.LZMAError:
                return False

        low, high = 1, bounded_tar.MAX_XZ_MEMORY
        self.assertTrue(accepts(high))
        while low < high:
            middle = (low + high) // 2
            if accepts(middle):
                high = middle
            else:
                low = middle + 1
        required_memory = low

        with mock.patch.object(bounded_tar, "MAX_XZ_MEMORY", required_memory):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, decompressed_size=output_size)
            )
        with mock.patch.object(
            bounded_tar, "MAX_XZ_MEMORY", required_memory - 1
        ), self.assertRaisesRegex(
            bounded_tar.TarValidationError, "XZ decompression failed"
        ):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, decompressed_size=output_size)
            )
        with self.assertRaisesRegex(bounded_tar.TarValidationError, "decompressed"):
            bounded_tar.validate_tar_archive(
                archive, self.limits(archive, decompressed_size=output_size - 1)
            )

    def test_xz_is_decoded_once_and_spool_lifecycle_is_bounded(self):
        archive, _size = self.write_xz_tar([("root/LICENSE", b"text")])
        real_decoder = lzma.LZMADecompressor
        real_tar_open = tarfile.open
        with mock.patch.object(
            bounded_tar.lzma, "LZMADecompressor", wraps=real_decoder
        ) as decoder, mock.patch.object(
            bounded_tar.tarfile, "open", wraps=real_tar_open
        ) as tar_open:
            with bounded_tar.open_validated_tar(archive, self.limits(archive)) as (
                package,
                records,
            ):
                spool = package.fileobj
                list(bounded_tar.validated_tar_members(package, records))
                self.assertFalse(spool.closed)
        self.assertEqual(decoder.call_count, 1)
        self.assertEqual(tar_open.call_count, 1)
        self.assertEqual(tar_open.call_args.kwargs["mode"], "r:")
        self.assertTrue(spool.closed)


if __name__ == "__main__":
    unittest.main()
