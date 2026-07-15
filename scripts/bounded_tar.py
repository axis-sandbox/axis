#!/usr/bin/env python3
# Copyright 2026 Advanced Micro Devices, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Decode and validate TAR archives once under explicit resource bounds."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import lzma
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from typing import BinaryIO, Iterator
import zlib


BLOCK_SIZE = 512
STREAM_CHUNK_SIZE = 64 * 1024
DECOMPRESSION_INPUT_CHUNK_SIZE = 64 * 1024
DECOMPRESSION_OUTPUT_CHUNK_SIZE = 64 * 1024
SPOOL_MEMORY_LIMIT = 8 * 1024 * 1024
MAX_XZ_MEMORY = 64 * 1024 * 1024
MAX_GNU_LONGNAME_SIZE = 16 * 1024
MAX_GNU_LONGLINK_SIZE = 16 * 1024
MAX_PAX_METADATA_SIZE = 64 * 1024
PAX_TYPES = {b"x", b"X", b"g"}


class TarValidationError(RuntimeError):
    """TAR decoding or metadata violated a resource or integrity bound."""


@dataclass(frozen=True)
class TarLimits:
    compressed_size: int
    decompressed_size: int
    raw_members: int
    member_size: int
    content_size: int


@dataclass(frozen=True)
class TarRecord:
    name: str
    size: int
    kind: str


class BoundedCompressedReader:
    """Count bytes read from an already validated archive descriptor."""

    def __init__(self, source: BinaryIO, limit: int):
        self.source = source
        self.limit = limit
        self.total = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.total
        request = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.source.read(request)
        if self.total + len(data) > self.limit:
            raise TarValidationError("TAR compressed data exceeds size limit")
        self.total += len(data)
        return data


class PrefixedReader:
    """Replay format-detection bytes without rereading the archive descriptor."""

    def __init__(self, prefix: bytes, source: BoundedCompressedReader):
        self.prefix = prefix
        self.offset = 0
        self.source = source

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        available = self.prefix[self.offset :]
        if size < 0:
            self.offset = len(self.prefix)
            return available + self.source.read()
        prefix = available[:size]
        self.offset += len(prefix)
        if len(prefix) == size:
            return prefix
        return prefix + self.source.read(size - len(prefix))


class BoundedReader:
    def __init__(self, source: BinaryIO, limit: int):
        self.source = source
        self.limit = limit
        self.total = 0

    def read_exact(self, size: int, description: str) -> bytes:
        if size < 0 or self.total + size > self.limit:
            raise TarValidationError("TAR decompressed data exceeds size limit")
        chunks = []
        remaining = size
        while remaining:
            chunk = self.source.read(min(STREAM_CHUNK_SIZE, remaining))
            if not chunk:
                raise TarValidationError(f"truncated TAR {description}")
            chunks.append(chunk)
            self.total += len(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def discard(self, size: int, description: str) -> None:
        remaining = size
        while remaining:
            chunk_size = min(STREAM_CHUNK_SIZE, remaining)
            self.read_exact(chunk_size, description)
            remaining -= chunk_size

    def drain_zeroes(self) -> None:
        while True:
            if self.total >= self.limit:
                if self.source.read(1):
                    raise TarValidationError("TAR decompressed data exceeds size limit")
                return
            chunk = self.source.read(min(STREAM_CHUNK_SIZE, self.limit - self.total))
            if not chunk:
                return
            self.total += len(chunk)
            if any(chunk):
                raise TarValidationError("nonzero data follows TAR end marker")


def parse_octal(field: bytes, description: str) -> int:
    if field and field[0] & 0x80:
        raise TarValidationError(f"base-256 TAR {description} is unsupported")
    value = field.rstrip(b"\0 ").lstrip(b" ")
    if not value:
        return 0
    if any(character not in b"01234567" for character in value):
        raise TarValidationError(f"invalid TAR {description}")
    return int(value, 8)


def validate_checksum(header: bytes) -> None:
    expected = parse_octal(header[148:156], "checksum")
    checksum_header = header[:148] + b" " * 8 + header[156:]
    unsigned = sum(checksum_header)
    signed = sum(value if value < 128 else value - 256 for value in checksum_header)
    if expected not in (unsigned, signed):
        raise TarValidationError("invalid TAR header checksum")


def decode_name(value: bytes, description: str) -> str:
    value = value.split(b"\0", 1)[0]
    if not value:
        raise TarValidationError(f"empty TAR {description}")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TarValidationError(f"TAR {description} is not UTF-8") from error


def header_name(header: bytes) -> str:
    name = decode_name(header[:100], "member name")
    prefix_bytes = header[345:500].split(b"\0", 1)[0]
    if not prefix_bytes:
        return name
    prefix = decode_name(prefix_bytes, "member prefix")
    return f"{prefix}/{name}"


def decode_longname(data: bytes) -> str:
    value = data.rstrip(b"\0")
    if not value or b"\0" in value:
        raise TarValidationError("invalid GNU longname metadata")
    return decode_name(value, "GNU longname")


def write_decompressed(
    destination: BinaryIO, data: bytes, total: int, limit: int
) -> int:
    if total + len(data) > limit:
        raise TarValidationError("TAR decompressed data exceeds size limit")
    destination.write(data)
    return total + len(data)


def copy_plain(source: BinaryIO, destination: BinaryIO, limit: int) -> int:
    total = 0
    while chunk := source.read(DECOMPRESSION_INPUT_CHUNK_SIZE):
        total = write_decompressed(destination, chunk, total, limit)
    return total


def decompress_gzip(source: BinaryIO, destination: BinaryIO, limit: int) -> int:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    while True:
        data = source.read(DECOMPRESSION_INPUT_CHUNK_SIZE)
        if not data:
            if not decompressor.eof:
                raise TarValidationError("truncated gzip TAR stream")
            return total
        while data:
            remaining = limit - total
            output = decompressor.decompress(
                data, min(DECOMPRESSION_OUTPUT_CHUNK_SIZE, remaining + 1)
            )
            total = write_decompressed(destination, output, total, limit)
            data = decompressor.unconsumed_tail
            if decompressor.eof:
                if decompressor.unused_data or data or source.read(1):
                    raise TarValidationError(
                        "concatenated or trailing gzip data is unsupported"
                    )
                return total


def decompress_xz(source: BinaryIO, destination: BinaryIO, limit: int) -> int:
    try:
        decompressor = lzma.LZMADecompressor(
            format=lzma.FORMAT_XZ, memlimit=MAX_XZ_MEMORY
        )
        total = 0
        source_exhausted = False
        while True:
            if decompressor.needs_input:
                data = source.read(DECOMPRESSION_INPUT_CHUNK_SIZE)
                source_exhausted = not data
            else:
                data = b""
            if source_exhausted:
                if not decompressor.eof:
                    raise TarValidationError("truncated XZ TAR stream")
                return total
            remaining = limit - total
            output = decompressor.decompress(
                data, max_length=min(DECOMPRESSION_OUTPUT_CHUNK_SIZE, remaining + 1)
            )
            total = write_decompressed(destination, output, total, limit)
            if decompressor.eof:
                if decompressor.unused_data or source.read(1):
                    raise TarValidationError(
                        "concatenated or trailing XZ data is unsupported"
                    )
                return total
    except lzma.LZMAError as error:
        raise TarValidationError(f"XZ decompression failed: {error}") from error


def decompress_to_spool(path: Path, destination: BinaryIO, limits: TarLimits) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TarValidationError(
            f"failed to open TAR archive safely: {path}"
        ) from error
    try:
        with os.fdopen(descriptor, "rb") as opened_source:
            descriptor = -1
            metadata = os.fstat(opened_source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise TarValidationError("TAR archive input is not a regular file")
            if metadata.st_size <= 0 or metadata.st_size > limits.compressed_size:
                raise TarValidationError("TAR compressed size exceeds limit")
            counted_source = BoundedCompressedReader(
                opened_source, limits.compressed_size
            )
            magic = counted_source.read(6)
            source = PrefixedReader(magic, counted_source)
            if magic.startswith(b"\x1f\x8b"):
                total = decompress_gzip(source, destination, limits.decompressed_size)
            elif magic == b"\xfd7zXZ\x00":
                total = decompress_xz(source, destination, limits.decompressed_size)
            else:
                total = copy_plain(source, destination, limits.decompressed_size)
            destination.flush()
            return total
    except TarValidationError:
        raise
    except (OSError, zlib.error) as error:
        raise TarValidationError(f"failed to decode TAR archive: {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_uncompressed_tar(source: BinaryIO, limits: TarLimits) -> list[TarRecord]:
    records: list[TarRecord] = []
    raw_member_count = 0
    content_size = 0
    pending_longname: str | None = None
    reader = BoundedReader(source, limits.decompressed_size)
    zero_blocks = 0
    while True:
        header = reader.read_exact(BLOCK_SIZE, "header")
        if not any(header):
            zero_blocks += 1
            if zero_blocks == 2:
                break
            continue
        if zero_blocks:
            raise TarValidationError("nonzero TAR header follows an end marker")
        validate_checksum(header)
        raw_member_count += 1
        if raw_member_count > limits.raw_members:
            raise TarValidationError("TAR has too many members or extension records")
        size = parse_octal(header[124:136], "member size")
        type_flag = header[156:157] or b"\0"

        if type_flag in PAX_TYPES:
            if size > MAX_PAX_METADATA_SIZE:
                raise TarValidationError("PAX metadata exceeds size limit")
            raise TarValidationError("PAX extension records are unsupported")
        if type_flag == b"K":
            if size > MAX_GNU_LONGLINK_SIZE:
                raise TarValidationError("GNU longlink metadata exceeds size limit")
            raise TarValidationError("GNU longlink records are unsupported")
        if type_flag == b"L":
            if pending_longname is not None:
                raise TarValidationError("stacked GNU longname records are unsupported")
            if size <= 0 or size > MAX_GNU_LONGNAME_SIZE:
                raise TarValidationError("GNU longname metadata exceeds size limit")
            data = reader.read_exact(size, "GNU longname data")
            reader.discard((-size) % BLOCK_SIZE, "GNU longname padding")
            pending_longname = decode_longname(data)
            continue

        name = pending_longname or header_name(header)
        pending_longname = None
        if type_flag in (b"\0", b"0"):
            kind = "file"
            if size > limits.member_size:
                raise TarValidationError(f"TAR member size exceeds limit: {name}")
            content_size += size
            if content_size > limits.content_size:
                raise TarValidationError("TAR content exceeds aggregate size limit")
        elif type_flag == b"5":
            kind = "directory"
            name = name.rstrip("/") or name
            if size != 0:
                raise TarValidationError(f"TAR directory contains data: {name}")
        else:
            raise TarValidationError(f"unsupported archive member type: {name}")
        records.append(TarRecord(name, size, kind))
        reader.discard(size, "member data")
        reader.discard((-size) % BLOCK_SIZE, "member padding")

    if pending_longname is not None:
        raise TarValidationError("GNU longname record has no following member")
    reader.drain_zeroes()
    return records


@contextmanager
def uncompressed_tar_spool(path: Path, limits: TarLimits) -> Iterator[BinaryIO]:
    spool_limit = max(1, min(SPOOL_MEMORY_LIMIT, limits.decompressed_size))
    with tempfile.SpooledTemporaryFile(max_size=spool_limit, mode="w+b") as spool:
        decompress_to_spool(path, spool, limits)
        spool.seek(0)
        yield spool


def validate_tar_archive(path: Path, limits: TarLimits) -> list[TarRecord]:
    with uncompressed_tar_spool(path, limits) as spool:
        return validate_uncompressed_tar(spool, limits)


@contextmanager
def open_validated_tar(
    path: Path, limits: TarLimits
) -> Iterator[tuple[tarfile.TarFile, list[TarRecord]]]:
    with uncompressed_tar_spool(path, limits) as spool:
        records = validate_uncompressed_tar(spool, limits)
        spool.seek(0)
        try:
            package = tarfile.open(fileobj=spool, mode="r:")
        except tarfile.TarError as error:
            raise TarValidationError(
                f"invalid uncompressed TAR archive: {path}"
            ) from error
        try:
            yield package, records
        finally:
            package.close()


def validated_tar_members(
    package: tarfile.TarFile, records: list[TarRecord]
) -> Iterator[tarfile.TarInfo]:
    index = 0
    for member in package:
        if index >= len(records):
            raise TarValidationError("tarfile exposed an unaccounted member")
        record = records[index]
        index += 1
        kind = "directory" if member.isdir() else "file" if member.isfile() else "other"
        if (member.name, member.size, kind) != (record.name, record.size, record.kind):
            raise TarValidationError(
                "tarfile metadata differs from the raw validated TAR manifest"
            )
        yield member
    if index != len(records):
        raise TarValidationError("tarfile omitted a raw validated TAR member")
