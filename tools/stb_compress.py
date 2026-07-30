#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Ported from stb_compress in Dear ImGui v1.92.7's
# misc/fonts/binary_to_compressed_c.cpp.
# See ../licenses/DEAR-IMGUI-MIT.txt and ../licenses/STB-MIT.txt.
"""Python implementation of Dear ImGui's small stb font compressor.

The format and matching logic mirror misc/fonts/binary_to_compressed_c.cpp
from Dear ImGui v1.92.7.  It is used so the localization patch can keep the
same AddFontFromMemoryCompressedTTF path as the original binary.
"""

from __future__ import annotations

import zlib


WINDOW = 0x40000
HASH_SIZE = 32768
MASK32 = 0xFFFFFFFF


def _u32(value: int) -> int:
    return value & MASK32


def _out_be(output: bytearray, value: int, count: int) -> None:
    output.extend(value.to_bytes(count, "big"))


def _out_literals(output: bytearray, data: bytes, start: int, count: int) -> None:
    while count > 65536:
        _out_literals(output, data, start, 65536)
        start += 65536
        count -= 65536
    if count == 0:
        return
    if count <= 32:
        output.append(0x20 + count - 1)
    elif count <= 2048:
        _out_be(output, 0x0800 + count - 1, 2)
    else:
        _out_be(output, 0x070000 + count - 1, 3)
    output.extend(data[start : start + count])


def _match_length(data: bytes, first: int, second: int, maximum: int) -> int:
    index = 0
    # The byte loop intentionally mirrors stb_matchlen().  A typical localized
    # subset font is small enough that the direct implementation is quick.
    while index < maximum and data[first + index] == data[second + index]:
        index += 1
    return index


def _not_crap(best: int, distance: int) -> bool:
    return (
        (best > 2 and distance <= 0x00100)
        or (best > 5 and distance <= 0x04000)
        or (best > 7 and distance <= 0x80000)
    )


def _hc(data: bytes, offset: int, value: int, c: int) -> int:
    return _u32((value << 7) + (value >> 25) + data[offset + c])


def _hc2(data: bytes, offset: int, value: int, c: int, d: int) -> int:
    return _u32(
        (value << 14)
        + (value >> 18)
        + (data[offset + c] << 7)
        + data[offset + d]
    )


def _hc3(data: bytes, offset: int, c: int, d: int, e: int) -> int:
    return _u32(
        (data[offset + c] << 14)
        + (data[offset + d] << 7)
        + data[offset + e]
    )


def compress(data: bytes) -> bytes:
    """Return an stb-compressed byte stream accepted by Dear ImGui."""

    if len(data) > MASK32:
        raise ValueError("stb font stream cannot exceed 4 GiB")

    output = bytearray(b"\x57\xbc\x00\x00")
    _out_be(output, 0, 4)
    _out_be(output, len(data), 4)
    _out_be(output, WINDOW, 4)

    hashes = [-1] * HASH_SIZE
    end = len(data)
    literal_start = 0
    cursor = 0

    def scramble(value: int) -> int:
        value = _u32(value)
        return _u32(value + (value >> 16)) & (HASH_SIZE - 1)

    while cursor < end and cursor + 12 < end:
        maximum = min(65536, end - cursor)
        best = 2
        distance = 0

        value = _hc3(data, cursor, 0, 1, 2)
        h1 = scramble(value)
        value = _hc2(data, cursor, value, 3, 4)
        h2 = scramble(value)
        value = _hc2(data, cursor, value, 5, 6)
        candidate2 = hashes[h2]
        value = _hc2(data, cursor, value, 7, 8)
        h3 = scramble(value)
        value = _hc2(data, cursor, value, 9, 10)
        candidate3 = hashes[h3]
        value = _hc2(data, cursor, value, 11, 12)
        h4 = scramble(value)

        candidates = (
            (hashes[h1], False),
            (candidate2, True),
            (candidate3, True),
            (hashes[h4], True),
        )
        for candidate, avoid_duplicate in candidates:
            if candidate < 0:
                continue
            candidate_distance = cursor - candidate
            if avoid_duplicate and distance == candidate_distance:
                continue
            length = _match_length(data, candidate, cursor, maximum)
            useful = candidate_distance <= WINDOW and (
                length > 9 or _not_crap(length, candidate_distance)
            )
            if length > best and useful:
                best = length
                distance = candidate_distance

        hashes[h1] = hashes[h2] = hashes[h3] = hashes[h4] = cursor

        if best < 3:
            cursor += 1
            continue

        def flush_literals() -> None:
            nonlocal literal_start
            _out_literals(output, data, literal_start, cursor - literal_start)

        if best <= 0x80 and distance <= 0x100:
            flush_literals()
            output.append(0x80 + best - 1)
            output.append(distance - 1)
        elif best > 5 and best <= 0x100 and distance <= 0x4000:
            flush_literals()
            _out_be(output, 0x4000 + distance - 1, 2)
            output.append(best - 1)
        elif best > 7 and best <= 0x100 and distance <= 0x80000:
            flush_literals()
            _out_be(output, 0x180000 + distance - 1, 3)
            output.append(best - 1)
        elif best > 8 and best <= 0x10000 and distance <= 0x80000:
            flush_literals()
            _out_be(output, 0x100000 + distance - 1, 3)
            _out_be(output, best - 1, 2)
        elif best > 9 and distance <= 0x1000000:
            best = min(best, 65536)
            flush_literals()
            if best <= 0x100:
                output.append(0x06)
                _out_be(output, distance - 1, 3)
                output.append(best - 1)
            else:
                output.append(0x04)
                _out_be(output, distance - 1, 3)
                _out_be(output, best - 1, 2)
        else:
            cursor += 1
            continue

        cursor += best
        literal_start = cursor

    cursor = end
    _out_literals(output, data, literal_start, cursor - literal_start)
    output.extend(b"\x05\xfa")
    _out_be(output, zlib.adler32(data) & MASK32, 4)
    return bytes(output)


def decompress(stream: bytes) -> bytes:
    """Decode an stb stream; primarily used as a build-time integrity check."""

    if len(stream) < 22 or stream[:4] != b"\x57\xbc\x00\x00":
        raise ValueError("invalid stb stream signature")
    if int.from_bytes(stream[4:8], "big") != 0:
        raise ValueError("64-bit stb stream lengths are unsupported")
    output_length = int.from_bytes(stream[8:12], "big")
    output = bytearray()
    cursor = 16

    def copy_match(distance: int, count: int) -> None:
        if distance <= 0 or distance > len(output):
            raise ValueError("invalid stb match distance")
        for _ in range(count):
            output.append(output[-distance])

    while True:
        opcode = stream[cursor]
        if opcode >= 0x20:
            if opcode >= 0x80:
                count = opcode - 0x80 + 1
                distance = stream[cursor + 1] + 1
                cursor += 2
                copy_match(distance, count)
            elif opcode >= 0x40:
                value = int.from_bytes(stream[cursor : cursor + 2], "big")
                distance = value - 0x4000 + 1
                count = stream[cursor + 2] + 1
                cursor += 3
                copy_match(distance, count)
            else:
                count = opcode - 0x20 + 1
                cursor += 1
                output.extend(stream[cursor : cursor + count])
                cursor += count
            continue

        if opcode >= 0x18:
            value = int.from_bytes(stream[cursor : cursor + 3], "big")
            distance = value - 0x180000 + 1
            count = stream[cursor + 3] + 1
            cursor += 4
            copy_match(distance, count)
        elif opcode >= 0x10:
            value = int.from_bytes(stream[cursor : cursor + 3], "big")
            distance = value - 0x100000 + 1
            count = int.from_bytes(stream[cursor + 3 : cursor + 5], "big") + 1
            cursor += 5
            copy_match(distance, count)
        elif opcode >= 0x08:
            value = int.from_bytes(stream[cursor : cursor + 2], "big")
            count = value - 0x0800 + 1
            cursor += 2
            output.extend(stream[cursor : cursor + count])
            cursor += count
        elif opcode == 0x07:
            count = int.from_bytes(stream[cursor + 1 : cursor + 3], "big") + 1
            cursor += 3
            output.extend(stream[cursor : cursor + count])
            cursor += count
        elif opcode == 0x06:
            distance = int.from_bytes(stream[cursor + 1 : cursor + 4], "big") + 1
            count = stream[cursor + 4] + 1
            cursor += 5
            copy_match(distance, count)
        elif opcode == 0x04:
            distance = int.from_bytes(stream[cursor + 1 : cursor + 4], "big") + 1
            count = int.from_bytes(stream[cursor + 4 : cursor + 6], "big") + 1
            cursor += 6
            copy_match(distance, count)
        elif opcode == 0x05 and stream[cursor + 1] == 0xFA:
            expected_adler = int.from_bytes(stream[cursor + 2 : cursor + 6], "big")
            if len(output) != output_length:
                raise ValueError("stb output length mismatch")
            if (zlib.adler32(output) & MASK32) != expected_adler:
                raise ValueError("stb checksum mismatch")
            return bytes(output)
        else:
            raise ValueError(f"unknown stb opcode 0x{opcode:02X}")
