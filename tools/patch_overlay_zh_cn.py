#!/usr/bin/env python3
"""Create a static zh-CN patch of the Pipsi-ZZZ 0.6.2 overlay DLL.

The input PE is never loaded or executed.  The patch adds one read-only section
containing UTF-8 translations and an stb-compressed Noto Sans SC subset, then
redirects existing RIP-relative string references and relocated string tables.
Both embedded Dear ImGui default-font paths are redirected to the CJK subset,
which covers the DX11 and DX12 contexts. Existing inline string-handling code
is adjusted for the UTF-8 Auto Skip preview; no executable section is added.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import struct
from collections import defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP
from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

from stb_compress import compress as stb_compress
from stb_compress import decompress as stb_decompress


IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_REL_BASED_DIR64 = 10
SECTION_NAME = b".zhcn"
SECTION_MAGIC = b"PIPSIZH\x00"
FORMAT_RE = re.compile(
    r"%(?:[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|I64|I32|z|t|j|L)?[diuoxXfFeEgGaAcspn%])"
)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def validate_distinct_paths(paths: dict[str, Path]) -> None:
    """Reject path aliases before any output file can be written."""

    seen: list[tuple[str, Path, str]] = []
    for role, path in paths.items():
        resolved = path.expanduser().resolve(strict=False)
        normalized = os.path.normcase(str(resolved))
        for previous_role, previous_path, previous_normalized in seen:
            same_path = normalized == previous_normalized
            if not same_path and resolved.exists() and previous_path.exists():
                same_path = os.path.samefile(resolved, previous_path)
            if same_path:
                raise ValueError(
                    f"{role} path collides with {previous_role}: {resolved}"
                )
        seen.append((role, resolved, normalized))


def all_occurrences(data: bytes, needle: bytes):
    start = 0
    while True:
        found = data.find(needle, start)
        if found < 0:
            return
        yield found
        start = found + 1


def read_c_string(data: bytes, offset: int) -> str:
    end = data.index(0, offset)
    return data[offset:end].decode("ascii")


def validate_translation_table(table: dict[str, str]) -> None:
    if not table:
        raise ValueError("translation table is empty")
    for source, target in table.items():
        if not source or not target:
            raise ValueError(f"empty translation entry: {source!r} -> {target!r}")
        if source.startswith("##"):
            raise ValueError(f"hidden ImGui ID must not be translated: {source}")
        source_formats = FORMAT_RE.findall(source)
        target_formats = FORMAT_RE.findall(target)
        if source_formats != target_formats:
            raise ValueError(
                f"format placeholder mismatch for {source!r}: "
                f"{source_formats!r} != {target_formats!r}"
            )
        target.encode("utf-8", errors="strict")


def build_font_subset(font_data: bytes, translations: dict[str, str]) -> bytes:
    codepoints = set(range(0x20, 0x7F))
    codepoints.update(range(0xA0, 0x100))
    codepoints.add(0x2026)
    for text in translations.values():
        codepoints.update(value for value in map(ord, text) if value >= 0x20)

    font = TTFont(
        io.BytesIO(font_data), recalcBBoxes=True, recalcTimestamp=False
    )
    if "fvar" in font:
        instantiateVariableFont(font, {"wght": 400}, inplace=True, optimize=True)

    options = subset.Options()
    options.hinting = True
    options.layout_features = ["*"]
    # Keep copyright and license records in the generated OFL font subset.
    options.name_IDs = [0, 1, 2, 3, 4, 5, 6, 13, 14]
    options.name_languages = [0x0409, 0x0804]
    options.recalc_timestamp = False
    options.canonical_order = True
    options.drop_tables += ["DSIG"]

    subsetter = subset.Subsetter(options=options)
    subsetter.populate(unicodes=codepoints)
    subsetter.subset(font)

    available = set()
    for cmap in font["cmap"].tables:
        available.update(cmap.cmap)
    missing = sorted(codepoints - available)
    if missing:
        shown = ", ".join(f"U+{value:04X}" for value in missing[:16])
        raise ValueError(f"font subset is missing requested characters: {shown}")

    name_values: dict[int, list[str]] = defaultdict(list)
    for record in font["name"].names:
        if record.nameID in (0, 13, 14):
            name_values[record.nameID].append(record.toUnicode())
    if not any("Adobe" in value for value in name_values[0]):
        raise ValueError("font subset lost its Adobe copyright record")
    if not any("SIL Open Font License" in value for value in name_values[13]):
        raise ValueError("font subset lost its SIL OFL license record")
    if not any("scripts.sil.org/OFL" in value for value in name_values[14]):
        raise ValueError("font subset lost its SIL OFL URL record")

    output = io.BytesIO()
    font.flavor = None
    font.save(output, reorderTables=True)
    result = output.getvalue()

    # Re-open the generated font so a malformed subset fails before PE editing.
    check = TTFont(io.BytesIO(result), lazy=False)
    check.close()
    return result


def build_section(
    translations: dict[str, str], compressed_font: bytes
) -> tuple[bytes, dict[str, int], int]:
    header_size = 0x20
    payload = bytearray(header_size)
    offsets: dict[str, int] = {}
    for source, target in translations.items():
        offsets[source] = len(payload)
        payload.extend(target.encode("utf-8"))
        payload.append(0)

    while len(payload) % 16:
        payload.append(0)
    font_offset = len(payload)
    payload.extend(compressed_font)

    struct.pack_into(
        "<8sIIIIII",
        payload,
        0,
        SECTION_MAGIC,
        1,
        len(translations),
        header_size,
        font_offset,
        len(compressed_font),
        0,
    )
    return bytes(payload), offsets, font_offset


def add_section(
    original: bytes, pe: pefile.PE, payload: bytes
) -> tuple[bytearray, int, int, int]:
    if any(section.Name.rstrip(b"\x00") == SECTION_NAME for section in pe.sections):
        raise ValueError("input already has a .zhcn section")

    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    section_table = (
        pe.DOS_HEADER.e_lfanew
        + 4
        + pe.FILE_HEADER.sizeof()
        + pe.FILE_HEADER.SizeOfOptionalHeader
    )
    new_header_offset = section_table + pe.FILE_HEADER.NumberOfSections * 40
    first_raw = min(
        section.PointerToRawData
        for section in pe.sections
        if section.PointerToRawData
    )
    if new_header_offset + 40 > first_raw:
        raise ValueError("PE headers have no room for another section")

    last_virtual_end = max(
        section.VirtualAddress
        + max(section.Misc_VirtualSize, section.SizeOfRawData)
        for section in pe.sections
    )
    last_raw_end = max(
        section.PointerToRawData + section.SizeOfRawData for section in pe.sections
    )
    new_rva = align_up(last_virtual_end, section_alignment)
    new_raw = align_up(last_raw_end, file_alignment)
    raw_size = align_up(len(payload), file_alignment)
    new_size_of_image = align_up(new_rva + len(payload), section_alignment)

    output = bytearray(original)
    if len(output) < new_raw:
        output.extend(b"\x00" * (new_raw - len(output)))
    output.extend(payload)
    output.extend(b"\x00" * (raw_size - len(payload)))

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        SECTION_NAME.ljust(8, b"\x00"),
        len(payload),
        new_rva,
        raw_size,
        new_raw,
        0,
        0,
        0,
        0,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    )
    output[new_header_offset : new_header_offset + 40] = section_header

    struct.pack_into(
        "<H",
        output,
        pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
        pe.FILE_HEADER.NumberOfSections + 1,
    )
    struct.pack_into(
        "<I",
        output,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData"),
        pe.OPTIONAL_HEADER.SizeOfInitializedData + raw_size,
    )
    struct.pack_into(
        "<I",
        output,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"),
        new_size_of_image,
    )
    return output, new_rva, new_raw, raw_size


def instructions(pe: pefile.PE):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue
        for insn in decoder.disasm(section.get_data(), image_base + section.VirtualAddress):
            if insn.id != 0:
                yield insn


def rip_targets(insn):
    for operand in insn.operands:
        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            yield insn.address + insn.size + operand.mem.disp


def relocation_rvas(pe: pefile.PE) -> set[int]:
    result: set[int] = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return result
    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        for entry in block.entries:
            if entry.type == IMAGE_REL_BASED_DIR64:
                result.add(entry.rva)
    return result


def source_string_vas(
    original: bytes, pe: pefile.PE, translations: dict[str, str]
) -> dict[int, str]:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    result: dict[int, str] = {}
    for source in translations:
        pattern = source.encode("ascii") + b"\x00"
        for offset in all_occurrences(original, pattern):
            try:
                rva = pe.get_rva_from_offset(offset)
            except pefile.PEFormatError:
                continue
            result[image_base + rva] = source
    return result


def patch_translations(
    output: bytearray,
    original: bytes,
    pe: pefile.PE,
    translations: dict[str, str],
    target_vas: dict[str, int],
) -> tuple[dict[str, dict[str, int]], list[dict[str, str]]]:
    old_va_to_source = source_string_vas(original, pe, translations)
    report = {
        source: {"rip_lea": 0, "relocated_pointer": 0, "unsupported_xref": 0}
        for source in translations
    }
    unsupported: list[dict[str, str]] = []
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for insn in instructions(pe):
        for target in rip_targets(insn):
            source = old_va_to_source.get(target)
            if source is None:
                continue
            if insn.mnemonic != "lea" or insn.disp_size != 4:
                report[source]["unsupported_xref"] += 1
                unsupported.append(
                    {
                        "source": source,
                        "address": f"0x{insn.address:X}",
                        "instruction": f"{insn.mnemonic} {insn.op_str}",
                    }
                )
                continue
            next_ip = insn.address + insn.size
            displacement = target_vas[source] - next_ip
            if not -(1 << 31) <= displacement < (1 << 31):
                raise ValueError(f"RIP displacement out of range for {source!r}")
            instruction_offset = pe.get_offset_from_rva(insn.address - image_base)
            struct.pack_into(
                "<i", output, instruction_offset + insn.disp_offset, displacement
            )
            report[source]["rip_lea"] += 1

    relocations = relocation_rvas(pe)
    for old_va, source in old_va_to_source.items():
        needle = struct.pack("<Q", old_va)
        for offset in all_occurrences(original, needle):
            try:
                pointer_rva = pe.get_rva_from_offset(offset)
            except pefile.PEFormatError:
                continue
            if pointer_rva not in relocations:
                continue
            struct.pack_into("<Q", output, offset, target_vas[source])
            report[source]["relocated_pointer"] += 1

    missing = [
        source
        for source, counts in report.items()
        if counts["rip_lea"] + counts["relocated_pointer"] == 0
    ]
    if missing:
        raise ValueError("no safe reference found for: " + ", ".join(repr(v) for v in missing))
    return report, unsupported


def embedded_proggy_fonts(original: bytes, pe: pefile.PE) -> dict[int, str]:
    result: dict[int, str] = {}
    image_base = pe.OPTIONAL_HEADER.ImageBase
    signature = b"\x57\xbc\x00\x00\x00\x00\x00\x00"
    for offset in all_occurrences(original, signature):
        try:
            decompressed = stb_decompress(original[offset:])
            font = TTFont(io.BytesIO(decompressed), lazy=False)
        except Exception:
            continue
        names: list[str] = []
        for record in font["name"].names:
            if record.nameID in (1, 4, 6):
                try:
                    names.append(record.toUnicode())
                except Exception:
                    pass
        font.close()
        joined = " / ".join(dict.fromkeys(names)) or f"EmbeddedFont@0x{offset:X}"
        rva = pe.get_rva_from_offset(offset)
        result[image_base + rva] = joined
    return result


def patch_default_fonts(
    output: bytearray, original: bytes, pe: pefile.PE, new_font_va: int
) -> list[dict[str, str]]:
    proggy = embedded_proggy_fonts(original, pe)
    if len(proggy) != 2:
        raise ValueError(f"expected two embedded Proggy fonts, found {len(proggy)}")

    image_base = pe.OPTIONAL_HEADER.ImageBase
    patched: list[dict[str, str]] = []
    for insn in instructions(pe):
        targets = set(rip_targets(insn))
        matched = targets.intersection(proggy)
        if not matched:
            continue
        if insn.mnemonic != "lea" or insn.disp_size != 4:
            raise ValueError(
                f"unsupported default-font reference at 0x{insn.address:X}: "
                f"{insn.mnemonic} {insn.op_str}"
            )
        next_ip = insn.address + insn.size
        displacement = new_font_va - next_ip
        if not -(1 << 31) <= displacement < (1 << 31):
            raise ValueError("new font is outside RIP-relative range")
        instruction_offset = pe.get_offset_from_rva(insn.address - image_base)
        struct.pack_into("<i", output, instruction_offset + insn.disp_offset, displacement)
        old_va = next(iter(matched))
        patched.append(
            {
                "instruction": f"0x{insn.address:X}",
                "original_font": proggy[old_va],
            }
        )
    if len(patched) != 2:
        raise ValueError(f"expected two default-font references, patched {len(patched)}")
    return patched


def patch_filter_preview(
    output: bytearray,
    original: bytes,
    pe: pefile.PE,
    translations: dict[str, str],
    target_vas: dict[str, int],
) -> dict[str, object]:
    """Fix the UTF-8 byte counts used by the Auto Skip filter preview.

    MSVC inlined the short English std::string appends in this function. Merely
    redirecting the literal pointers would therefore leave two English movabs
    fast paths and truncate the multibyte Chinese strings. The two 8-byte
    movabs paths are made unreachable and routed through the existing string
    growth helper; the other byte counts are adjusted in place.
    """

    expected_text = {
        "Comic": "漫画",
        "Cutscene": "过场动画",
        "Dialogue": "对话",
        "Galge": "视觉小说",
    }
    for source, expected in expected_text.items():
        if translations.get(source) != expected:
            raise ValueError(
                f"filter preview patch expects {source!r} -> {expected!r}"
            )
    lengths = {
        source: len(translations[source].encode("utf-8")) for source in expected_text
    }
    if lengths != {"Comic": 6, "Cutscene": 12, "Dialogue": 6, "Galge": 12}:
        raise ValueError(f"unexpected filter UTF-8 lengths: {lengths!r}")

    image_base = pe.OPTIONAL_HEADER.ImageBase
    baseline_comic_reference = 0x180002C6D
    comic_sources = source_string_vas(
        original, pe, {"Comic": translations["Comic"]}
    )
    comic_inline_references: list[int] = []
    for insn in instructions(pe):
        if insn.mnemonic == "lea":
            continue
        if set(rip_targets(insn)).intersection(comic_sources):
            comic_inline_references.append(insn.address)
    if len(comic_inline_references) != 1:
        raise ValueError(
            "expected exactly one inline Comic reference, found "
            f"{len(comic_inline_references)}"
        )
    comic_inline_reference = comic_inline_references[0]
    address_delta = comic_inline_reference - baseline_comic_reference

    def profile_va(baseline_va: int) -> int:
        return baseline_va + address_delta

    def raw_offset(va: int) -> int:
        return pe.get_offset_from_rva(va - image_base)

    def replace(va: int, expected: bytes, replacement: bytes) -> None:
        if len(expected) != len(replacement):
            raise ValueError(f"in-place patch size mismatch at 0x{va:X}")
        offset = raw_offset(va)
        actual = bytes(output[offset : offset + len(expected)])
        if actual != expected:
            raise ValueError(
                f"unexpected instruction bytes at 0x{va:X}: "
                f"{actual.hex()} != {expected.hex()}"
            )
        output[offset : offset + len(replacement)] = replacement

    def redirect_rip(
        va: int,
        instruction_size: int,
        displacement_offset: int,
        expected_prefix: bytes,
        target_va: int,
        replacement_prefix: bytes | None = None,
    ) -> None:
        offset = raw_offset(va)
        prefix = bytes(output[offset : offset + len(expected_prefix)])
        if prefix != expected_prefix:
            raise ValueError(
                f"unexpected RIP instruction at 0x{va:X}: "
                f"{prefix.hex()} != {expected_prefix.hex()}"
            )
        if replacement_prefix is not None:
            if len(replacement_prefix) != len(expected_prefix):
                raise ValueError("RIP opcode replacement size mismatch")
            output[offset : offset + len(replacement_prefix)] = replacement_prefix
        displacement = target_va - (va + instruction_size)
        if not -(1 << 31) <= displacement < (1 << 31):
            raise ValueError(f"RIP displacement out of range at 0x{va:X}")
        struct.pack_into("<i", output, offset + displacement_offset, displacement)

    # Comic is initialized in the small-string buffer with a 4-byte load plus
    # a second zero-extending load. Widen the latter to a word and store EAX so
    # both remaining UTF-8 bytes and a trailing zero are written in place.
    replace(
        profile_va(0x180002C65),
        b"\x48\xC7\x45\xCF\x05\x00\x00\x00",
        b"\x48\xC7\x45\xCF\x06\x00\x00\x00",
    )
    redirect_rip(
        profile_va(0x180002C6D),
        instruction_size=6,
        displacement_offset=2,
        expected_prefix=b"\x8B\x05",
        target_va=target_vas["Comic"],
    )
    redirect_rip(
        profile_va(0x180002C76),
        instruction_size=7,
        displacement_offset=3,
        expected_prefix=b"\x0F\xB6\x05",
        replacement_prefix=b"\x0F\xB7\x05",
        target_va=target_vas["Comic"] + 4,
    )
    replace(profile_va(0x180002C7D), b"\x88\x45\xC3", b"\x89\x45\xC3")
    replace(
        profile_va(0x180002C80),
        b"\x44\x88\x7D\xC4",
        b"\x44\x88\x7D\xC5",
    )

    # The Cutscene and Dialogue fast paths embed exactly eight ASCII bytes in
    # movabs instructions. Force the already-present allocation/append paths,
    # whose literal pointers were redirected by patch_translations().
    replace(profile_va(0x180002CF7), b"\x72", b"\xEB")
    replace(
        profile_va(0x180002D23),
        b"\x48\xC7\x44\x24\x20\x08\x00\x00\x00",
        b"\x48\xC7\x44\x24\x20\x0C\x00\x00\x00",
    )
    replace(
        profile_va(0x180002D33),
        b"\xBA\x08\x00\x00\x00",
        b"\xBA\x0C\x00\x00\x00",
    )

    replace(profile_va(0x180002DC3), b"\x72", b"\xEB")
    replace(
        profile_va(0x180002DEF),
        b"\x48\xC7\x44\x24\x20\x08\x00\x00\x00",
        b"\x48\xC7\x44\x24\x20\x06\x00\x00\x00",
    )
    replace(
        profile_va(0x180002DFF),
        b"\xBA\x08\x00\x00\x00",
        b"\xBA\x06\x00\x00\x00",
    )

    # Galge already uses memcpy/the growth helper, so only its byte counts and
    # terminator offset need to follow the 12-byte UTF-8 translation.
    replace(
        profile_va(0x180002E84),
        b"\x48\x83\xF8\x05",
        b"\x48\x83\xF8\x0C",
    )
    replace(
        profile_va(0x180002E8A),
        b"\x48\x8D\x42\x05",
        b"\x48\x8D\x42\x0C",
    )
    replace(
        profile_va(0x180002EA2),
        b"\x41\xB8\x05\x00\x00\x00",
        b"\x41\xB8\x0C\x00\x00\x00",
    )
    replace(
        profile_va(0x180002EB7),
        b"\xC6\x43\x05\x00",
        b"\xC6\x43\x0C\x00",
    )
    replace(
        profile_va(0x180002EBD),
        b"\x48\xC7\x44\x24\x20\x05\x00\x00\x00",
        b"\x48\xC7\x44\x24\x20\x0C\x00\x00\x00",
    )
    replace(
        profile_va(0x180002ECD),
        b"\xBA\x05\x00\x00\x00",
        b"\xBA\x0C\x00\x00\x00",
    )

    # The original preview cuts at 22 raw bytes when length exceeds 25, which
    # can split a three-byte CJK code point. The longest translated combination
    # is 42 bytes including three ", " separators, so keep it intact.
    max_preview = sum(lengths.values()) + 3 * len(b", ")
    if max_preview != 42:
        raise ValueError(f"unexpected maximum filter preview length: {max_preview}")
    replace(
        profile_va(0x180002EE3),
        b"\x48\x83\xFA\x19",
        b"\x48\x83\xFA\x2A",
    )

    return {
        "labels": {
            source: {
                "translation": translations[source],
                "utf8_bytes": length,
            }
            for source, length in lengths.items()
        },
        "max_preview_utf8_bytes": max_preview,
        "preview_truncation_threshold": max_preview,
        "profile_address_delta": f"0x{address_delta:X}",
        "comic_inline_reference": f"0x{comic_inline_reference:X}",
        "forced_growth_paths": [
            f"0x{profile_va(0x180002CF7):X}",
            f"0x{profile_va(0x180002DC3):X}",
        ],
    }


def validate_output(
    output: bytes,
    expected_rva: int,
    expected_raw: int,
    section_payload_size: int,
    font_offset: int,
    compressed_font: bytes,
) -> pefile.PE:
    pe = pefile.PE(data=output, fast_load=False)
    matching = [
        section for section in pe.sections if section.Name.rstrip(b"\x00") == SECTION_NAME
    ]
    if len(matching) != 1:
        raise ValueError("output does not contain exactly one .zhcn section")
    section = matching[0]
    if section.VirtualAddress != expected_rva or section.PointerToRawData != expected_raw:
        raise ValueError(".zhcn section address changed unexpectedly")
    if section.Misc_VirtualSize != section_payload_size:
        raise ValueError(".zhcn virtual size mismatch")
    if output[expected_raw : expected_raw + 8] != SECTION_MAGIC:
        raise ValueError(".zhcn metadata signature mismatch")
    stored_font = output[
        expected_raw + font_offset : expected_raw + font_offset + len(compressed_font)
    ]
    if stored_font != compressed_font:
        raise ValueError("embedded font stream mismatch")
    decompressed = stb_decompress(stored_font)
    check = TTFont(io.BytesIO(decompressed), lazy=False)
    check.close()
    return pe


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--translations", required=True, type=Path)
    parser.add_argument("--font", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    paths = {
        "input": args.input,
        "output": args.output,
        "translations": args.translations,
        "font": args.font,
    }
    if args.report is not None:
        paths["report"] = args.report
    validate_distinct_paths(paths)

    manifest = json.loads(args.translations.read_text(encoding="utf-8"))
    translations: dict[str, str] = manifest["ui"]
    validate_translation_table(translations)

    original = args.input.read_bytes()
    input_sha256 = sha256(original)
    target = manifest["target"]
    expected_input_sha256 = target["sha256"].upper()
    if input_sha256 != expected_input_sha256:
        raise ValueError(
            f"input SHA-256 does not match Pipsi-ZZZ {target['version']}: "
            f"{input_sha256} != {expected_input_sha256}"
        )

    font_bytes = args.font.read_bytes()
    font_sha256 = sha256(font_bytes)
    expected_font_sha256 = manifest["font"]["sha256"].upper()
    if font_sha256 != expected_font_sha256:
        raise ValueError(
            "font SHA-256 does not match the pinned localization font: "
            f"{font_sha256} != {expected_font_sha256}"
        )

    pe = pefile.PE(data=original, fast_load=False)
    if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        raise ValueError("input is not an x64 PE")
    if not pe.FILE_HEADER.IMAGE_FILE_DLL:
        raise ValueError("input is not a DLL")

    subset_font = build_font_subset(font_bytes, translations)
    compressed_font = stb_compress(subset_font)
    if stb_decompress(compressed_font) != subset_font:
        raise ValueError("font compression round-trip failed")

    payload, string_offsets, font_offset = build_section(translations, compressed_font)
    output, section_rva, section_raw, section_raw_size = add_section(original, pe, payload)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    target_vas = {
        source: image_base + section_rva + offset
        for source, offset in string_offsets.items()
    }

    translation_report, unsupported = patch_translations(
        output, original, pe, translations, target_vas
    )
    filter_preview_report = patch_filter_preview(
        output, original, pe, translations, target_vas
    )
    handled_inline = {
        ("Comic", filter_preview_report["comic_inline_reference"]),
    }
    remaining_unsupported = [
        item
        for item in unsupported
        if (item["source"], item["address"]) not in handled_inline
    ]
    if len(unsupported) - len(remaining_unsupported) != len(handled_inline):
        raise ValueError("expected Comic inline reference was not handled")
    translation_report["Comic"]["unsupported_xref"] -= 1
    unsupported = remaining_unsupported
    font_report = patch_default_fonts(
        output, original, pe, image_base + section_rva + font_offset
    )

    output_bytes = bytes(output)
    output_pe = validate_output(
        output_bytes,
        section_rva,
        section_raw,
        len(payload),
        font_offset,
        compressed_font,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output_bytes)

    report = {
        "input": args.input.name,
        "output": args.output.name,
        "target_version": target["version"],
        "input_sha256": input_sha256,
        "output_sha256": sha256(output_bytes),
        "input_size": len(original),
        "output_size": len(output_bytes),
        "translations": len(translations),
        "translation_references": translation_report,
        "unsupported_original_references": unsupported,
        "font": {
            "source": args.font.name,
            "source_sha256": font_sha256,
            "subset_size": len(subset_font),
            "compressed_size": len(compressed_font),
            "patched_default_paths": font_report,
        },
        "dynamic_filter_preview": filter_preview_report,
        "section": {
            "name": SECTION_NAME.decode("ascii"),
            "rva": f"0x{section_rva:X}",
            "raw_offset": f"0x{section_raw:X}",
            "virtual_size": len(payload),
            "raw_size": section_raw_size,
            "size_of_image": output_pe.OPTIONAL_HEADER.SizeOfImage,
        },
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
