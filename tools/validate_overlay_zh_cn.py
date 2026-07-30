#!/usr/bin/env python3
"""Independently validate the static Pipsi-ZZZ zh-CN PE patch.

This script parses files as data only. It never loads or executes either PE.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from fontTools.ttLib import TTFont

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stb_compress import decompress as stb_decompress  # noqa: E402


SECTION_NAME = b".zhcn"
SECTION_MAGIC = b"PIPSIZH\x00"
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_REL_BASED_DIR64 = 10


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def all_occurrences(data: bytes, needle: bytes):
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return
        yield offset
        start = offset + 1


def decode_instructions(pe: pefile.PE):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if not section.IMAGE_SCN_MEM_EXECUTE:
            continue
        for instruction in decoder.disasm(
            section.get_data(), base + section.VirtualAddress
        ):
            if instruction.id:
                yield instruction


def rip_targets(instruction):
    for operand in instruction.operands:
        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
            yield instruction.address + instruction.size + operand.mem.disp


def relocation_rvas(pe: pefile.PE) -> set[int]:
    result: set[int] = set()
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if entry.type == IMAGE_REL_BASED_DIR64:
                result.add(entry.rva)
    return result


def original_string_vas(
    original: bytes, pe: pefile.PE, translations: dict[str, str]
) -> dict[int, str]:
    result: dict[int, str] = {}
    base = pe.OPTIONAL_HEADER.ImageBase
    for source in translations:
        for offset in all_occurrences(original, source.encode("ascii") + b"\x00"):
            try:
                result[base + pe.get_rva_from_offset(offset)] = source
            except pefile.PEFormatError:
                pass
    return result


def instruction_at(pe: pefile.PE, va: int):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    offset = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
    data = pe.__data__[offset : offset + 16]
    decoded = list(decoder.disasm(data, va, count=1))
    require(bool(decoded), f"cannot decode instruction at 0x{va:X}")
    return decoded[0]


def directory_signature(pe: pefile.PE, data: bytes):
    result = []
    for index, entry in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        rva, size = entry.VirtualAddress, entry.Size
        content_hash = None
        if rva and size and index != pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]:
            try:
                offset = pe.get_offset_from_rva(rva)
                content_hash = digest(data[offset : offset + size])
            except pefile.PEFormatError:
                content_hash = "unmapped"
        result.append((rva, size, content_hash))
    return result


def import_signature(pe: pefile.PE):
    return [
        (
            entry.dll,
            tuple((symbol.name, symbol.ordinal, symbol.hint) for symbol in entry.imports),
        )
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    ]


def export_signature(pe: pefile.PE):
    exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exports is None:
        return []
    return [
        (symbol.name, symbol.ordinal, symbol.address, symbol.forwarder)
        for symbol in exports.symbols
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("localized", type=Path)
    parser.add_argument("--translations", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    original = args.original.read_bytes()
    localized = args.localized.read_bytes()
    manifest = json.loads(args.translations.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    translations: dict[str, str] = manifest["ui"]

    target = manifest["target"]
    require(
        digest(original) == target["sha256"].upper(),
        f"original hash does not match Pipsi-ZZZ {target['version']}",
    )
    require(digest(original) == report["input_sha256"], "original hash mismatch")
    require(digest(localized) == report["output_sha256"], "localized hash mismatch")
    require(len(translations) == report["translations"], "translation count mismatch")

    original_pe = pefile.PE(data=original, fast_load=False)
    localized_pe = pefile.PE(data=localized, fast_load=False)
    require(
        localized_pe.FILE_HEADER.NumberOfSections
        == original_pe.FILE_HEADER.NumberOfSections + 1,
        "localized PE must add exactly one section",
    )
    require(
        directory_signature(original_pe, original)
        == directory_signature(localized_pe, localized),
        "a PE data directory or its contents changed",
    )
    require(
        import_signature(original_pe) == import_signature(localized_pe),
        "import table changed",
    )
    require(
        export_signature(original_pe) == export_signature(localized_pe),
        "export table changed",
    )

    for before, after in zip(original_pe.sections, localized_pe.sections):
        require(before.__pack__() == after.__pack__(), f"section header changed: {before.Name!r}")

    matching = [
        section
        for section in localized_pe.sections
        if section.Name.rstrip(b"\x00") == SECTION_NAME
    ]
    require(len(matching) == 1, "expected exactly one .zhcn section")
    section = matching[0]
    required_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    require(
        section.Characteristics & required_flags == required_flags,
        ".zhcn is not initialized read-only data",
    )
    require(not section.Characteristics & IMAGE_SCN_MEM_EXECUTE, ".zhcn is executable")
    require(not section.Characteristics & IMAGE_SCN_MEM_WRITE, ".zhcn is writable")

    raw = section.PointerToRawData
    payload = localized[raw : raw + section.Misc_VirtualSize]
    require(len(payload) == section.Misc_VirtualSize, ".zhcn payload is truncated")
    magic, version, count, strings_at, font_at, font_size, reserved = struct.unpack_from(
        "<8sIIIIII", payload, 0
    )
    require(magic == SECTION_MAGIC, ".zhcn signature mismatch")
    require(version == 1 and reserved == 0, ".zhcn metadata version mismatch")
    require(count == len(translations), ".zhcn string count mismatch")
    require(strings_at == 0x20, ".zhcn string table offset mismatch")
    require(font_at + font_size == len(payload), ".zhcn font bounds mismatch")

    string_vas: dict[str, int] = {}
    cursor = strings_at
    image_base = localized_pe.OPTIONAL_HEADER.ImageBase
    for source, expected in translations.items():
        end = payload.index(0, cursor)
        actual = payload[cursor:end].decode("utf-8", errors="strict")
        require(actual == expected, f"embedded translation mismatch for {source!r}")
        string_vas[source] = image_base + section.VirtualAddress + cursor
        cursor = end + 1
    require(cursor <= font_at, "string table overlaps font stream")
    require(not any(payload[cursor:font_at]), "non-zero data in string/font alignment gap")

    compressed_font = payload[font_at : font_at + font_size]
    font_data = stb_decompress(compressed_font)
    font = TTFont(io.BytesIO(font_data), lazy=False)
    cmap: set[int] = set()
    for table in font["cmap"].tables:
        cmap.update(table.cmap)
    name_values: dict[int, list[str]] = defaultdict(list)
    for record in font["name"].names:
        if record.nameID in (0, 13, 14):
            name_values[record.nameID].append(record.toUnicode())
    require(
        any("Adobe" in value for value in name_values[0]),
        "font copyright record is missing",
    )
    require(
        any("SIL Open Font License" in value for value in name_values[13]),
        "font SIL OFL license record is missing",
    )
    require(
        any("scripts.sil.org/OFL" in value for value in name_values[14]),
        "font SIL OFL URL record is missing",
    )
    font.close()
    required_codepoints = set(range(0x20, 0x7F)) | set(range(0xA0, 0x100)) | {0x2026}
    for target in translations.values():
        required_codepoints.update(ord(char) for char in target if ord(char) >= 0x20)
    missing = sorted(required_codepoints - cmap)
    require(not missing, "font lacks required glyphs: " + ", ".join(f"U+{v:04X}" for v in missing))

    # Validate every special machine-code edit required by the dynamically
    # assembled Auto Skip filter preview. These paths use raw byte counts, so a
    # normal literal-reference check alone cannot prove UTF-8 safety.
    def expect_bytes(va: int, expected: bytes) -> None:
        offset = localized_pe.get_offset_from_rva(va - image_base)
        actual = localized[offset : offset + len(expected)]
        require(
            actual == expected,
            f"dynamic filter patch mismatch at 0x{va:X}: "
            f"{actual.hex()} != {expected.hex()}",
        )

    dynamic_expected = {
        "Comic": ("漫画", 6),
        "Cutscene": ("过场动画", 12),
        "Dialogue": ("对话", 6),
        "Galge": ("视觉小说", 12),
    }
    for source, (target, byte_count) in dynamic_expected.items():
        require(translations[source] == target, f"unexpected dynamic label for {source}")
        require(len(target.encode("utf-8")) == byte_count, f"bad UTF-8 length for {source}")

    baseline_comic_reference = 0x180002C6D
    original_comic_targets = original_string_vas(
        original, original_pe, {"Comic": translations["Comic"]}
    )
    original_comic_inline_refs = []
    for instruction in decode_instructions(original_pe):
        if instruction.mnemonic == "lea":
            continue
        if set(rip_targets(instruction)).intersection(original_comic_targets):
            original_comic_inline_refs.append(instruction.address)
    require(
        len(original_comic_inline_refs) == 1,
        "original must have exactly one inline Comic reference",
    )
    comic_inline_reference = original_comic_inline_refs[0]
    reported_comic_reference = int(
        report["dynamic_filter_preview"]["comic_inline_reference"], 16
    )
    require(
        reported_comic_reference == comic_inline_reference,
        "dynamic filter profile address mismatch",
    )
    profile_address_delta = comic_inline_reference - baseline_comic_reference

    def profile_va(baseline_va: int) -> int:
        return baseline_va + profile_address_delta

    expect_bytes(
        profile_va(0x180002C65),
        b"\x48\xC7\x45\xCF\x06\x00\x00\x00",
    )
    comic_first = instruction_at(localized_pe, profile_va(0x180002C6D))
    require(
        list(rip_targets(comic_first)) == [string_vas["Comic"]],
        "Comic first inline load does not target its translation",
    )
    comic_second = instruction_at(localized_pe, profile_va(0x180002C76))
    require(comic_second.mnemonic == "movzx", "Comic second load is not movzx")
    require(
        list(rip_targets(comic_second)) == [string_vas["Comic"] + 4],
        "Comic second inline load does not target its final UTF-8 bytes",
    )
    expect_bytes(profile_va(0x180002C7D), b"\x89\x45\xC3")
    expect_bytes(profile_va(0x180002C80), b"\x44\x88\x7D\xC5")

    expect_bytes(profile_va(0x180002CF7), b"\xEB\x2A")
    expect_bytes(
        profile_va(0x180002D23),
        b"\x48\xC7\x44\x24\x20\x0C\x00\x00\x00",
    )
    expect_bytes(profile_va(0x180002D33), b"\xBA\x0C\x00\x00\x00")
    cutscene_source = instruction_at(localized_pe, profile_va(0x180002D2C))
    require(
        list(rip_targets(cutscene_source)) == [string_vas["Cutscene"]],
        "Cutscene growth path does not use its translation",
    )

    expect_bytes(profile_va(0x180002DC3), b"\xEB\x2A")
    expect_bytes(
        profile_va(0x180002DEF),
        b"\x48\xC7\x44\x24\x20\x06\x00\x00\x00",
    )
    expect_bytes(profile_va(0x180002DFF), b"\xBA\x06\x00\x00\x00")
    dialogue_source = instruction_at(localized_pe, profile_va(0x180002DF8))
    require(
        list(rip_targets(dialogue_source)) == [string_vas["Dialogue"]],
        "Dialogue growth path does not use its translation",
    )

    expect_bytes(profile_va(0x180002E84), b"\x48\x83\xF8\x0C")
    expect_bytes(profile_va(0x180002E8A), b"\x48\x8D\x42\x0C")
    expect_bytes(profile_va(0x180002EA2), b"\x41\xB8\x0C\x00\x00\x00")
    expect_bytes(profile_va(0x180002EB7), b"\xC6\x43\x0C\x00")
    expect_bytes(
        profile_va(0x180002EBD),
        b"\x48\xC7\x44\x24\x20\x0C\x00\x00\x00",
    )
    expect_bytes(profile_va(0x180002ECD), b"\xBA\x0C\x00\x00\x00")
    for va in (0x180002EA8, 0x180002EC6):
        adjusted_va = profile_va(va)
        galge_source = instruction_at(localized_pe, adjusted_va)
        require(
            list(rip_targets(galge_source)) == [string_vas["Galge"]],
            f"Galge path at 0x{adjusted_va:X} does not use its translation",
        )

    expect_bytes(profile_va(0x180002EE3), b"\x48\x83\xFA\x2A")
    labels = [translations[source] for source in dynamic_expected]
    preview_lengths = []
    for mask in range(1 << len(labels)):
        preview = ", ".join(
            label for index, label in enumerate(labels) if mask & (1 << index)
        )
        encoded = preview.encode("utf-8", errors="strict")
        encoded.decode("utf-8", errors="strict")
        preview_lengths.append(len(encoded))
    require(max(preview_lengths) == 42, "dynamic filter maximum is not 42 bytes")
    require(
        report["dynamic_filter_preview"]["max_preview_utf8_bytes"] == 42,
        "dynamic filter report mismatch",
    )

    # These names are Unity input-axis identifiers, not menu labels. Translating
    # either would make the free-camera mouse lookup fail even though the text
    # looks user-facing in a raw string scan.
    preserved = set(manifest.get("preserve", []))
    localized_instruction_list = list(decode_instructions(localized_pe))
    localized_instruction_by_va = {
        instruction.address: instruction for instruction in localized_instruction_list
    }
    for expected in ("Mouse X", "Mouse Y"):
        require(expected not in translations, f"engine identifier translated: {expected}")
        require(expected in preserved, f"engine identifier not documented: {expected}")
        engine_targets = original_string_vas(
            localized, localized_pe, {expected: expected}
        )
        references = [
            instruction
            for instruction in localized_instruction_list
            if set(rip_targets(instruction)).intersection(engine_targets)
        ]
        require(
            len(references) == 1,
            f"expected one engine identifier reference for {expected}",
        )
        instruction = references[0]
        targets = list(rip_targets(instruction))
        require(
            len(targets) == 1,
            f"engine identifier reference missing at 0x{instruction.address:X}",
        )
        rva = targets[0] - image_base
        actual = localized_pe.get_data(rva, len(expected) + 1)
        require(actual == expected.encode("ascii") + b"\x00", f"engine identifier changed: {expected}")
        original_instruction = instruction_at(original_pe, instruction.address)
        require(
            instruction.bytes == original_instruction.bytes,
            f"engine identifier instruction changed: {expected}",
        )
        nearby = [
            item
            for item in localized_instruction_list
            if instruction.address < item.address <= instruction.address + 0x30
        ]
        has_length_seven = any(
            item.mnemonic == "mov" and item.op_str == "edx, 7" for item in nearby
        )
        require(has_length_seven, f"engine identifier length changed: {expected}")

    # ImGui 1.92 dynamically loads glyphs only when renderer backends advertise
    # texture updates. Verify both bundled renderers set the 0x18 flag
    # (RendererHasTextures | RendererHasVtxOffset) near their backend-name setup.
    require(
        b"Dear ImGui 1.92.7 (19270)\x00" in localized,
        "unexpected Dear ImGui version",
    )
    dynamic_font_backends = 0
    for backend_name in ("imgui_impl_dx11", "imgui_impl_dx12"):
        backend_targets = original_string_vas(
            localized, localized_pe, {backend_name: backend_name}
        )
        backend_refs = [
            instruction
            for instruction in localized_instruction_list
            if instruction.mnemonic == "lea"
            and set(rip_targets(instruction)).intersection(backend_targets)
        ]
        require(len(backend_refs) == 1, f"backend marker not unique: {backend_name}")
        marker_va = backend_refs[0].address
        nearby = [
            item
            for item in localized_instruction_list
            if marker_va <= item.address <= marker_va + 0x30
        ]
        supports_dynamic_textures = any(
            item.mnemonic == "or"
            and any(
                operand.type == X86_OP_IMM and operand.imm == 0x18
                for operand in item.operands
            )
            for item in nearby
        )
        require(
            supports_dynamic_textures,
            f"{backend_name} does not advertise dynamic font textures",
        )
        dynamic_font_backends += 1

    rip_lea_counts: dict[str, int] = defaultdict(int)
    font_va = image_base + section.VirtualAddress + font_at
    font_refs: list[int] = []
    target_to_source = {value: key for key, value in string_vas.items()}
    old_targets = original_string_vas(original, original_pe, translations)
    remaining_old_refs: list[tuple[str, int, str]] = []
    for instruction in decode_instructions(localized_pe):
        for target in rip_targets(instruction):
            source = target_to_source.get(target)
            if source is not None and instruction.mnemonic == "lea":
                rip_lea_counts[source] += 1
            if target == font_va:
                require(instruction.mnemonic == "lea", "font target uses a non-LEA reference")
                font_refs.append(instruction.address)
            old_source = old_targets.get(target)
            if old_source is not None:
                remaining_old_refs.append(
                    (old_source, instruction.address, f"{instruction.mnemonic} {instruction.op_str}")
                )

    relocations = relocation_rvas(localized_pe)
    pointer_counts: dict[str, int] = defaultdict(int)
    remaining_old_pointers: list[tuple[str, int]] = []
    for source, target in string_vas.items():
        for offset in all_occurrences(localized, struct.pack("<Q", target)):
            try:
                rva = localized_pe.get_rva_from_offset(offset)
            except pefile.PEFormatError:
                continue
            if rva in relocations:
                pointer_counts[source] += 1
    for old_va, source in old_targets.items():
        for offset in all_occurrences(localized, struct.pack("<Q", old_va)):
            try:
                rva = localized_pe.get_rva_from_offset(offset)
            except pefile.PEFormatError:
                continue
            if rva in relocations:
                remaining_old_pointers.append((source, rva))

    for source, expected_counts in report["translation_references"].items():
        require(
            rip_lea_counts[source] == expected_counts["rip_lea"],
            f"RIP reference count mismatch for {source!r}",
        )
        require(
            pointer_counts[source] == expected_counts["relocated_pointer"],
            f"pointer reference count mismatch for {source!r}",
        )
        require(
            rip_lea_counts[source] + pointer_counts[source] > 0,
            f"no localized UI reference for {source!r}",
        )
    require(not remaining_old_pointers, "an old relocated string pointer remains")

    expected_remaining = [
        (
            item["source"],
            int(item["address"], 16),
            item["instruction"],
        )
        for item in report["unsupported_original_references"]
    ]
    require(
        remaining_old_refs == expected_remaining,
        f"unexpected original string references remain: {remaining_old_refs!r}",
    )
    expected_font_refs = sorted(
        int(item["instruction"], 16) for item in report["font"]["patched_default_paths"]
    )
    require(sorted(font_refs) == expected_font_refs, "default font references mismatch")

    # Prove that every changed byte inside the original file span belongs to a
    # documented header, reference, font, or dynamic-preview edit. The new
    # localization payload itself starts at the old end of file.
    allowed_changes: set[int] = set()

    def allow_file_range(offset: int, size: int) -> None:
        allowed_changes.update(range(offset, offset + size))

    allow_file_range(
        original_pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"), 2
    )
    allow_file_range(
        original_pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfInitializedData"),
        4,
    )
    allow_file_range(
        original_pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"), 4
    )
    section_table = (
        original_pe.DOS_HEADER.e_lfanew
        + 4
        + original_pe.FILE_HEADER.sizeof()
        + original_pe.FILE_HEADER.SizeOfOptionalHeader
    )
    allow_file_range(
        section_table + original_pe.FILE_HEADER.NumberOfSections * 40,
        40,
    )

    for instruction in decode_instructions(original_pe):
        if instruction.mnemonic != "lea" or instruction.disp_size != 4:
            continue
        if not set(rip_targets(instruction)).intersection(old_targets):
            continue
        offset = original_pe.get_offset_from_rva(instruction.address - image_base)
        allow_file_range(offset + instruction.disp_offset, instruction.disp_size)

    old_relocations = relocation_rvas(original_pe)
    for old_va in old_targets:
        for offset in all_occurrences(original, struct.pack("<Q", old_va)):
            try:
                rva = original_pe.get_rva_from_offset(offset)
            except pefile.PEFormatError:
                continue
            if rva in old_relocations:
                allow_file_range(offset, 8)

    for va in expected_font_refs:
        instruction = instruction_at(original_pe, va)
        require(instruction.disp_size == 4, f"font instruction has no disp32 at 0x{va:X}")
        offset = original_pe.get_offset_from_rva(va - image_base)
        allow_file_range(offset + instruction.disp_offset, instruction.disp_size)

    dynamic_ranges = tuple(
        (profile_va(va), size)
        for va, size in (
        (0x180002C65, 8),
        (0x180002C6D, 6),
        (0x180002C76, 7),
        (0x180002C7D, 3),
        (0x180002C80, 4),
        (0x180002CF7, 1),
        (0x180002D23, 9),
        (0x180002D33, 5),
        (0x180002DC3, 1),
        (0x180002DEF, 9),
        (0x180002DFF, 5),
        (0x180002E84, 4),
        (0x180002E8A, 4),
        (0x180002EA2, 6),
        (0x180002EB7, 4),
        (0x180002EBD, 9),
        (0x180002ECD, 5),
        (0x180002EE3, 4),
        )
    )
    for va, size in dynamic_ranges:
        allow_file_range(original_pe.get_offset_from_rva(va - image_base), size)

    require(
        section.PointerToRawData >= len(original),
        ".zhcn overlaps the original file span",
    )
    changed = {
        offset
        for offset, (before, after) in enumerate(zip(original, localized))
        if before != after
    }
    unexpected_changes = sorted(changed - allowed_changes)
    require(
        not unexpected_changes,
        "undocumented changes in original file span: "
        + ", ".join(f"0x{offset:X}" for offset in unexpected_changes[:16]),
    )

    summary = {
        "ok": True,
        "original_sha256": digest(original),
        "localized_sha256": digest(localized),
        "translations": len(translations),
        "localized_rip_references": sum(rip_lea_counts.values()),
        "localized_pointer_references": sum(pointer_counts.values()),
        "intentional_internal_english_references": len(remaining_old_refs),
        "default_font_references": len(font_refs),
        "dynamic_filter_combinations": len(preview_lengths),
        "dynamic_filter_max_utf8_bytes": max(preview_lengths),
        "dynamic_filter_address_delta": f"0x{profile_address_delta:X}",
        "preserved_engine_identifiers": 2,
        "dynamic_font_backends": dynamic_font_backends,
        "font_uncompressed_bytes": len(font_data),
        "font_compressed_bytes": len(compressed_font),
        "required_font_codepoints": len(required_codepoints),
        "font_license_records_preserved": True,
        "pe_directories_preserved": len(original_pe.OPTIONAL_HEADER.DATA_DIRECTORY),
        "documented_changed_bytes_in_original_span": len(changed),
        "undocumented_changed_bytes": len(unexpected_changes),
        "new_section": {
            "name": SECTION_NAME.decode("ascii"),
            "rva": f"0x{section.VirtualAddress:X}",
            "raw_offset": f"0x{section.PointerToRawData:X}",
            "virtual_size": section.Misc_VirtualSize,
            "characteristics": f"0x{section.Characteristics:08X}",
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
