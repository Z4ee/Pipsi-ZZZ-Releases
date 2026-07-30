# Pipsi-ZZZ 0.6.2 zh-CN static validation

The localized output was generated and audited without loading or executing
the original or patched PE files.

| Item | Result |
| --- | --- |
| Original `Cheat.dll` SHA-256 | `1CBA50A52796FA6BAD65A89457DB4DA0E7AF973726E277D376225EE0858FC5FE` |
| Localized `Cheat.dll` SHA-256 | `4C024A0E4BEA2AF7E9CA1EF5A547531DBBE2B5EF0A9EB910D8197E3EF4E0A2A9` |
| Translated visible strings | 88 / 88 |
| RIP-relative string references | 131 |
| Relocated string pointers | 9 |
| Unsupported live references | 0 |
| Default-font paths redirected | 2 / 2 |
| Required font code points missing | 0 |
| Unexpected original-file changes | 0 |

Structural checks:

- Added exactly one `.zhcn` section.
- `.zhcn` is initialized, read-only data and is neither writable nor
  executable.
- All 16 PE data directories and their contents are unchanged.
- Existing section headers, imports, exports, and non-target sections are
  unchanged.
- The embedded font subset retains its Adobe copyright, SIL OFL license, and
  license URL records.
- All 469 edits inside the original file range are covered by the explicit
  header, reference, font, or filter-preview allowlist.
- The longest translated Auto Skip preview is 42 UTF-8 bytes and its length
  handling was checked for every filter combination.

This repository intentionally does not include either binary. The hashes are
provided so maintainers can reproduce and compare the audited result locally.
