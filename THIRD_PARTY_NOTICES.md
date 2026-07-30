# Third-party notices

This source-only localization workflow relies on or produces data derived from
the following third-party projects:

- `tools/stb_compress.py` is a Python port of the `stb_compress` format and
  matching algorithm shipped in Dear ImGui v1.92.7's
  `misc/fonts/binary_to_compressed_c.cpp`. See
  `licenses/DEAR-IMGUI-MIT.txt` and `licenses/STB-MIT.txt`.
- A generated localization DLL contains a subset of the user-supplied Noto
  Sans SC font. That subset remains under the SIL Open Font License 1.1. See
  `licenses/NOTO-SANS-SC-OFL-1.1.txt`.

The font file itself is not included in this repository. Anyone distributing
a generated DLL must provide the Noto Sans SC copyright notice and OFL text
with that DLL.
