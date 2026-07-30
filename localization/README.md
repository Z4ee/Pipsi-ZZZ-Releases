# Simplified Chinese localization / 简体中文汉化

This directory contains the reviewable source for the Simplified Chinese
overlay localization tested with Pipsi-ZZZ 0.6.2. It does not contain or
redistribute the game overlay, launcher, release archive, or font binaries.

本目录提供经 Pipsi-ZZZ 0.6.2 测试的简体中文覆盖层汉化源文件，便于原作者逐项审查。
仓库中不包含、也不重新分发覆盖层 DLL、启动器、发布压缩包或字体二进制。

## Contents / 内容

- `zh-CN.json`: 88 visible overlay strings and identifiers that must remain
  unchanged.
- `../tools/patch_overlay_zh_cn.py`: parses the x64 PE as data, appends one
  read-only `.zhcn` section, redirects existing UI references, and embeds a
  locally supplied CJK font subset.
- `../tools/validate_overlay_zh_cn.py`: independently checks PE structure,
  translations, references, font coverage, and the exact patch allowlist.
- `../tools/stb_compress.py`: compatible compressor/decompressor for Dear
  ImGui's embedded-font stream.
- `VALIDATION-0.6.2.md`: static validation results for the tested build.
- `../THIRD_PARTY_NOTICES.md` and `../licenses/`: notices and license texts
  for the compression algorithm and generated font subset.

## Build / 生成

Requirements: Python 3.11 or newer, the original 0.6.2 `Cheat.dll`, and a
locally supplied copy of the pinned Noto Sans SC variable font. The input DLL
and font are read as data and are never loaded or executed.

需要 Python 3.11 或更高版本、原版 0.6.2 `Cheat.dll`，以及用户自行提供的
下方指定版本的 Noto Sans SC 可变字体。脚本只把 DLL 和字体作为数据读取，
不会加载或执行它们。

Verify the original 0.6.2 DLL before generating the localization:

生成汉化前，请先核对原版 0.6.2 DLL：

```powershell
Get-FileHash -Algorithm SHA256 path\to\Cheat.dll
```

Expected SHA-256:
`1CBA50A52796FA6BAD65A89457DB4DA0E7AF973726E277D376225EE0858FC5FE`

Pinned font source:
[`NotoSansSC[wght].ttf`](https://github.com/google/fonts/blob/ec0464b978de222073645d6d3366f3fdf03376d8/ofl/notosanssc/NotoSansSC%5Bwght%5D.ttf)
from Google Fonts commit
`ec0464b978de222073645d6d3366f3fdf03376d8`.

Expected font SHA-256:
`A3041811A78C361B1DE50F953C805E0244951C21C5BD412F7232EF0D899AF0DA`

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-localization.txt

.\.venv\Scripts\python.exe tools\patch_overlay_zh_cn.py `
  path\to\Cheat.dll build\Cheat.zh-CN.dll `
  --translations localization\zh-CN.json `
  --font "path\to\NotoSansSC[wght].ttf" `
  --report build\localization-report.json

.\.venv\Scripts\python.exe tools\validate_overlay_zh_cn.py `
  path\to\Cheat.dll build\Cheat.zh-CN.dll `
  --translations localization\zh-CN.json `
  --report build\localization-report.json
```

## Safety and scope / 安全与范围

- No DLL, EXE, ZIP, TTF, or OTF file is included in this contribution.
- The patcher verifies both the exact 0.6.2 DLL and pinned font SHA-256 before
  editing any data, and refuses colliding input/output/report paths.
- The patcher fails closed if the expected x64 PE layout, UI references,
  filter-preview code, or the two Dear ImGui default-font paths differ.
- The output adds initialized read-only data only; the new section is neither
  writable nor executable.
- Validation is static. The localized build has not been executed in game.

- 本提交不包含 DLL、EXE、ZIP、TTF 或 OTF 文件。
- 补丁器在修改数据前会强制核对 0.6.2 DLL 与固定字体的 SHA-256，并拒绝
  输入、输出和报告路径互相覆盖。
- 如果 x64 PE 布局、界面引用、自动跳过预览逻辑或两条 ImGui 默认字体路径与
  预期不符，补丁器会立即停止。
- 输出仅新增只读初始化数据；新节不可写、不可执行。
- 当前结果仅经过静态校验，尚未在游戏内运行测试。

The generated font subset remains under the SIL Open Font License 1.1. If a
generated DLL is redistributed, keep `THIRD_PARTY_NOTICES.md` and
`licenses/NOTO-SANS-SC-OFL-1.1.txt` with it.

生成的字体子集仍受 SIL Open Font License 1.1 约束。若分发生成的 DLL，
必须同时附带 `THIRD_PARTY_NOTICES.md` 与
`licenses/NOTO-SANS-SC-OFL-1.1.txt`。
