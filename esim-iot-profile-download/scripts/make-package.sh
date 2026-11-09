#!/usr/bin/env bash
# 生成可上传的技能包 ZIP（只含入库文件，排除 .venv/__pycache__/测试日志）
#
# 用法:
#   bash scripts/make-package.sh                 # 输出到 <仓库外>/esim-iot-profile-download.zip
#   OUT=/tmp/pkg.zip bash scripts/make-package.sh
#
# 为什么需要它：桌面端「上传技能」对整包有硬限制——
#   ≤128 个文件、单文件 ≤2MB、总量 ≤6MB、路径深度 ≤16、不得含软链/特殊文件。
#   开发目录里带 .venv（uv 环境，400+ 文件且含软链）与 __pycache__ 时会直接超限，
#   报「技能包无效」。git archive 只打包已提交文件，天然满足这些限制。

set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$PACKAGE_DIR/.." && pwd)"
NAME="$(basename "$PACKAGE_DIR")"
OUT="${OUT:-$(dirname "$REPO_DIR")/$NAME.zip}"

cd "$REPO_DIR"
git archive --format=zip -o "$OUT" HEAD "$NAME"

echo "[make-package] 技能包: $NAME"
python3 - "$OUT" <<'PY'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
files = [i for i in z.infolist() if not i.is_dir()]
total = sum(i.file_size for i in files)
print(f"[make-package] 文件数: {len(files)}（限制 128）")
print(f"[make-package] 解压体积: {total/1024:.0f} KB（限制 6MB）")
print(f"[make-package] 最大单文件: {max(i.file_size for i in files)/1024:.0f} KB（限制 2MB）")
roots = sorted({n.filename.split('/')[0] for n in z.infolist() if n.filename.strip('/')})
print(f"[make-package] 顶层目录: {roots}")
ok = (len(files) <= 128 and total <= 6*1024*1024
      and max(i.file_size for i in files) <= 2*1024*1024
      and any(f.filename.endswith('/SKILL.md') for f in files)
      and not any('.venv' in f.filename or '__pycache__' in f.filename for f in files))
print("[make-package] 符合上传限制:", "是" if ok else "否")
sys.exit(0 if ok else 1)
PY
echo "[make-package] 输出: $OUT"
