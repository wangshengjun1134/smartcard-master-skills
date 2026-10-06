#!/usr/bin/env bash
# 为技能准备「自带」Python 运行环境（Runtime 不管理依赖，见 SKILL.md「运行环境」）
#
# 用法:
#   bash scripts/setup-venv.sh              # 创建 <技能包>/.venv 并安装运行依赖
#   PYTHON=python3.12 bash scripts/setup-venv.sh
#
# 说明:
#   - 生成的环境在技能包内（<技能包>/.venv），由 main.py 入口自动检测并切换解释器
#   - 该目录不应打包/入库（.gitignore 已忽略 venv/ 与 .venv/）
#   - Windows 等价命令（PowerShell）:
#       python -m venv .venv
#       .venv\Scripts\python -m pip install -r requirements.txt

set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-$PACKAGE_DIR/.venv}"
REQUIREMENTS="$PACKAGE_DIR/requirements.txt"

echo "[setup-venv] 技能包: $PACKAGE_DIR"
echo "[setup-venv] 解释器: $($PYTHON -V 2>&1)"
echo "[setup-venv] 环境目录: $VENV_DIR"

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON" -m venv "$VENV_DIR"
else
  echo "[setup-venv] 复用已存在的环境"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
if [ ! -x "$VENV_PYTHON" ]; then
  VENV_PYTHON="$VENV_DIR/Scripts/python.exe"   # Windows (Git Bash)
fi
if [ ! -x "$VENV_PYTHON" ]; then
  echo "[setup-venv] 未找到虚拟环境解释器，环境可能创建失败" >&2
  exit 1
fi

"$VENV_PYTHON" -m pip install --upgrade pip
"$VENV_PYTHON" -m pip install -r "$REQUIREMENTS"

echo "[setup-venv] 校验依赖:"
"$VENV_PYTHON" -c "import cryptography, pyasn1, sys; print('  ok:', sys.executable)"

echo "[setup-venv] 完成。main.py 会自动检测并使用该环境（可用 ESIM_SKILL_VENV 覆盖路径）。"
