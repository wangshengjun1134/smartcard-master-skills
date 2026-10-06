#!/usr/bin/env bash
# 建立技能「自带」执行环境（技能自己维护，uv 优先）
#
# 用法:
#   bash scripts/setup-env.sh                  # uv 优先；无 uv 时回退 python venv + pip
#   PYTHON_SPEC=3.12 bash scripts/setup-env.sh # 指定 Python 版本（uv 可自行下载该版本）
#   VENV_DIR=/opt/esim-env bash scripts/setup-env.sh
#
# 说明:
#   - 环境目录默认 <技能包>/.venv，由 main.py 入口自动检测并切换解释器
#     （也可用 ESIM_SKILL_VENV 指定其他位置）
#   - 该目录不入库/不打包（.gitignore 已忽略 venv/ 与 .venv/）
#   - 推荐安装 uv（也可由 main.py 的 operation=setup_env 触发同样的安装）
#       curl -LsSf https://astral.sh/uv/install.sh | sh

set -euo pipefail

PACKAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${VENV_DIR:-$PACKAGE_DIR/.venv}"
PYTHON_SPEC="${PYTHON_SPEC:-}"
REQUIREMENTS="$PACKAGE_DIR/requirements.txt"

echo "[setup-env] 技能包: $PACKAGE_DIR"
echo "[setup-env] 环境目录: $VENV_DIR"

if command -v uv >/dev/null 2>&1; then
  echo "[setup-env] 使用 uv: $(uv --version)"
  if [ -n "$PYTHON_SPEC" ]; then
    uv venv "$VENV_DIR" --python "$PYTHON_SPEC" \
      || { echo "[setup-env] 指定版本不可用，改用 uv 自动选择解释器"; uv venv "$VENV_DIR"; }
  else
    uv venv "$VENV_DIR"
  fi
  VENV_PYTHON="$VENV_DIR/bin/python"
  [ -x "$VENV_PYTHON" ] || VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
  uv pip install --python "$VENV_PYTHON" -r "$REQUIREMENTS"
else
  echo "[setup-env] 未找到 uv，回退 python venv + pip"
  echo "[setup-env] 建议安装 uv 以获得更快的环境安装： curl -LsSf https://astral.sh/uv/install.sh | sh"
  PYTHON="${PYTHON:-python3}"
  "$PYTHON" -m venv "$VENV_DIR"
  VENV_PYTHON="$VENV_DIR/bin/python"
  [ -x "$VENV_PYTHON" ] || VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
  "$VENV_PYTHON" -m pip install --upgrade pip
  "$VENV_PYTHON" -m pip install -r "$REQUIREMENTS"
fi

if [ ! -x "$VENV_PYTHON" ]; then
  echo "[setup-env] 未找到环境解释器，安装可能失败" >&2
  exit 1
fi

echo "[setup-env] 校验依赖:"
"$VENV_PYTHON" -c "import cryptography, pyasn1, sys; print('  ok:', sys.executable, sys.version.split()[0])"

echo "[setup-env] 完成。main.py 入口会自动使用该环境（可用 ESIM_SKILL_VENV 覆盖路径）。"
