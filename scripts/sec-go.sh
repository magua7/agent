#!/usr/bin/env sh
set -eu

SEC_GO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$SEC_GO_ROOT/src"

if [ -x "$SEC_GO_ROOT/.venv/bin/python" ]; then
  SEC_GO_PYTHON="$SEC_GO_ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  SEC_GO_PYTHON=python3
else
  SEC_GO_PYTHON=python
fi

"$SEC_GO_PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "SEC-GO requires Python 3.11 or newer." >&2
  exit 2
}

cd "$SEC_GO_ROOT"
exec "$SEC_GO_PYTHON" -m security_agent.interfaces.product_cli "$@"
