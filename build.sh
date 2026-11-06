#!/usr/bin/env bash
# Собирает один файл awg-cascade.sh: подставляет публичный ключ репозитория Amnezia.
# Запуск: build.sh [ФАЙЛ_КЛЮЧА]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
python3 -I - "$here/awg-cascade.sh.in" "${1:-$here/packaging/amnezia-ppa.key}" "$here/awg-cascade.sh" <<'PY'
import sys
src, key, out = sys.argv[1:4]
text = open(src, encoding="utf-8").read()
k = open(key, encoding="utf-8").read().strip()
assert text.count("@@PPA_KEY@@") == 1
text = text.replace("@@ZVER@@", "1.0.7").replace("@@ZSHA@@", "547a5dce3f4820721a425680ea3f7f3971b7e9c772b8c795dd2d623148da0928")
open(out, "w", encoding="utf-8", newline="\n").write(text.replace("@@PPA_KEY@@", k))
PY
chmod 755 "$here/awg-cascade.sh"
(cd "$here/panel" && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o "$here/awg-cascade-panel" .)
