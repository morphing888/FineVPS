#!/usr/bin/env bash
# Установка каскада одной командой, запускается на сервере 1:
#   curl -fsSL https://raw.githubusercontent.com/morphing888/FineVPS/main/install.sh | sudo bash
# Повторный запуск обновляет программу и сохраняет настройки.
# Весь код внутри функции: bash читает этот файл из канала и не должен запускать его частично.
set -euo pipefail

main() {
    local base=${FINEVPS_RELEASE_URL:-https://github.com/morphing888/FineVPS/releases/latest/download}
    local dir=/var/lib/finevps-install f
    if [[ $EUID -ne 0 ]]; then
        echo "Запусти установку от root: curl -fsSL ... | sudo bash" >&2
        exit 1
    fi
    if [[ $(uname -m) != x86_64 ]]; then
        echo "Нужен сервер x86_64, а этот: $(uname -m)" >&2
        exit 1
    fi
    if ! command -v curl >/dev/null || ! command -v sha256sum >/dev/null; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq </dev/null
        apt-get install -y -qq curl ca-certificates coreutils </dev/null
    fi
    rm -rf /var/lib/finevps-install
    mkdir -m 700 "$dir"
    trap 'rm -rf /var/lib/finevps-install' EXIT
    echo "Скачиваю программу..."
    for f in awg-cascade.sh awg-cascade-panel SHA256SUMS; do
        curl -fsSL --retry 3 --connect-timeout 15 -o "$dir/$f" "$base/$f"
    done
    if ! (cd "$dir" && sha256sum -c --quiet SHA256SUMS); then
        echo "Контрольная сумма не совпала, установка остановлена" >&2
        exit 1
    fi
    chmod 755 "$dir/awg-cascade.sh" "$dir/awg-cascade-panel"
    bash "$dir/awg-cascade.sh" bootstrap --panel "$dir/awg-cascade-panel" "$@" </dev/null
}

main "$@"
