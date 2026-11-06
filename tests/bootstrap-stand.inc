# Установка с нуля: install.sh, ссылка, администратор, мастер сервера 2. Запуск: BOOT=1 E2E_BIN=...
echo "--- установка с нуля ---"
R2PW=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
printf 'root:%s\n' "$R2PW" | chpasswd
export AWGC_SSH_OPTS="-o UserKnownHostsFile=$W/kh -o SendEnv=AWGC_*"
PANEL_FILE=/usr/local/sbin/awg-cascade-panel
mkdir -p "$W/rel" "$W/bad"
cp "$SRC" "$W/rel/awg-cascade.sh"; cp "$E2E_BIN" "$W/rel/awg-cascade-panel"
(cd "$W/rel" && sha256sum awg-cascade.sh awg-cascade-panel >SHA256SUMS)
cp "$W/rel/"* "$W/bad/"; printf '\n# подмена\n' >>"$W/bad/awg-cascade.sh"
in_ns inet python3 -I -m http.server --bind 198.18.2.1 8000 --directory "$W" >/dev/null 2>&1 &
sleep 1
inst() { in_ns entry env FINEVPS_RELEASE_URL="http://198.18.2.1:8000/$1" bash -s -- --endpoint "$ENTRY_WAN" <"$HERE/../install.sh"; }

inst bad >"$W/bad.log" 2>&1; rc=$?
t "подменённая программа не запускается" test $rc -ne 0
t "сказано про контрольную сумму" grep -q 'Контрольная сумма' "$W/bad.log"
t "после отказа ничего не установлено" test ! -e "$BIN"

inst rel >"$W/boot.log" 2>&1; rc=$?
sed 's/\x1b\[[0-9;]*m//g' "$W/boot.log" | grep -vE 'setup=' | tail -12
t "установка одной командой завершилась" test $rc -eq 0
LINK=$(sed 's/\x1b\[[0-9;]*m//g' "$W/boot.log" | awk '/Ссылка:/ {print $2}')
t "ссылка первого входа показана" test -n "$LINK"
t "ключ ссылки не лежит на диске" bash -c "! grep -q '${LINK##*setup=}' '$AWGC_STATE/panel/setup.token'"
t "панель ждёт сервер 2" grep -qx pending "$AWGC_STATE/panel/stage"
t "пока без связи с сервером 2" test ! -e "$AWGC_AWG_DIR/awguplink.conf"
# shellcheck disable=SC1090
. "$AWGC_STATE/cascade.env"
t "порт панели открыт" bash -c "ip netns exec entry iptables -S AWGC_INPUT | grep -q 'dport $PANEL_PORT'"

in_ns entry "$PANEL_FILE" serve --state "$AWGC_STATE" --port "$PANEL_PORT" --base "/$PANEL_PATH" --host "$ENTRY_WAN" --cli "$BIN" >"$W/p.log" 2>&1 &
sleep 1
in_ns inet env PANEL_LINK="$LINK" R2_IP="$EXIT_WAN" R2_PASS="$R2PW" SHOTS="$E2E_SHOTS" NODE_PATH="$(npm root -g 2>/dev/null)" node "$HERE/e2e-boot.js"
rc=$?
t "сценарии в браузере" test $rc -eq 0

echo "--- после мастера ---"
t "каскад отмечен готовым" grep -qx ready "$AWGC_STATE/panel/stage"
t "пароль сервера 2 нигде не сохранён" bash -c "! grep -rqF '$R2PW' '$AWGC_STATE' '$AWGC_AWG_DIR' '$W/p.log'"
t "пароля нет в окружении процессов" bash -c "! grep -slF '$R2PW' /proc/[0-9]*/environ 2>/dev/null | grep -q ."
client_up andrey
t "пользователь из панели: российский сайт через сервер 1" test "$(seen $RU_SITE)" = "$ENTRY_WAN"
t "пользователь из панели: зарубежный сайт через сервер 2" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
client_down
"${ENT[@]}" agent-install >"$W/agent.log" 2>&1; rc=$?
t "сервер 2 доступен по ключу, без пароля" bash -c "test $rc -eq 0 && grep -q 'по ключу' '$W/agent.log' && ! grep -q 'ВВЕДИ ПАРОЛЬ' '$W/agent.log'"
a1=$(sha256sum "$AWGC_STATE/panel/auth.json")
inst rel >"$W/boot2.log" 2>&1; rc=$?
t "повторный запуск обновляет программу" bash -c "test $rc -eq 0 && grep -q 'обновляю программу' '$W/boot2.log'"
t "повторный запуск не меняет вход" test "$a1" = "$(sha256sum "$AWGC_STATE/panel/auth.json")"
t "повторный запуск не показывает ссылку" bash -c "! grep -q 'Ссылка:' '$W/boot2.log'"
t "адрес панели не изменился" grep -q "$PANEL_PATH" "$W/boot2.log"
pkill -f "$PANEL_FILE" 2>/dev/null
echo "ИТОГ: пройдено $PASS, не пройдено $FAIL"
[[ $FAIL -eq 0 ]]
