# Часть стенда для панели: подключается из stand.sh при E2E=1.
echo "--- панель ---"
"${ENT[@]}" panel-install "$E2E_BIN" >"$W/panel.log" 2>&1; rc=$?
t "установка панели" test $rc -eq 0
"${ENT[@]}" routing >/dev/null 2>&1
# shellcheck disable=SC1090
. "$AWGC_STATE/cascade.env"
PASSW=test-admin-pass-1
URL=$(sed 's/\x1b\[[0-9;]*m//g' "$W/panel.log" | awk '/Адрес панели:/ {print $3}')
t "адрес и ссылка первого входа показаны" bash -c "test -n '$URL' && grep -q 'Ссылка: ' '$W/panel.log'"
t "порт статистики закрыт снаружи" bash -c "! ip netns exec inet curl -s --max-time 3 http://$EXIT_WAN:8711/stats"
t "статистика ставится по ключу, без пароля" bash -c "grep -q 'по ключу' '$W/panel.log' && ! grep -q 'ВВЕДИ ПАРОЛЬ' '$W/panel.log'"

"${ENT[@]}" panel-install "$E2E_BIN" >"$W/panel2.log" 2>&1; rc=$?
t "повторная установка панели" test $rc -eq 0
t "адрес панели при обновлении тот же" grep -q "$URL" "$W/panel2.log"
TOKEN=$(sed 's/\x1b\[[0-9;]*m//g' "$W/panel2.log" | sed -n 's/.*setup=//p')
t "пока нет администратора, ссылка показывается снова" test -n "$TOKEN"

python3 -I "$HERE/seed-stats.py" "$AWGC_STATE/panel/stats.json" andrey

start_panel() { in_ns entry "$E2E_BIN" serve --state "$AWGC_STATE" --port "$PANEL_PORT" --base "/$PANEL_PATH" --host "$ENTRY_WAN" --cli "$BIN" --agent "$LINK_EXIT:8711" >"$W/p.log" 2>&1 & PANEL_PID=$!; }
LINK_EXIT=10.87.2.1
start_panel
in_ns exit "$E2E_BIN" agent --listen 10.87.2.1:8711 --tunnel-if awgexit >"$W/a.log" 2>&1 &
AGENT_PID=$!
sleep 1
t "агент виден только через туннель" bash -c "ip netns exec entry curl -s --max-time 3 http://10.87.2.1:8711/stats | grep -q memTotal"
t "устройство не достаёт до агента" bash -c "! ip netns exec client curl -s --max-time 3 http://10.87.2.1:8711/stats"
t "без секретного адреса панели нет" test "$(in_ns inet curl -sk -o /dev/null -w '%{http_code}' "https://$ENTRY_WAN:$PANEL_PORT/")" = 404

( while :; do in_ns client curl -s --max-time 6 -o /dev/null "http://$WORLD_SITE:8080/big"; in_ns client curl -s --max-time 6 -o /dev/null "http://$RU_SITE:8080/big"; sleep 0.3; done ) &
LOAD_PID=$!
sleep 28

cat >"$W/ctl.sh" <<CTL
#!/bin/bash
case \$1 in
  agent-stop) pkill -f "$E2E_BIN agent" ;;
  agent-start) ip netns exec exit "$E2E_BIN" agent --listen 10.87.2.1:8711 --tunnel-if awgexit >/dev/null 2>&1 & ;;
  uplink-down) ip netns exec entry awg-quick down awguplink ;;
  panel-restart) pkill -f "$E2E_BIN serve"; sleep 1; ip netns exec entry "$E2E_BIN" serve --state "$AWGC_STATE" --port "$PANEL_PORT" --base "/$PANEL_PATH" --host "$ENTRY_WAN" --cli "$BIN" --agent "10.87.2.1:8711" >/dev/null 2>&1 & ;;
esac
CTL
chmod +x "$W/ctl.sh"
in_ns inet env PANEL_URL="$URL" PANEL_TOKEN="$TOKEN" PANEL_PASS="$PASSW" CTL="$W/ctl.sh" SHOTS="$E2E_SHOTS" NODE_PATH="$(npm root -g 2>/dev/null)" node "$HERE/e2e.js"
rc=$?
kill $LOAD_PID 2>/dev/null
pkill -f "$E2E_BIN" 2>/dev/null
client_down
t "сценарии в браузере" test $rc -eq 0
a1=$(sha256sum "$AWGC_STATE/panel/auth.json")
"${ENT[@]}" panel-install "$E2E_BIN" >"$W/panel3.log" 2>&1; rc=$?
t "обновление с администратором" test $rc -eq 0
t "вход при обновлении не меняется" test "$a1" = "$(sha256sum "$AWGC_STATE/panel/auth.json")"
t "ссылка при обновлении не показывается" bash -c "! grep -q 'Ссылка:' '$W/panel3.log'"
t "setup-link не работает при готовой панели" bash -c "! '$BIN' setup-link >/dev/null 2>&1"
in_ns entry cat /proc/self/net/dev >/dev/null
echo "ИТОГ: пройдено $PASS, не пройдено $FAIL"
[[ $FAIL -eq 0 ]]
