# Маршруты сервисов: подключается из stand.sh после проверок YouTube.
echo "--- маршруты ---"
STEAM_IP=203.0.113.10 TG_IP=198.51.100.7 DISC_IP=192.0.2.50 GOO_IP=192.0.2.60
C="$AWGC_STATE/routes/cache"
dns_q() { in_ns client dig +short +time=2 +tries=1 @1.1.1.1 "$1" A 2>/dev/null | tail -1; }
E="ip netns exec entry $BIN" # для проверок внутри bash -c
"${ENT[@]}" youtube exit >/dev/null 2>&1 # YouTube через сервер 2: так видно, что Google его не забирает
client_up andrey
t "до настройки Steam через сервер 2" test "$(seen $STEAM_IP)" = "$EXIT_WAN"
t "без маршрутов по доменам сервер имён выключен" bash -c "$E route json | grep -q '\"dns\":false'"

"${ENT[@]}" route set steam 1 >"$W/r1.log" 2>&1; rc=$?
t "Steam: сервер 1 включается" test $rc -eq 0
t "Steam идёт с сервера 1" test "$(seen $STEAM_IP)" = "$ENTRY_WAN"
t "сети Steam из RIPEstat" grep -qx 203.0.113.0/24 "$C/steam.nets"
t "IPv6 и мусор из RIPEstat пропущены" bash -c "! grep -qE ':|999' '$C/steam.nets'"
t "домены Steam из v2fly" bash -c "grep -qx store.steampowered.com '$C/steam.domains' && grep -qx steamcommunity.com '$C/steam.domains' && ! grep -q bad '$C/steam.domains'"
t "для доменов включился сервер имён" bash -c "$E route json | grep -q '\"dns\":true'"
t "российские сайты как прежде" test "$(seen $RU_SITE)" = "$ENTRY_WAN"
t "зарубежные сайты как прежде" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "YouTube через сервер 2 при сервере имён" test "$(dns_q www.youtube.com >/dev/null; seen $YT_SITE)" = "$EXIT_WAN"

fails=0
for i in 1 2 3 4 5 6; do "${ENT[@]}" check >/dev/null 2>&1 || fails=$((fails + 1)); done
t "проверка каскада с сервером имён проходит 6 раз из 6" test $fails -eq 0
"${ENT[@]}" route set telegram 1 >"$W/r2.log" 2>&1; rc=$?
t "Telegram: сеть из второго источника, домены из запасного списка" bash -c "test $rc -eq 0 && grep -qx 198.51.100.0/24 '$C/telegram.nets' && grep -qx telegram.org '$C/telegram.domains'"
t "Telegram: про недоступный источник сказано" grep -q 'источник списков не ответил' "$W/r2.log"
t "Telegram: в панели видна ошибка источника" bash -c "$E route json | python3 -I -c 'import json,sys; d=json.load(sys.stdin); s=[x for x in d[\"services\"] if x[\"id\"]==\"telegram\"][0]; sys.exit(0 if s[\"error\"] and s[\"target\"]==\"1\" else 1)'"
t "Telegram идёт с сервера 1" test "$(seen $TG_IP)" = "$ENTRY_WAN"

"${ENT[@]}" route set discord 1 >/dev/null 2>&1
t "Discord: вложенный список v2fly разобран" bash -c "grep -qx discordapp.net '$C/discord.domains' && grep -qx gateway.discord.gg '$C/discord.domains' && ! grep -q disc$ '$C/discord.domains'"
t "Discord до запроса имени через сервер 2" test "$(seen $DISC_IP)" = "$EXIT_WAN"
t "имя discord.com отвечает" test "$(dns_q discord.com)" = "$DISC_IP"
t "Discord после запроса имени с сервера 1" test "$(seen $DISC_IP)" = "$ENTRY_WAN"

"${ENT[@]}" route set google 1 >/dev/null 2>&1
t "Google: домены YouTube исключены" bash -c "grep -qx google.com '$C/google.domains' && ! grep -q youtube '$C/google.domains'"
dns_q google.com >/dev/null; dns_q www.youtube.com >/dev/null
t "Google идёт с сервера 1" test "$(seen $GOO_IP)" = "$ENTRY_WAN"
t "YouTube всё равно через сервер 2" test "$(seen $YT_SITE)" = "$EXIT_WAN"

"${ENT[@]}" route add $STEAM_IP 2 >/dev/null 2>&1; rc=$?
t "своё правило для адреса" test $rc -eq 0
t "своё правило важнее сервиса" test "$(seen $STEAM_IP)" = "$EXIT_WAN"
"${ENT[@]}" route add 'HTTPS://Example.org/path?x=1' 1 >/dev/null 2>&1; rc=$?
t "адрес сайта из ссылки приведён к домену" bash -c "test $rc -eq 0 && grep -qx '1 example.org' '$AWGC_STATE/routes/custom'"
dns_q example.org >/dev/null
t "своё правило по домену: с сервера 1" test "$(seen $WORLD_SITE)" = "$ENTRY_WAN"
t "своё правило для 77.88.8.8 на сервер 2" bash -c "$E route add 77.88.8.8 2 >/dev/null 2>&1"
t "российский адрес по правилу через сервер 2" test "$(seen $RU_SITE)" = "$EXIT_WAN"
for bad in '1.2.3.0/4' 'bad_domain' '300.1.1.1' '-rf'; do
    t "отклонено: $bad" bash -c "! $E route add '$bad' 1 >/dev/null 2>&1"
done
t "неизвестный сервис отклонён" bash -c "! $E route set nosuch 1 >/dev/null 2>&1"
"${ENT[@]}" route check example.org >"$W/rc.json" 2>&1
t "проверка: сайт по своему правилу" python3 -I -c "import json,sys; d=json.load(open('$W/rc.json')); r=d['results'][0]; sys.exit(0 if r['ip']=='$WORLD_SITE' and r['target']=='1' and r['reason']=='своё правило' else 1)"
t "проверка: Steam по сети" bash -c "$E route check 203.0.113.99 | grep -q '\"target\":\"1\",\"reason\":\"Steam\"'"
t "проверка: российская сеть" bash -c "$E route check 77.88.1.1 | grep -q 'российская сеть'"
t "проверка: остальные адреса" bash -c "$E route check 9.9.9.9 | grep -q '\"target\":\"2\",\"reason\":\"остальные адреса\"'"
t "проверка: YouTube" bash -c "$E route check $YT_SITE | grep -q '\"reason\":\"YouTube\"'"
t "список маршрутов: правильный JSON" bash -c "$E route json | python3 -I -m json.tool >/dev/null"
"${ENT[@]}" routing >/dev/null 2>&1
t "после routing правила на месте" test "$(seen $TG_IP)" = "$ENTRY_WAN"
AWGC_RIPE_URL="file:///nonexistent/@ASN@" AWGC_V2FLY_URL="file:///nonexistent" "${ENT[@]}" route update >/dev/null 2>&1
t "источники не ответили: прежние списки остались" bash -c "grep -qx 203.0.113.0/24 '$C/steam.nets' && grep -qx store.steampowered.com '$C/steam.domains'"
t "источники не ответили: Telegram работает" test "$(seen $TG_IP)" = "$ENTRY_WAN"
"${ENT[@]}" route del example.org >/dev/null 2>&1
dns_q example.org >/dev/null
t "удалённое правило по домену больше не действует" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "нет такого правила: понятная ошибка" bash -c "$E route del example.org 2>&1 | grep -q 'такого правила нет'"
for r in $STEAM_IP 77.88.8.8; do "${ENT[@]}" route del $r >/dev/null 2>&1; done
for s in steam telegram discord google; do "${ENT[@]}" route set $s auto >/dev/null 2>&1; done
t "всё как обычно: Steam через сервер 2" test "$(seen $STEAM_IP)" = "$EXIT_WAN"
t "всё как обычно: российские сайты напрямую" test "$(seen $RU_SITE)" = "$ENTRY_WAN"
t "без правил сервер имён снова выключен" bash -c "$E route json | grep -q '\"dns\":false'"
client_down
