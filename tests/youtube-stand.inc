# Режимы YouTube: подключается из stand.sh.
echo "--- YouTube ---"
client_up andrey
name() { in_ns client dig +short +time=2 +tries=1 @1.1.1.1 "$1" A 2>/dev/null | tail -1; }
t "обычный режим: YouTube через сервер 2" test "$(seen $YT_SITE)" = "$EXIT_WAN"
t "режим обхода без подбора запрещён" bash -c "! '$BIN' youtube bypass >/dev/null 2>&1"
"${ENT[@]}" youtube direct >"$W/yt.log" 2>&1; rc=$?
t "режим без обхода включается" test $rc -eq 0
sed 's/\x1b\[[0-9;]*m//g' "$W/yt.log" | tail -2
t "сервер имён отвечает устройствам" test "$(name www.youtube.com)" = "$YT_SITE"
t "адрес YouTube попал в список" bash -c "ip netns exec entry ipset test awgc_yt $YT_SITE 2>&1 | grep -q 'is in set'"
t "YouTube идёт с сервера 1"          test "$(seen $YT_SITE)" = "$ENTRY_WAN"
t "другие зарубежные сайты через сервер 2" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "российские сайты напрямую"         test "$(seen $RU_SITE)" = "$ENTRY_WAN"
t "QUIC к YouTube отклоняется" bash -c "! ip netns exec client timeout 3 python3 -I -c \"
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('$YT_SITE',443))
s.send(b'x'); s.settimeout(2); s.recv(9)\" 2>&1 | grep -q timed"
in_ns entry awg-quick down awguplink >/dev/null 2>&1
t "без сервера 2 имена всё равно отвечают" test "$(name example.org)" = "$WORLD_SITE"
in_ns entry ipset flush awgc_yt
name www.youtube.com >/dev/null
t "YouTube работает без сервера 2"     test "$(seen $YT_SITE)" = "$ENTRY_WAN"
t "другой зарубежный сайт заблокирован" test -z "$(seen $WORLD_SITE)"
in_ns entry awg-quick up awguplink >/dev/null 2>&1; sleep 4
cat >"$W/bc.log" <<'LOG'
* SUMMARY
curl_test_https_tls12 ipv4 www.youtube.com : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=1
* COMMON
curl_test_https_tls12 ipv4 : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=1

* COVERAGE
3/3 : curl_test_https_tls12 ipv4 : nfqws2 --payload=tls_client_hello --lua-desync=multisplit:pos=1
2/3 : curl_test_https_tls13 ipv4 : nfqws2 --payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:tcp_md5 --lua-desync=multidisorder:pos=midsld

blockcheck optimizes test sequence.
LOG
"${ENT[@]}" youtube-test --parse "$W/bc.log"
t "из журнала выбран обход для TLS 1.3" grep -q 'multidisorder:pos=midsld' "$AWGC_STATE/youtube/found.strategy"
t "записано покрытие" test "$(cat "$AWGC_STATE/youtube/coverage")" = 2/3
printf '* SUMMARY\nwww.youtube.com curl_test_https_tls12 ipv4 : working without bypass\n' >"$W/bc2.log"
cp "$AWGC_STATE/youtube/found.strategy" "$W/strategy.keep"
"${ENT[@]}" youtube-test --parse "$W/bc2.log"
t "обход не нужен: определено" test "$(cat "$AWGC_STATE/youtube/result")" = nobypass
cp "$W/strategy.keep" "$AWGC_STATE/youtube/found.strategy"
mkdir -p "$ZAPRET_DIR_T"
t "список способов: не меньше восьми" test "$("${ENT[@]}" youtube list | wc -l)" -ge 8
t "неизвестный способ отклонён" bash -c "! '$BIN' youtube preset p99 >/dev/null 2>&1"
"${ENT[@]}" youtube preset p5 >"$W/yt2.log" 2>&1; rc=$?
t "способ из списка включается" test $rc -eq 0
t "параметры способа записаны" grep -q 'sni=www.google.com' "$ZAPRET_DIR_T/awgc/nfqws2.conf"
"${ENT[@]}" youtube preset p8 >/dev/null 2>&1
t "переключение на другой способ" grep -q 'ip_autottl' "$ZAPRET_DIR_T/awgc/nfqws2.conf"
"${ENT[@]}" youtube preset found >/dev/null 2>&1
t "подобранный способ тоже включается" grep -q 'multidisorder:pos=midsld' "$ZAPRET_DIR_T/awgc/nfqws2.conf"
"${ENT[@]}" youtube mark p1 bad; "${ENT[@]}" youtube mark p2 good; "${ENT[@]}" youtube mark p1 good
t "ответ о способах корректный" bash -c "'$BIN' youtube json | python3 -I -c \"
import json,sys
d=json.load(sys.stdin)
m={p['id']:p['mark'] for p in d['presets']}
assert d['mode']=='bypass' and d['preset']=='found' and m['p1']=='good' and m['p2']=='good' and 'found' in m, d\""
"${ENT[@]}" youtube mark p1 none
t "отметка снимается" bash -c "'$BIN' youtube json | grep -q '\"id\":\"p1\"[^}]*\"mark\":\"\"'"
t "режим обхода включается" test "$("${ENT[@]}" youtube status | grep -c обход)" -ge 1
t "правила перехвата применились" bash -c "ip netns exec entry nft list table inet awgc_yt | grep -q 'ct original packets 1-15'"
t "настройка программы обхода записана" bash -c "grep -q -- '--hostlist=$ZAPRET_DIR_T/awgc/hosts.txt' '$ZAPRET_DIR_T/awgc/nfqws2.conf'"
printf '%s\n' "--payload=tls_client_hello --out-range=<d10 --lua-desync=fake:x=(a|b)" >"$AWGC_STATE/youtube/found.strategy"
"${ENT[@]}" youtube preset found >/dev/null 2>&1
t "особые знаки стратегии закрыты кавычками" python3 -I -c "
import shlex
a=shlex.split(open('$ZAPRET_DIR_T/awgc/nfqws2.conf').read())
assert a[-3:]==['--payload=tls_client_hello','--out-range=<d10','--lua-desync=fake:x=(a|b)'],a
assert '<' not in open('$ZAPRET_DIR_T/awgc/nfqws2.conf').read().replace(\"'--out-range=<d10'\",'')"
t "трафик идёт, даже если программа обхода упала" test "$(seen $YT_SITE)" = "$ENTRY_WAN"
"${ENT[@]}" routing >/dev/null 2>&1
t "режим сохраняется после routing" bash -c "ip netns exec entry nft list table inet awgc_yt >/dev/null"
seen443() { in_ns client curl -s --max-time 5 "http://$YT_SITE:443/"; }
hits() { wc -l <"$W/stub.hits" 2>/dev/null || echo 0; }
"${ENT[@]}" youtube preset t1 >/dev/null 2>&1; rc=$?
t "tpws включается" test $rc -eq 0
t "команда tpws верная" grep -q -- "tpws --bind-addr=10.87.1.1 --port=8703 --split-pos=1,midsld --disorder=tls" "$AWGC_STATE/youtube/proxy.cmd"
t "через tpws YouTube идёт с сервера 1" test "$(seen443)" = "$ENTRY_WAN"
t "соединение прошло через прокси" test "$(hits)" -eq 1
t "другие порты мимо прокси" test "$(seen $YT_SITE)" = "$ENTRY_WAN"
t "счётчик прокси не изменился" test "$(hits)" -eq 1
t "зарубежные сайты через сервер 2 при прокси" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
"${ENT[@]}" youtube preset b1 >/dev/null 2>&1; rc=$?
t "ByeDPI включается" test $rc -eq 0
t "команда ByeDPI верная" grep -q -- "ciadpi -i 10.87.1.1 -p 8703 -E --disorder 1 --auto=torst --tlsrec 1+s" "$AWGC_STATE/youtube/proxy.cmd"
t "через ByeDPI YouTube идёт с сервера 1" test "$(seen443)" = "$ENTRY_WAN"
t "ByeDPI тоже через прокси" test "$(hits)" -eq 2
kill "$(cat "$AWGC_STATE/youtube/proxy.pid")"; sleep 0.3; "${ENT[@]}" routing >/dev/null 2>&1
t "без прокси соединения не обрываются" test "$(seen443)" = "$ENTRY_WAN"
AWGC_WARP_ENDPOINTS="198.18.2.1:9" "${ENT[@]}" youtube preset warp >"$W/warp0.log" 2>&1; rc=$?
t "недоступный WARP: понятная ошибка" test $rc -ne 0
t "недоступный WARP: режим без обхода" bash -c "'$BIN' youtube status | grep -q 'без обхода'"
t "недоступный WARP: YouTube работает" test "$(seen443)" = "$ENTRY_WAN"
"${ENT[@]}" youtube preset warp >"$W/warp.log" 2>&1; rc=$?
t "WARP включается со второго узла" test $rc -eq 0
sed 's/\x1b\[[0-9;]*m//g' "$W/warp.log" | grep -E 'WARP' | head -3
t "IPv6 из профиля WARP не попал в настройки" bash -c "! grep -q '2606:' '$AWGC_AWG_DIR/awgwarp.conf'"
t "YouTube идёт через WARP" test "$(seen $YT_SITE)" = 10.99.0.2
t "зарубежные сайты через сервер 2 при WARP" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "российские сайты напрямую при WARP" test "$(seen $RU_SITE)" = "$ENTRY_WAN"
"${ENT[@]}" routing >/dev/null 2>&1
t "после routing WARP остаётся" test "$(seen $YT_SITE)" = 10.99.0.2
in_ns entry awg-quick down awgwarp >/dev/null 2>&1
t "при падении WARP YouTube не утекает другим путём" test -z "$(seen $YT_SITE)"
"${ENT[@]}" youtube preset warp >/dev/null 2>&1
"${ENT[@]}" youtube preset p1 >/dev/null 2>&1
t "после WARP его правил не осталось" bash -c "! ip netns exec entry ip rule | grep -q 8702"
t "после смены способа WARP выключен" bash -c "! ip netns exec entry ip link show awgwarp >/dev/null 2>&1"
"${ENT[@]}" youtube exit >/dev/null 2>&1; sleep 1
t "после возврата YouTube снова через сервер 2" test "$(seen $YT_SITE)" = "$EXIT_WAN"
t "имена снова идут как раньше" test "$(name example.org)" = "$WORLD_SITE"
t "правил перехвата нет" bash -c "! ip netns exec entry nft list table inet awgc_yt >/dev/null 2>&1"
t "лишних правил маршрутизации нет" bash -c "! ip netns exec entry ip rule | grep -q 'dport'"
"${ENT[@]}" youtube direct >/dev/null 2>&1
client_down
