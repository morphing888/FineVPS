#!/usr/bin/env bash
# Сквозной тест каскада на сетевых пространствах Linux.
# Настоящий AmneziaWG здесь заменён обычным WireGuard (wireguard-go): строки маскировки
# отбрасываются. Проверяются маршруты, фаервол, SSH-настройка сервера 2 и пользователи.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/../awg-cascade.sh"
W=$(mktemp -d)
PASS=0 FAIL=0
RU_SITE=77.88.8.8 WORLD_SITE=1.1.1.1 YT_SITE=142.250.1.1
ENTRY_WAN=198.18.2.2 EXIT_WAN=198.18.3.2 CLIENT_WAN=198.18.1.2

t() { # t "название" команда...
    local name=$1; shift
    if "$@"; then echo "PASS  $name"; PASS=$((PASS+1)); else echo "FAIL  $name"; FAIL=$((FAIL+1)); fi
}
in_ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

cleanup() {
    for n in client entry exit inet; do
        ip netns pids "$n" 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del "$n" 2>/dev/null
    done
    rm -f /usr/local/bin/awg /usr/local/bin/awg-quick /usr/local/sbin/awg-cascade /usr/local/sbin/awg-cascade-panel
    usermod -p '*' root 2>/dev/null
    rm -f /etc/sysctl.d/90-awg-cascade.conf
    rm -rf "$W" /etc/awg-test
}
trap cleanup EXIT

export -n HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NO_PROXY no_proxy
unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NO_PROXY no_proxy

# --- заменители awg и awg-quick ---
cat >/usr/local/bin/awg <<'EOF'
#!/bin/sh
exec wg "$@"
EOF
cat >/usr/local/bin/awg-quick <<'EOF'
#!/bin/bash
# $1=up|down $2=имя: убираем строки AmneziaWG и DNS, вызываем wg-quick
export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
d=/run/awgshim-$(ip netns identify $$ 2>/dev/null); mkdir -p "$d"
n=$(basename "$2" .conf)
s=$2; [[ -f $s ]] || s=${AWGC_AWG_DIR}/$n.conf
grep -vE '^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|DNS) *=' "$s" | sed 's/, ::\/0//' >"$d/$n.conf"  # в ядре стенда нет IPv6
exec wg-quick "$1" "$d/$n.conf"
EOF
chmod 755 /usr/local/bin/awg /usr/local/bin/awg-quick

# --- сеть ---
for n in client entry exit inet; do ip netns add "$n"; in_ns "$n" ip link set lo up; done
link() { # link ns addr gw idx
    ip link add "v$1" type veth peer name "r$1"
    ip link set "v$1" netns "$1"; ip link set "r$1" netns inet
    in_ns "$1" ip addr add "$2/24" dev "v$1"; in_ns "$1" ip link set "v$1" up
    in_ns "$1" ip route add default via "$3"
    in_ns inet ip addr add "$3/24" dev "r$1"; in_ns inet ip link set "r$1" up
}
link client $CLIENT_WAN 198.18.1.1
link entry  $ENTRY_WAN  198.18.2.1
link exit   $EXIT_WAN   198.18.3.1
in_ns inet sysctl -q -w net.ipv4.ip_forward=1
in_ns inet ip addr add $RU_SITE/32 dev lo
in_ns inet ip addr add $WORLD_SITE/32 dev lo
in_ns inet ip addr add $YT_SITE/32 dev lo
in_ns inet ip addr add 8.8.8.8/32 dev lo
for a in 203.0.113.10 198.51.100.7 192.0.2.50 192.0.2.60; do in_ns inet ip addr add $a/32 dev lo; done # сервисы для маршрутов

# --- сайт, который показывает адрес посетителя ---
cat >"$W/site.py" <<'EOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=b"0"*3000000 if self.path.startswith("/big") else self.client_address[0].encode(); self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
import threading
threading.Thread(target=http.server.ThreadingHTTPServer(("0.0.0.0",443),H).serve_forever,daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0",8080),H).serve_forever()
EOF
in_ns inet python3 -I "$W/site.py" & sleep 0.5

# --- список сетей ---
{ echo 77.88.0.0/16; for i in $(seq 1 200); do for j in $(seq 1 6); do echo "5.$i.$j.0/24"; done; done; } >"$W/ru.zone"
echo '<html>заглушка провайдера</html>' >"$W/bad.zone"

# --- внешний сервер имён: youtube.com на YT_SITE, остальное на WORLD_SITE ---
in_ns inet dnsmasq --no-resolv --no-hosts --bind-dynamic --listen-address=1.1.1.1 --listen-address=8.8.8.8 --listen-address=77.88.8.8 --pid-file="$W/up.pid" \
    --address=/youtube.com/$YT_SITE --address=/example.org/$WORLD_SITE --user=root \
    --address=/discord.com/192.0.2.50 --address=/google.com/192.0.2.60

# --- SSH на сервере 2 ---
mkdir -p /run/sshd /root/.ssh; chmod 700 /root/.ssh
ssh-keygen -q -t ed25519 -N '' -f "$W/id"
ssh-keygen -q -t ed25519 -N '' -f "$W/host"
cat "$W/id.pub" >>/root/.ssh/authorized_keys
in_ns exit /usr/sbin/sshd -p 22 -h "$W/host" -o PermitRootLogin=yes -o PidFile="$W/sshd.pid" \
    -o 'AcceptEnv AWGC_*' -o UsePAM=no

export AWGC_NO_QUEUE=1 # в ядре стенда нет очередей nfqueue
export AWGC_YT_DEFAULT=exit # прежние проверки начинают с YouTube через сервер 2
export AWGC_STATE=/etc/awg-test/state AWGC_AWG_DIR=/etc/awg-test/awg AWGC_SKIP_PACKAGES=1 AWGC_NO_SYSTEMD=1
export AWGC_RU_URLS="file://$W/ru.zone"
# Источники списков сервисов: RIPEstat и v2fly. Не все файлы есть: так проверяется отказ источника.
export AWGC_RIPE_URL="file://$W/ripe/@ASN@.json" AWGC_V2FLY_URL="file://$W/v2fly"
mkdir -p "$W/ripe" "$W/v2fly"
echo '{"data":{"prefixes":[{"prefix":"203.0.113.0/24","timelines":[]},{"prefix":"2001:db8::/32"},{"prefix":"999.1.1.0/24"}]}}' >"$W/ripe/AS32590.json"
echo '{"data":{"prefixes":[{"prefix":"198.51.100.0/24"}]}}' >"$W/ripe/AS62041.json"
printf 'steampowered.com\nfull:store.steampowered.com\n# комментарий\nregexp:^bad$\n' >"$W/v2fly/steam"
printf 'discord.com @ads\ninclude:discord-extra\nkeyword:disc\n' >"$W/v2fly/discord"
printf 'domain:discordapp.net\nfull:gateway.discord.gg\n' >"$W/v2fly/discord-extra"
printf 'google.com\nyoutube.com\nwww.youtube.com\ninclude:youtube\n' >"$W/v2fly/google"
export AWGC_SSH_OPTS="-i $W/id -o UserKnownHostsFile=$W/kh -o BatchMode=yes -o SendEnv=AWGC_*"
export PATH=/usr/local/bin:/usr/local/sbin:$PATH
BIN=/usr/local/sbin/awg-cascade
ZAPRET_DIR_T=/etc/awg-test/zapret
export AWGC_ZAPRET_DIR=$ZAPRET_DIR_T

# --- заглушки: прозрачный прокси и WARP на обычном WireGuard ---
export AWGC_PROXY_STUB="python3 -I $HERE/proxy-stub.py" STUB_HITS=$W/stub.hits
export AWGC_WARP_PROFILE=$W/warp.conf AWGC_WARP_ENDPOINTS="198.18.2.1:9 198.18.2.1:51999"
wk=$(wg genkey); wp=$(wg genkey); wkp=$(printf %s "$wk" | wg pubkey); wpp=$(printf %s "$wp" | wg pubkey)
cat >"$W/wgwarp.conf" <<EOF
[Interface]
PrivateKey = $wk
Address = 10.99.0.1/24
ListenPort = 51999

[Peer]
PublicKey = $wpp
AllowedIPs = 10.99.0.2/32
EOF
in_ns inet awg-quick up "$W/wgwarp.conf" >/dev/null 2>&1
cat >"$W/warp.conf" <<EOF
[Interface]
PrivateKey = $wp
Address = 10.99.0.2/32, 2606:4700::2/128
DNS = 1.1.1.1

[Peer]
PublicKey = $wkp
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
EOF

RUN=(ip netns exec entry "$SRC")
ENT=(ip netns exec entry "$BIN")

client_conf() { mkdir -p "$W/cl"; cp "$AWGC_STATE/users/$1.conf" "$W/cl/client.conf"; }
client_up() { client_conf "$1"; in_ns client awg-quick up "$W/cl/client.conf" >/dev/null 2>&1; sleep 2; }
client_down() { in_ns client awg-quick down "$W/cl/client.conf" >/dev/null 2>&1; }
seen() { in_ns "${2:-client}" curl -s --max-time 5 "http://$1:8080/"; }

if [[ -n ${BOOT:-} ]]; then . "$HERE/bootstrap-stand.inc"; exit $?; fi

echo "--- установка ---"
"${RUN[@]}" install --exit-ip $EXIT_WAN --exit-ssh-port 22 --user andrey --endpoint $ENTRY_WAN >"$W/install.log" 2>&1
rc=$?
tail -25 "$W/install.log" | grep -vE '█|▀|▄' | sed 's/\x1b\[[0-9;]*m//g'
t "установка завершилась успешно" test $rc -eq 0
t "предупреждение о пароле показано" grep -q 'ВВЕДИ ПАРОЛЬ' "$W/install.log"
t "звуковой сигнал есть" grep -q $'\a' "$W/install.log"

echo "--- маршруты ---"
client_up andrey
t "российский сайт видит сервер 1"  test "$(seen $RU_SITE)" = "$ENTRY_WAN"
t "зарубежный сайт видит сервер 2"  test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "сам сервер 1 выходит напрямую"   test "$(seen $WORLD_SITE entry)" = "$ENTRY_WAN"
t "проверка check проходит"         in_ns entry "$BIN" check
big() { in_ns client curl -s --max-time 10 -o /dev/null -w '%{http_code}' "http://$WORLD_SITE:8080/x$(head -c 3000 /dev/zero | tr '\0' a)"; }
t "большой запрос проходит (MTU)"   test "$(big)" = 200

if [[ -n ${E2E:-} ]]; then . "$HERE/panel-stand.inc"; exit $?; fi

echo "--- отказ связи с сервером 2 ---"
in_ns entry awg-quick down awguplink >/dev/null 2>&1
t "зарубежный трафик не уходит с IP сервера 1" test -z "$(seen $WORLD_SITE)"
t "российские сайты работают без сервера 2"    test "$(seen $RU_SITE)" = "$ENTRY_WAN"
in_ns entry awg-quick up awguplink >/dev/null 2>&1; sleep 4
t "после подъёма туннеля всё вернулось"        test "$(seen $WORLD_SITE)" = "$EXIT_WAN"

echo "--- строгая проверка обратного пути ---"
in_ns entry sysctl -q -w net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.awguplink.rp_filter=1
t "без исправления ответы отбрасываются" test -z "$(seen $WORLD_SITE)"
"${ENT[@]}" routing >/dev/null 2>&1
t "routing исправляет rp_filter"         test "$(seen $WORLD_SITE)" = "$EXIT_WAN"

echo "--- повторные запуски ---"
count() { in_ns entry sh -c 'iptables-save | wc -l; ip rule | wc -l; ip route show table 8701 | wc -l' | tr '\n' ' '; }
a=$(count); "${ENT[@]}" routing >/dev/null 2>&1; "${ENT[@]}" routing >/dev/null 2>&1; b=$(count)
t "правила не размножаются" test "$a" = "$b"
AWGC_RU_URLS="file://$W/bad.zone" "${ENT[@]}" routing >/dev/null 2>&1
t "страница-заглушка не портит список" test "$(in_ns entry ipset list awgc_ru | awk '/^Number/{print $4}')" -ge 1000
"${ENT[@]}" routing >/dev/null 2>&1 & "${ENT[@]}" routing >/dev/null 2>&1; rc=$?; wait $!; rc2=$?
t "два одновременных запуска не мешают друг другу" test $rc -eq 0 -a $rc2 -eq 0
"${ENT[@]}" install --exit-ip $EXIT_WAN >"$W/re.log" 2>&1; rc=$?
t "повторная установка не ломает каскад" test $rc -eq 0
# туннели перезапускались: устройство заново договаривается с сервером сама, без действий человека
recovered() { local i; for i in $(seq 1 45); do [ "$(seen $WORLD_SITE)" = "$EXIT_WAN" ] && { echo "  восстановилось за ~$i попыток"; return 0; }; sleep 1; done; return 1; }
t "пользователь работает после повторной установки" recovered

echo "--- пользователи ---"
client_down
"${ENT[@]}" add vasya >/dev/null 2>&1
t "второй пользователь получил другой адрес" grep -q 'Address = 10.87.1.3/32' "$AWGC_STATE/users/vasya.conf"
client_up vasya
t "новый пользователь работает без перезапуска" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
t "list показывает двоих" test "$("${ENT[@]}" list | grep -cE '^(andrey|vasya) ')" -eq 2
"${ENT[@]}" disable vasya >/dev/null 2>&1; sleep 1
t "отключённый пользователь не работает" test -z "$(seen $WORLD_SITE)"
t "отключённый виден в списке" bash -c "'$BIN' list | grep -q 'отключён'"
"${ENT[@]}" add petya >/dev/null 2>&1
t "адрес отключённого не занимается" grep -q 'Address = 10.87.1.4/32' "$AWGC_STATE/users/petya.conf"
"${ENT[@]}" del petya >/dev/null 2>&1
"${ENT[@]}" enable vasya >/dev/null 2>&1
client_down; client_up vasya
t "включённый пользователь снова работает" test "$(seen $WORLD_SITE)" = "$EXIT_WAN"
cp "$AWGC_STATE/users/vasya.conf" "$W/vasya.saved"
"${ENT[@]}" del vasya >/dev/null 2>&1
sleep 1
in_ns client awg-quick down "$W/cl/client.conf" >/dev/null 2>&1
cp "$W/vasya.saved" "$W/cl/client.conf"; in_ns client awg-quick up "$W/cl/client.conf" >/dev/null 2>&1; sleep 2
t "удалённый пользователь отключён" test -z "$(seen $WORLD_SITE)"
client_down
t "имя с недопустимыми символами отклонено" bash -c "! '$BIN' add 'a b;rm' >/dev/null 2>&1"
t "ключи закрыты от других" test "$(stat -c %a "$AWGC_STATE/keys")" = 700
t "настройки закрыты от других" test "$(stat -c %a "$AWGC_AWG_DIR/awgclients.conf")" = 600

. "$HERE/youtube-stand.inc"
. "$HERE/routes-stand.inc"

echo "--- пустой список ---"
client_up andrey
in_ns entry ipset flush awgc_ru
t "без списка всё идёт через сервер 2" test "$(seen $RU_SITE)" = "$EXIT_WAN"
"${ENT[@]}" routing >/dev/null 2>&1
client_down

echo "--- удаление ---"
in_ns entry sh -c 'iptables-save | grep -c AWGC' >/dev/null
"${ENT[@]}" uninstall >/dev/null 2>&1; rc=$?
t "без --yes не удаляет" test $rc -ne 0
"${ENT[@]}" uninstall --yes >/dev/null 2>&1
t "правила сервера 1 убраны"  test "$(in_ns entry sh -c 'iptables-save | grep -c AWGC')" = 0
t "маршруты сервера 1 убраны" test -z "$(in_ns entry ip rule | grep fwmark)"
t "набор сетей убран"         bash -c "! ip netns exec entry ipset list awgc_ru >/dev/null 2>&1"
t "наборы маршрутов убраны"   bash -c "! ip netns exec entry ipset list -n | grep -q awgc_"
t "сервер 1 выходит в сеть"   test "$(seen $WORLD_SITE entry)" = "$ENTRY_WAN"

echo
echo "ИТОГ: пройдено $PASS, не пройдено $FAIL"
[[ $FAIL -eq 0 ]]
