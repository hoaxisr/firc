#!/bin/sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
POSTINST="$HERE/../../../../files/entware/_ipk/control/postinst"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/bin"

fail=0
fake_socat() { # $1 = the body the daemon answers, empty for no answer
    printf '%s' "$1" > "$WORK/body"
    cat > "$WORK/bin/socat" <<SH
#!/bin/sh
printf '%s\n' "\$*" > "$WORK/args"
cat > "$WORK/asked"
[ -s "$WORK/body" ] || exit 1
printf 'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n'
cat "$WORK/body"
SH
    chmod +x "$WORK/bin/socat"
}
expect() { # $1 = what, $2 = expected output (stdout and stderr)
    PATH="$WORK/bin:$PATH" FIRC_CONF="$WORK/firc.conf" FIRC_SOCK="$WORK/firc.sock" sh "$POSTINST" --report-web > "$WORK/said" 2>&1
    if [ "$(cat "$WORK/said")" = "$2" ]; then
        echo "   $1: OK"
    else
        echo "   REGRESSION in $1: wanted"
        echo "$2"
        echo "   got"
        cat "$WORK/said"
        fail=1
    fi
}

printf 'app:\n  httpWeb:\n    enabled: true\n    host:\n      address: "[::]"\n      port: 999\n  dnsProxy:\n    host:\n      port: 3553\n' > "$WORK/firc.conf"

echo "== postinst: where the WebUI listens"
fake_socat '{"settings":{"app.httpWeb.host.port":666},"boot":"b","restarting":false,"pendingRestart":[],"webUi":{"port":666,"movedFrom":0,"lanAddress":"192.168.1.1"}}'
expect "on its port" "firc: WebUI at http://192.168.1.1:666"
if [ "$(cat "$WORK/args")" = "-t10 - UNIX-CONNECT:$WORK/firc.sock" ] &&
    [ "$(cat "$WORK/asked")" = "$(printf 'GET /api/v1/system/settings HTTP/1.0\r\n\r\n')" ]; then
    echo "   the request and the socket it goes to: OK"
else
    echo "   REGRESSION: asked $(cat "$WORK/args") with:"
    cat "$WORK/asked"
    fail=1
fi

fake_socat '{"webUi":{"port":999,"movedFrom":666,"lanAddress":"192.168.1.1"},"classes":{}}'
expect "moved off a busy port" "firc: port 666 is in use; the WebUI moved to 999
firc: WebUI at http://192.168.1.1:999"

fake_socat '{"webUi":{"port":666,"movedFrom":0,"lanAddress":"fd00::1"}}'
expect "on an IPv6 address" "firc: WebUI at http://[fd00::1]:666"

fake_socat '{"webUi":{"port":666,"movedFrom":0,"lanAddress":""}}'
expect "with no LAN address" "firc: WebUI at http://<router address>:666"

fake_socat '{"webUi":{"port":0,"movedFrom":0,"lanAddress":"192.168.1.1"}}'
expect "not listening" "firc: the WebUI is not listening (turned off, or every port tried is in use);
firc: set app.httpWeb.host.port in $WORK/firc.conf and run /opt/etc/init.d/S99firc restart"

fake_socat '{"webUi":{"port":666,"movedFrom":0,"lanAddress":"192.168.1.1"},"dnsProxy":{"listening":false,"port":3553,"proto":"udp","error":"[::]:3553/udp: address already in use by socat (pid 812)","holder":{"name":"socat","pid":812}}}'
expect "the DNS proxy is down" "firc: the DNS proxy is not running: [::]:3553/udp: address already in use by socat (pid 812)
firc: until port 3553/udp is free, firc answers no DNS: no new name gets a fake address
firc: and name rules do not apply; subnet rules and addresses already handed out still route.
firc: firc takes the port by itself once it is free, or set app.dnsProxy.host.port in $WORK/firc.conf and restart
firc: WebUI at http://192.168.1.1:666"

fake_socat '{"webUi":{"port":666,"movedFrom":0,"lanAddress":"192.168.1.1"},"dnsProxy":{"listening":false,"port":3553,"proto":"tcp","error":"[::]:3553/tcp: address already in use by a\"b\\ (pid 9)","holder":{"name":"a\"b\\","pid":9}}}'
expect "a holder whose name has a quote and a backslash" "firc: the DNS proxy is not running: [::]:3553/tcp: address already in use by a\"b\\ (pid 9)
firc: until port 3553/tcp is free, firc answers no DNS: no new name gets a fake address
firc: and name rules do not apply; subnet rules and addresses already handed out still route.
firc: firc takes the port by itself once it is free, or set app.dnsProxy.host.port in $WORK/firc.conf and restart
firc: WebUI at http://192.168.1.1:666"

fake_socat '{"webUi":{"port":666,"movedFrom":0,"lanAddress":"192.168.1.1"},"dnsProxy":{"listening":true,"port":3553,"proto":"","error":"","holder":null}}'
expect "the DNS proxy is up" "firc: WebUI at http://192.168.1.1:666"

fake_socat ''
expect "no answer from the daemon" "firc: could not ask the daemon where the WebUI is; firc.conf sets port 999"

printf 'app:\n  link: []\n' > "$WORK/firc.conf"
expect "no answer, no port in firc.conf" "firc: could not ask the daemon where the WebUI is; firc.conf sets port 666"

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "ok"
