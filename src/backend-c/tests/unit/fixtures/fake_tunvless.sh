#!/bin/sh
printf '%s\n' "$@" > "${FAKE_ARGV_OUT:-/dev/null}"
[ -n "${FAKE_STARTS_OUT:-}" ] && printf '%s %s\n' "$3" "$$" >> "$FAKE_STARTS_OUT"
[ "$3" = "${FAKE_STUBBORN_DEV:-}" ] && trap '' TERM
[ "$1" = "--probe" ] && [ "${FAKE_MODE:-ok}" = ok ] && FAKE_MODE=probe
case "${FAKE_MODE:-ok}" in
noread) exec sleep 3600 ;;
closein) exec sleep 3600 <&- ;;
stubborn) trap '' TERM; exec sleep 3600 ;;
fds) ls -l /proc/self/fd > "${FAKE_FDS_OUT:-/dev/null}"; exec sleep 3600 ;;
probe)
    i=0
    while IFS= read -r l; do
        [ -z "$l" ] && break
        printf '%s\n' "$l" >> "${FAKE_STDIN_OUT:-/dev/null}"
        n=${l##*#}
        case "$l" in
        *fail*) printf '%d\t%s\tfailed\tconnection refused\n' "$i" "$n" ;;
        *) printf '%d\t%s\tok\thandshake %d ms, first byte %d ms\n' "$i" "$n" $((10 + i)) $((20 + i)) ;;
        esac
        i=$((i + 1))
    done
    exit 0 ;;
esac
IN=${FAKE_STDIN_OUT:-/dev/null}
: > "$IN"
while IFS= read -r l; do
    printf '%s\n' "$l" >> "$IN"
    [ -z "$l" ] && break
done
answer() {
    while IFS= read -r l; do
        [ "$l" = nodes ] || continue
        printf 'nodes\n' >> "$IN"
        n=0
        while IFS= read -r x; do
            printf '%s\n' "$x" >> "$IN"
            [ -z "$x" ] && break
            n=$((n + 1))
        done
        [ -n "${FAKE_NOACK:-}" ] || printf '{"type":"nodes","count":%d}\n' "${FAKE_ACK_COUNT:-$n}"
        [ -z "${FAKE_AFTER:-}" ] || printf '%s\n' "$FAKE_AFTER"
    done
    exec sleep 3600
}
case "${FAKE_MODE:-ok}" in
ok) printf '{"type":"ready","dev":"%s"}\n{"type":"active","nodes":["A"]}\n' "$3"; echo 'tunvless[info]: up' >&2; answer ;;
nodes)
    sleep "${FAKE_SLEEP:-0}"
    printf '{"type":"ready","dev":"%s"}\n' "$3"
    if [ -n "${FAKE_EVENTS:-}" ]; then printf '%s\n' "$FAKE_EVENTS"; else printf '{"type":"active","nodes":["A"]}\n'; fi
    answer ;;
closeafter) exec 0<&-; printf '{"type":"ready","dev":"%s"}\n' "$3"; exec sleep 3600 ;;
pins)
    printf '{"type":"ready","dev":"%s"}\n' "$3"
    [ "$(wc -l < "$FAKE_STARTS_OUT")" = 1 ] && printf '{"type":"pins_full"}\n'
    answer ;;
crash) printf '{"type":"ready","dev":"%s"}\n' "$3"; exit 1 ;;
late) sleep "${FAKE_SLEEP:-1}" </dev/null >/dev/null 2>&1; exit 1 ;;
badconf) echo 'tunvless[warn]: bad option' >&2; exit 2 ;;
warnsp) echo "tunvless[warn] tunnel: device $3 was not created" >&2; echo 'tunvless[warn]ing: not a warn tag' >&2; exec sleep 3600 ;;
flood) head -c 5000 /dev/zero | tr '\0' x; printf '\n{"type":"active","nodes":["B"]}\n'; exec sleep 3600 ;;
flood2) head -c 5000 /dev/zero | tr '\0' y >&2; echo >&2; head -c 5000 /dev/zero | tr '\0' x; echo; exec sleep 3600 ;;
down) printf '{"type":"ready","dev":"%s"}\n{"type":"active","nodes":["A"]}\n{"type":"node_down","node":"B","why":"x"}\n' "$3"; answer ;;
emptyev) printf '{"type":"active","nodes":["A"]}\n{"type":"ready","dev":""}\n{"type":"node_down","node":"","why":"x"}\n{"type":"node_up","node":""}\n' ; exec sleep 3600 ;;
esac
