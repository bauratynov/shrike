#!/usr/bin/env bash
# shrike-serve — minimal HTTP server exposing shrike as a REST endpoint.
#
# Wraps socat(1). Each connection hands the HTTP body to shrike via
# stdin (not supported directly) — the wrapper writes the body to a
# temp file, invokes shrike --json, and streams the output back.
#
# Intentionally a shell script, not a C server: keeps the shrike
# binary freestanding, avoids bringing a web server into the audit
# surface, and ships a 40-line workflow you can read end-to-end.
#
# Usage:
#   tools/shrike-serve.sh 8080
# then
#   curl -X POST --data-binary @/bin/ls http://localhost:8080/scan

set -euo pipefail

port="${1:-8080}"
shrike_bin="${SHRIKE_BIN:-./shrike}"

if ! command -v socat >/dev/null 2>&1; then
    echo "shrike-serve: socat(1) required" >&2
    exit 1
fi
if [[ ! -x "$shrike_bin" ]]; then
    echo "shrike-serve: $shrike_bin not executable; set SHRIKE_BIN" >&2
    exit 1
fi

handler() {
    # Parse request line + headers (minimal).
    local line="" body_len=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [[ -z "$line" ]] && break
        if [[ "$line" =~ ^[Cc]ontent-[Ll]ength:\ *([0-9]+) ]]; then
            body_len="${BASH_REMATCH[1]}"
        fi
    done

    local tmp=$(mktemp)
    trap "rm -f '$tmp'" EXIT
    if [[ "$body_len" -gt 0 ]]; then
        head -c "$body_len" > "$tmp"
    fi

    # Invoke shrike.
    local out
    out=$("$shrike_bin" --json --quiet "$tmp" 2>/dev/null || true)
    local len=${#out}

    printf 'HTTP/1.1 200 OK\r\n'
    printf 'Content-Type: application/x-ndjson\r\n'
    printf 'Content-Length: %d\r\n' "$len"
    printf 'Connection: close\r\n\r\n'
    printf '%s' "$out"
}

export -f handler
export SHRIKE_BIN="$shrike_bin"

echo "shrike-serve: listening on :$port (POST /scan with binary body)"
exec socat -T 10 TCP-LISTEN:"$port",reuseaddr,fork EXEC:'bash -c handler',pty
