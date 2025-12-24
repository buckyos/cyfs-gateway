#!/bin/bash

PORT_HOST="${PORT_HOST:-207.246.96.13}"
VERBOSE="${VERBOSE:-0}"


check_dig() {
  local label="$1"
  local cmd="$2"
  local expect_regex="$3"
  local output

  echo ""
  echo "== $label"
  echo "$ $cmd"
  output=$(eval "$cmd" 2>&1)
  if [[ $? -eq 0 && -n "$output" && "$output" =~ $expect_regex ]]; then
    echo "✓ $label"
  else
    echo "✗ $label"
    echo "$output"
  fi
}

check_port() {
  local label="$1"
  local host="$2"
  local port="$3"
  local cmd="nc -z -w 2 $host $port"
  local output

  echo ""
  echo "== $label"
  echo "$ $cmd"
  output=$(eval "$cmd" 2>&1)
  if [[ $? -eq 0 ]]; then
    echo "✓ $label"
  else
    echo "✗ $label"
    echo "$output"
  fi
}

check_cert() {
  local label="$1"
  local host="$2"
  local port="$3"
  local cmd="openssl s_client -connect $host:$port -servername $host -tls1_2 -showcerts"
  local output
  local cert_count
  local verify_ok

  echo ""
  echo "== $label"
  echo "$ $cmd"
  output=$(echo "" | eval "$cmd" 2>&1)
  cert_count=$(printf "%s\n" "$output" | awk 'BEGIN{c=0} /BEGIN CERTIFICATE/{c++} END{print c}')
  verify_ok=$(printf "%s\n" "$output" | awk '/Verify return code: 0 \(ok\)/{print "ok"}')

  if [[ "$cert_count" -ge 2 && "$verify_ok" == "ok" ]]; then
    echo "✓ $label"
  else
    echo "✗ $label"
    echo "cert_count=$cert_count verify_ok=$verify_ok"
    if [[ "$VERBOSE" == "1" ]]; then
      echo "$output"
    fi
  fi
}

check_dig "指定sn IP dig" \
  "dig @207.246.96.13 sn.buckyos.ai" \
  "ANSWER SECTION"

check_dig "local dns dig txt" \
  "dig @207.246.96.13 -t A test-addr.web3.buckyos.ai" \
  "ANSWER SECTION"

check_dig "ns dig web3.buckyos.ai" \
  "dig -t NS web3.buckyos.ai" \
  "status: NOERROR"

check_port "port 2980 open" "$PORT_HOST" "2980"

check_cert "sn.buckyos.ai cert fullchain valid" "sn.buckyos.ai" "443"
