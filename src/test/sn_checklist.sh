#!/bin/bash

PORT_HOST="${PORT_HOST:-207.246.96.13}"


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
