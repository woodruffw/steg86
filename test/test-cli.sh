#!/usr/bin/env bash

TEST_DEPS=(shasum objdump)
FIXTURE="${FIXTURE:-/bin/bash}"

function steg86 {
  cargo run -q -- "${@}"
}

function die {
  >&2 echo "Fatal: ${*}"
  exit 1
}

function installed {
  cmd=$(command -v "${1}")

  [[ -n "${cmd}" ]] && [[ -f "${cmd}" ]]
  return ${?}
}

function test_steg86_profile_has_consistent_output {
  echo -n "${FUNCNAME[0]} "

  profile1=$(steg86 profile "${FIXTURE}")
  profile2=$(steg86 profile "${FIXTURE}")

  [[ "${profile1}" = "${profile2}" ]] || die "steg86 profile runs do not match"

  echo "OK"
}

function test_steg86_embed_extract_roundtrip {
  echo -n "${FUNCNAME[0]} "

  embedded=$(mktemp /tmp/steg86-XXXXX)
  head -c 1024 < /dev/urandom > "${embedded}"

  stegdest=$(mktemp -u /tmp/steg86-XXXXX)
  steg86 embed "${FIXTURE}" "${stegdest}" < "${embedded}"

  extracted=$(mktemp /tmp/steg86-XXXXX)
  steg86 extract "${stegdest}" > "${extracted}"

  embedded_cksum=$(shasum < "${embedded}")
  extracted_cksum=$(shasum < "${extracted}")

  rm -f "${embedded}" "${stegdest}" "${extracted}"

  [[ "${embedded_cksum}" = "${extracted_cksum}" ]] \
    || die "steg86 embed/extract does not roundtrip correctly"

  echo "OK"
}

function test_steg86_embed_extract_roundtrip_raw {
  echo -n "${FUNCNAME[0]} "

  raw_text=$(mktemp -u /tmp/steg86-XXXXX)
  objcopy "${FIXTURE}" /dev/null --dump-section .text="${raw_text}"

  embedded=$(mktemp /tmp/steg86-XXXXX)
  head -c 1024 < /dev/urandom > "${embedded}"

  stegdest=$(mktemp -u /tmp/steg86-XXXXX)
  steg86 embed --raw "${raw_text}" "${stegdest}" < "${embedded}"

  extracted=$(mktemp /tmp/steg86-XXXXX)
  steg86 extract --raw "${stegdest}" > "${extracted}"

  embedded_cksum=$(shasum < "${embedded}")
  extracted_cksum=$(shasum < "${extracted}")

  rm -f "${raw_text}" "${embedded}" "${stegdest}" "${extracted}"

  [[ "${embedded_cksum}" = "${extracted_cksum}" ]] \
    || die "steg86 raw embed/extract does not roundtrip correctly"

  echo "OK"
}

for dep in "${TEST_DEPS[@]}"; do
  installed "${dep}" || die "Missing test dependency: ${dep}"
done

[[ -f "${FIXTURE}" ]] || die "missing fixture to test with: ${FIXTURE}"
[[ "$(uname -m)" = "x86_64" ]] || die "CLI tests must be run on x86_64"

test_steg86_profile_has_consistent_output
test_steg86_embed_extract_roundtrip
test_steg86_embed_extract_roundtrip_raw

exit 0
