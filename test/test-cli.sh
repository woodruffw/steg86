#!/usr/bin/env bash

FIXTURE="${FIXTURE:-/bin/bash}"

function steg86 {
  cargo run -q -- "${@}"
}

function die {
  >&2 echo "Fatal: ${*}"
  exit 1
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

[[ -f "${FIXTURE}" ]] || die "missing fixture to test with: ${FIXTURE}"

test_steg86_profile_has_consistent_output
test_steg86_embed_extract_roundtrip

exit 0
