#!/bin/sh
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
if [ -z "$OSSLSIGNCODE" ]; then
  OSSLSIGNCODE=osslsigncode
fi

if [ "${QBIT_ALLOW_LEGACY_WIN_SIGNING:-0}" != "1" ]; then
  cat <<EOF
error: this is the inherited Bitcoin-style key-file signer.

qbit's default Windows signing path is:

  ./azure-detached-sig-create.sh

The bundled win-codesign.cert is inherited from Bitcoin Core and must not be
used for qbit releases. Set QBIT_ALLOW_LEGACY_WIN_SIGNING=1 only if the release
tracker records an explicit fallback decision and the cert/key inputs have been
replaced with qbit-owned material.
EOF
  exit 1
fi

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path to key>"
  echo "example:"
  echo "  QBIT_ALLOW_LEGACY_WIN_SIGNING=1 \\"
  echo "  QBIT_LEGACY_WIN_CERTFILE=qbit-codesign.cert \\"
  echo "  $0 codesign.key"
  exit 1
fi

OUT=signature-win.tar.gz
SRCDIR=unsigned
WORKDIR=./.tmp
OUTDIR="${WORKDIR}/out"
OUTSUBDIR="${OUTDIR}/win"
TIMESERVER="${QBIT_LEGACY_WIN_TIMESERVER:-http://timestamp.acs.microsoft.com/}"
CERTFILE="${QBIT_LEGACY_WIN_CERTFILE:-}"

if [ -z "$CERTFILE" ]; then
  cat <<EOF
error: QBIT_LEGACY_WIN_CERTFILE is required for legacy key-file signing.

Do not use the inherited Bitcoin Core win-codesign.cert for qbit releases.
Prefer ./azure-detached-sig-create.sh unless the release tracker records an
explicit fallback decision.
EOF
  exit 1
fi

stty -echo
printf "Enter the passphrase for %s: " "$1"
read -r cs_key_pass
printf "\n"
stty echo


mkdir -p "${OUTSUBDIR}"
find ${SRCDIR} -wholename "*.exe" -type f -exec realpath --relative-to=. {} \; | while read -r bin
do
    echo Signing "${bin}"
    bin_base="$(realpath --relative-to=${SRCDIR} "${bin}")"
    mkdir -p "$(dirname ${WORKDIR}/"${bin_base}")"
    "${OSSLSIGNCODE}" sign \
        -certs "${CERTFILE}" \
        -t "${TIMESERVER}" \
        -h sha256 \
        -in "${bin}" \
        -out "${WORKDIR}/${bin_base}" \
        -key "$1" \
        -pass "${cs_key_pass}"
    mkdir -p "$(dirname ${OUTSUBDIR}/"${bin_base}")"
    "${OSSLSIGNCODE}" extract-signature \
        -pem \
        -in "${WORKDIR}/${bin_base}" \
        -out "${OUTSUBDIR}/${bin_base}.pem" \
        && rm "${WORKDIR}/${bin_base}"
done

rm -f "${OUT}"
tar -C "${OUTDIR}" -czf "${OUT}" .
rm -rf "${WORKDIR}"
echo "Created ${OUT}"
