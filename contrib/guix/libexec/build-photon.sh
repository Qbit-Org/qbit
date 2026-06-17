#!/usr/bin/env bash
# Copyright (c) 2026 The qbit core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
export LC_ALL=C
set -e -o pipefail
export TZ=UTC

umask 0022

if [ -n "$V" ]; then
    set -vx
    export VERBOSE="$V"
fi

cat << EOF
Required environment variables as seen inside the container:
    DIST_ARCHIVE_BASE: ${DIST_ARCHIVE_BASE:?not set}
    DISTNAME: ${DISTNAME:?not set}
    PHOTON_DISTNAME: ${PHOTON_DISTNAME:?not set}
    VERSION: ${VERSION:?not set}
    HOST: ${HOST:?not set}
    SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:?not set}
    JOBS: ${JOBS:?not set}
    DISTSRC: ${DISTSRC:?not set}
    OUTDIR: ${OUTDIR:?not set}
EOF

ACTUAL_OUTDIR="${OUTDIR}"
OUTDIR="${DISTSRC}/output"

BASEPREFIX="${PWD}/depends"

store_path() {
    grep --extended-regexp "/[^-]{32}-${1}-[^-]+${2:+-${2}}" "${GUIX_ENVIRONMENT}/manifest" \
        | head --lines=1 \
        | sed --expression='s|\x29*$||' \
              --expression='s|^[[:space:]]*"||' \
              --expression='s|"[[:space:]]*$||'
}

NATIVE_GCC="$(store_path gcc-toolchain)"
NATIVE_GCC_STATIC="$(store_path gcc-toolchain static)"

unset LIBRARY_PATH
unset CPATH
unset C_INCLUDE_PATH
unset CPLUS_INCLUDE_PATH
unset OBJC_INCLUDE_PATH
unset OBJCPLUS_INCLUDE_PATH

build_CC="${NATIVE_GCC}/bin/gcc -isystem ${NATIVE_GCC}/include"
build_CXX="${NATIVE_GCC}/bin/g++ -isystem ${NATIVE_GCC}/include/c++ -isystem ${NATIVE_GCC}/include"
export LIBRARY_PATH="${NATIVE_GCC}/lib:${NATIVE_GCC_STATIC}/lib"

case "$HOST" in
    *linux*)
        CROSS_GLIBC="$(store_path "glibc-cross-${HOST}")"
        CROSS_GLIBC_STATIC="$(store_path "glibc-cross-${HOST}" static)"
        CROSS_KERNEL="$(store_path "linux-libre-headers-cross-${HOST}")"
        CROSS_GCC="$(store_path "gcc-cross-${HOST}")"
        CROSS_GCC_LIB_STORE="$(store_path "gcc-cross-${HOST}" lib)"
        CROSS_GCC_LIBS=( "${CROSS_GCC_LIB_STORE}/lib/gcc/${HOST}"/* )
        CROSS_GCC_LIB="${CROSS_GCC_LIBS[0]}"

        export CROSS_C_INCLUDE_PATH="${CROSS_GCC_LIB}/include:${CROSS_GCC_LIB}/include-fixed:${CROSS_GLIBC}/include:${CROSS_KERNEL}/include"
        export CROSS_CPLUS_INCLUDE_PATH="${CROSS_GCC}/include/c++:${CROSS_GCC}/include/c++/${HOST}:${CROSS_GCC}/include/c++/backward:${CROSS_C_INCLUDE_PATH}"
        export CROSS_LIBRARY_PATH="${CROSS_GCC_LIB_STORE}/lib:${CROSS_GCC_LIB}:${CROSS_GLIBC}/lib:${CROSS_GLIBC_STATIC}/lib"
        ;;
    *)
        echo "Unsupported HOST for qbit-photon Guix packaging: '$HOST'" >&2
        exit 1
        ;;
esac

IFS=':' read -ra PATHS <<< "${CROSS_C_INCLUDE_PATH}:${CROSS_CPLUS_INCLUDE_PATH}:${CROSS_LIBRARY_PATH}"
for p in "${PATHS[@]}"; do
    if [ -n "$p" ] && [ ! -d "$p" ]; then
        echo "'$p' doesn't exist or isn't a directory... Aborting..."
        exit 1
    fi
done

export GUIX_LD_WRAPPER_DISABLE_RPATH=yes

[ -e /usr/bin ] || mkdir -p /usr/bin
[ -e /usr/bin/env ] || ln -s --no-dereference "$(command -v env)" /usr/bin/env

case "$HOST" in
    x86_64-linux-gnu)    glibc_dynamic_linker=/lib64/ld-linux-x86-64.so.2 ;;
    arm-linux-gnueabihf) glibc_dynamic_linker=/lib/ld-linux-armhf.so.3 ;;
    aarch64-linux-gnu)   glibc_dynamic_linker=/lib/ld-linux-aarch64.so.1 ;;
    riscv64-linux-gnu)   glibc_dynamic_linker=/lib/ld-linux-riscv64-lp64d.so.1 ;;
    powerpc64-linux-gnu) glibc_dynamic_linker=/lib64/ld64.so.1 ;;
    *)
        echo "Unsupported Linux HOST for qbit-photon Guix packaging: '$HOST'" >&2
        exit 1
        ;;
esac

export TAR_OPTIONS="--owner=0 --group=0 --numeric-owner --mtime='@${SOURCE_DATE_EPOCH}' --sort=name"

make -C depends --jobs="$JOBS" HOST="$HOST" \
                                   NO_BOOST=1 NO_LIBEVENT=1 NO_QT=1 NO_QR=1 NO_WALLET=1 NO_USDT=1 NO_IPC=1 NO_ZMQ= NO_PHOTON= \
                                   ${V:+V=1} \
                                   ${SOURCES_PATH+SOURCES_PATH="$SOURCES_PATH"} \
                                   ${BASE_CACHE+BASE_CACHE="$BASE_CACHE"} \
                                   ${build_CC+build_CC="$build_CC"} \
                                   ${build_CXX+build_CXX="$build_CXX"} \
                                   x86_64_linux_CC=x86_64-linux-gnu-gcc \
                                   x86_64_linux_CXX=x86_64-linux-gnu-g++ \
                                   x86_64_linux_AR=x86_64-linux-gnu-gcc-ar \
                                   x86_64_linux_RANLIB=x86_64-linux-gnu-gcc-ranlib \
                                   x86_64_linux_NM=x86_64-linux-gnu-gcc-nm \
                                   x86_64_linux_STRIP=x86_64-linux-gnu-strip

GIT_ARCHIVE="${DIST_ARCHIVE_BASE}/${DISTNAME}.tar.gz"
if [ ! -e "$GIT_ARCHIVE" ]; then
    mkdir -p "$(dirname "$GIT_ARCHIVE")"
    git archive --prefix="${DISTNAME}/" --output="$GIT_ARCHIVE" HEAD
fi

mkdir -p "$OUTDIR"
mkdir -p "$DISTSRC"

HOST_CFLAGS="-O2 -g -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-all"
case "$HOST" in
    x86_64-linux-gnu) HOST_CFLAGS+=" -fcf-protection=full" ;;
esac
HOST_CFLAGS+=$(find /gnu/store -maxdepth 1 -mindepth 1 -type d -exec echo -n " -ffile-prefix-map={}=/usr" \;)
HOST_CXXFLAGS="$HOST_CFLAGS"
HOST_LDFLAGS="-Wl,--as-needed -Wl,--dynamic-linker=$glibc_dynamic_linker -static-libstdc++ -Wl,-O2 -Wl,-z,relro -Wl,-z,now"

(
    cd "$DISTSRC"

    tar --strip-components=1 -xf "${GIT_ARCHIVE}"

    env CFLAGS="${HOST_CFLAGS}" CXXFLAGS="${HOST_CXXFLAGS}" LDFLAGS="${HOST_LDFLAGS}" \
    cmake -S contrib/photon -B build-photon \
          --toolchain "${BASEPREFIX}/${HOST}/toolchain.cmake" \
          -Werror=dev \
          -DPHOTON_BUILD_TESTS=OFF \
          -DPHOTON_BUILD_BENCHMARKS=OFF \
          -DPHOTON_ENABLE_FUZZ=OFF \
          -DOPENSSL_USE_STATIC_LIBS=TRUE \
          -DQBIT_PHOTON_VERSION="${VERSION}"

    cmake --build build-photon -j "$JOBS" ${V:+--verbose}

    python3 contrib/guix/security-check.py build-photon/qbit-photon
    python3 contrib/guix/symbol-check.py build-photon/qbit-photon

    INSTALLPATH="${PWD}/installed"
    mkdir -p "${INSTALLPATH}/${PHOTON_DISTNAME}"
    cmake --install build-photon --prefix "${INSTALLPATH}/${PHOTON_DISTNAME}" ${V:+--verbose}

    (
        cd installed

        find "${PHOTON_DISTNAME}/bin" -type f -executable -print0 \
            | xargs -0 -P"$JOBS" -I{} "${DISTSRC}/build-photon/split-debug.sh" {} {} {}.dbg

        find "${PHOTON_DISTNAME}" -not -name "*.dbg" -print0 \
            | sort --zero-terminated \
            | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
            | gzip -9n > "${OUTDIR}/${PHOTON_DISTNAME}-${HOST}.tar.gz" \
            || ( rm -f "${OUTDIR}/${PHOTON_DISTNAME}-${HOST}.tar.gz" && exit 1 )

        find "${PHOTON_DISTNAME}" -name "*.dbg" -print0 \
            | sort --zero-terminated \
            | tar --create --no-recursion --mode='u+rw,go+r-w,a+X' --null --files-from=- \
            | gzip -9n > "${OUTDIR}/${PHOTON_DISTNAME}-${HOST}-debug.tar.gz" \
            || ( rm -f "${OUTDIR}/${PHOTON_DISTNAME}-${HOST}-debug.tar.gz" && exit 1 )
    )
)

rm -rf "$ACTUAL_OUTDIR"
mv --no-target-directory "$OUTDIR" "$ACTUAL_OUTDIR" \
    || ( rm -rf "$ACTUAL_OUTDIR" && exit 1 )

(
    cd /outdir-base
    {
        echo "$GIT_ARCHIVE"
        find "$ACTUAL_OUTDIR" -type f
    } | xargs realpath --relative-base="$PWD" \
      | xargs sha256sum \
      | sort -k2 \
      | sponge "$ACTUAL_OUTDIR"/SHA256SUMS.part
)
