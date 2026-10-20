# The sources both busybox builds use, sourced by build.sh and build-windows.sh.
#
# Pinned, and refused if their checksums differ:
#   * busybox.net's busybox-1.37.0.tar.bz2, by the sha256 busybox.net publishes;
#   * Alpine's busyboxconfig at aports commit a8dcedab, by the sha512 in that
#     commit's APKBUILD. It is the config behind Alpine's busybox-static
#     1.37.0-r20, the musl busybox Ferrix's test-shell already runs, so the two
#     binaries differ in their C library and not in their applets.
#
# Each has a mirror, fetched when its upstream does not answer: Alpine's
# distfiles for the tarball, and aports' own GitHub mirror, at the same
# commit, for the config. gitlab.alpinelinux.org answers GitHub's Actions
# runners 418 (seen on 2026-10-20, the v0.1.0 release's jobs and a probe
# job beside them), and busybox.net turns away clients it takes for robots.
# A mirror is checked against the same pin, so it can never change the bytes.

VERSION=1.37.0
TARBALL=busybox-$VERSION.tar.bz2
TARBALL_URL=https://busybox.net/downloads/$TARBALL
TARBALL_MIRROR=https://distfiles.alpinelinux.org/distfiles/v3.22/$TARBALL
TARBALL_SHA256=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4
APORTS_COMMIT=a8dcedab8fd001d8a35a703a70140fa071b3fa29
CONFIG_URL=https://gitlab.alpinelinux.org/alpine/aports/-/raw/$APORTS_COMMIT/main/busybox/busyboxconfig
CONFIG_MIRROR=https://raw.githubusercontent.com/alpinelinux/aports/$APORTS_COMMIT/main/busybox/busyboxconfig
CONFIG_SHA512=93f0fa512a394a07f760b13bd70a28424d3ad1a6c283b77fd4894114c5b472cfbe65f3441afa28596771d75527aaa9794706a3b329b4898e5d83bce799169929

# The file is kept once it matches. Its URLs, upstream first and then its
# mirrors, are tried in turn until one gives the pinned bytes; a download
# that differs is thrown away and the next URL tried, and a kept file that
# differs is refused. Only a file that matches is ever moved into place.
fetch() { # "url [mirror ...]" file checksum-command checksum
    local urls=$1 file=$2 tool=$3 sum=$4 url got
    if [ -f "$file" ]; then
        got=$("$tool" "$file" | cut -d' ' -f1)
        if [ "$got" != "$sum" ]; then
            echo "${0##*/}: $file does not match its pinned $tool" >&2
            echo "  expected $sum" >&2
            echo "  got      $got" >&2
            exit 1
        fi
        return
    fi
    for url in $urls; do
        rm -f "$file.part"
        if ! curl -fsSL --max-time 300 -o "$file.part" "$url"; then
            echo "${0##*/}: $url did not answer; trying the next source" >&2
            continue
        fi
        got=$("$tool" "$file.part" | cut -d' ' -f1)
        if [ "$got" = "$sum" ]; then
            mv "$file.part" "$file"
            return
        fi
        echo "${0##*/}: $url gave a ${file##*/} that does not match its pinned $tool" >&2
        echo "  expected $sum" >&2
        echo "  got      $got" >&2
    done
    rm -f "$file.part"
    echo "${0##*/}: no source gave ${file##*/} with its pinned $tool: $urls" >&2
    exit 1
}

fetch_sources() { # directory
    mkdir -p "$1"
    fetch "$TARBALL_URL $TARBALL_MIRROR" "$1/$TARBALL" sha256sum "$TARBALL_SHA256"
    fetch "$CONFIG_URL $CONFIG_MIRROR" "$1/busyboxconfig" sha512sum "$CONFIG_SHA512"
    echo "busybox $VERSION and Alpine's config at $APORTS_COMMIT, both verified"
}
