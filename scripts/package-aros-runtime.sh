#!/usr/bin/env sh
# AROS runtime packaging changes Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
set -eu

# Defaults produce the current stable AROS i386 package. Pass explicit
# outdir/pkgdir values for other targets, for example AROS x86_64.
outdir=${1:-aros-i386-abiv0-arosone}
pkgdir=${2:-dist/bebbossh-aros-i386-abiv0}

# Derive the architecture token from the package directory so the kit ships the
# architecture-specific public-release smoke script and release checklist
# instead of always embedding the i386 ones.
case "$pkgdir" in
    *x86_64*) arch=x86_64; ARCH=X86_64 ;;
    *) arch=i386; ARCH=I386 ;;
esac
release_smoke="scripts/aros-${arch}-public-release-smoke.sh"
release_doc="docs/AROS_${ARCH}_RELEASE.md"

for tool in bebbossh bebboscp bebbosshd bebbosshkeygen; do
    if [ ! -x "$outdir/$tool" ]; then
        echo "missing executable: $outdir/$tool" >&2
        exit 1
    fi
done

rm -rf "$pkgdir"
mkdir -p "$pkgdir"

cp "$outdir/bebbossh" "$pkgdir/bebbossh"
cp "$outdir/bebboscp" "$pkgdir/bebboscp"
cp "$outdir/bebbosshd" "$pkgdir/bebbosshd"
cp "$outdir/bebbosshkeygen" "$pkgdir/bebbosshkeygen"
cp packaging/aros/sshd_config.example "$pkgdir/sshd_config.example"
cp packaging/aros/passwd.example "$pkgdir/passwd.example"
cp packaging/aros/README.AROS.txt "$pkgdir/README.AROS.txt"
mkdir -p "$pkgdir/scripts"
cp scripts/aros-ssh-smoke-test.sh "$pkgdir/scripts/aros-ssh-smoke-test.sh"
cp scripts/aros-auth-forward-test.sh "$pkgdir/scripts/aros-auth-forward-test.sh"
cp scripts/aros-transfer-stress-test.sh "$pkgdir/scripts/aros-transfer-stress-test.sh"
have_release_smoke=
if [ -f "$release_smoke" ]; then
    cp "$release_smoke" "$pkgdir/$release_smoke"
    have_release_smoke=yes
else
    echo "warning: missing $release_smoke; packaging without it" >&2
fi
mkdir -p "$pkgdir/docs"
cp docs/AROS_TESTER.md "$pkgdir/docs/AROS_TESTER.md"
have_release_doc=
if [ -f "$release_doc" ]; then
    cp "$release_doc" "$pkgdir/$release_doc"
    have_release_doc=yes
else
    echo "warning: missing $release_doc; packaging without it" >&2
fi
cp README.md "$pkgdir/README.md"
cp AROS_PORTING.md "$pkgdir/AROS_PORTING.md"
cp COPYING "$pkgdir/COPYING"
cp LICENSE "$pkgdir/LICENSE"

(
    cd "$pkgdir"
    set -- bebbossh bebboscp bebbosshd bebbosshkeygen \
        sshd_config.example passwd.example README.AROS.txt \
        scripts/aros-ssh-smoke-test.sh \
        scripts/aros-auth-forward-test.sh \
        scripts/aros-transfer-stress-test.sh
    [ -n "$have_release_smoke" ] && set -- "$@" "$release_smoke"
    set -- "$@" docs/AROS_TESTER.md
    [ -n "$have_release_doc" ] && set -- "$@" "$release_doc"
    set -- "$@" README.md AROS_PORTING.md COPYING LICENSE
    shasum -a 256 "$@" > SHA256SUMS
)

archive_base=${pkgdir%/}
rm -f "$archive_base.tar.gz" "$archive_base.zip"
tar -C "$(dirname "$archive_base")" -czf "$archive_base.tar.gz" "$(basename "$archive_base")"

if command -v zip >/dev/null 2>&1; then
    (
        cd "$(dirname "$archive_base")"
        zip -qr "$(basename "$archive_base").zip" "$(basename "$archive_base")"
    )
fi

echo "created $pkgdir"
echo "created $archive_base.tar.gz"
if [ -f "$archive_base.zip" ]; then
    echo "created $archive_base.zip"
fi
