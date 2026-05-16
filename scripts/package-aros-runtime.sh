#!/usr/bin/env sh
# AROS runtime packaging changes Copyright (C) 2026 Michele Dipace <michele.dipace@kaffeine.net>
set -eu

# Defaults produce the current stable AROS i386 package. Pass explicit
# outdir/pkgdir values for other targets, for example AROS x86_64.
outdir=${1:-aros-i386-abiv0-arosone}
pkgdir=${2:-dist/bebbossh-aros-i386}

if [ ! -x "$outdir/bebbosshd" ]; then
    echo "missing executable: $outdir/bebbosshd" >&2
    exit 1
fi

if [ ! -x "$outdir/bebbosshkeygen" ]; then
    echo "missing executable: $outdir/bebbosshkeygen" >&2
    exit 1
fi

rm -rf "$pkgdir"
mkdir -p "$pkgdir"

cp "$outdir/bebbosshd" "$pkgdir/bebbosshd"
cp "$outdir/bebbosshkeygen" "$pkgdir/bebbosshkeygen"
cp packaging/aros/sshd_config.example "$pkgdir/sshd_config.example"
cp packaging/aros/passwd.example "$pkgdir/passwd.example"
cp packaging/aros/README.AROS.txt "$pkgdir/README.AROS.txt"
mkdir -p "$pkgdir/scripts"
cp scripts/aros-ssh-smoke-test.sh "$pkgdir/scripts/aros-ssh-smoke-test.sh"
cp scripts/aros-auth-forward-test.sh "$pkgdir/scripts/aros-auth-forward-test.sh"
cp scripts/aros-transfer-stress-test.sh "$pkgdir/scripts/aros-transfer-stress-test.sh"
mkdir -p "$pkgdir/docs"
cp docs/AROS_TESTER.md "$pkgdir/docs/AROS_TESTER.md"
cp README.md "$pkgdir/README.md"
cp AROS_PORTING.md "$pkgdir/AROS_PORTING.md"
cp COPYING "$pkgdir/COPYING"
cp LICENSE "$pkgdir/LICENSE"

(
    cd "$pkgdir"
    shasum -a 256 \
        bebbosshd \
        bebbosshkeygen \
        sshd_config.example \
        passwd.example \
        README.AROS.txt \
        scripts/aros-ssh-smoke-test.sh \
        scripts/aros-auth-forward-test.sh \
        scripts/aros-transfer-stress-test.sh \
        docs/AROS_TESTER.md \
        README.md \
        AROS_PORTING.md \
        COPYING \
        LICENSE > SHA256SUMS
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
