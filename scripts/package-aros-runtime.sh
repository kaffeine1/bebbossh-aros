#!/usr/bin/env sh
set -eu

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
