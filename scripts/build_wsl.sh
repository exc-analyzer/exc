#!/bin/bash
set -e

# Mevcut dizin (Windows path mounted in WSL)
ORIG_DIR=$(pwd)
echo "Original dir: $ORIG_DIR"

# Gecici dizin olustu
TEMP_DIR=$(mktemp -d)
echo "Working in temp dir: $TEMP_DIR"

# Kaynak kodlari kopyala (nokta dosyalari dahil)
cp -r . "$TEMP_DIR/src"

cd "$TEMP_DIR/src"

echo "Fixing permissions..."
# debian/docs gibi dosyalar windows'dan gelirken executable gelebilir, duzelt
chmod -x debian/docs debian/control debian/install debian/compat debian/*.install 2>/dev/null || true
chmod +x debian/rules

echo "Cleaning up..."
rm -rf dist build *.egg-info debian/exc-analyzer debian/.debhelper debian/*.log debian/*.substvars

echo "Building package..."
# dpkg-buildpackage hata verirse logu kopyala ve cik
if ! dpkg-buildpackage -us -uc > build.log 2>&1; then
    echo "Build FAILED!"
    chmod 644 build.log
    cp build.log "$ORIG_DIR/build_error.log"
    echo "Log copied to $ORIG_DIR/build_error.log"
    tail -n 20 build.log
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "Copying artifacts back..."
cp ../*.deb "$ORIG_DIR/"

# Temizlik
cd "$ORIG_DIR"
rm -rf "$TEMP_DIR"

echo "Build Completed Successfully!"
