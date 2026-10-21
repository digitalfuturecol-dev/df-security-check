#!/usr/bin/env bash
# Genera build/df-security-check.zip con solo los archivos del plugin.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build && mkdir -p build/df-security-check
cp -R df-security-check.php uninstall.php readme.txt LICENSE includes languages data build/df-security-check/
(cd build && zip -rq df-security-check.zip df-security-check -x '*.DS_Store')
rm -rf build/df-security-check
echo "build/df-security-check.zip"
