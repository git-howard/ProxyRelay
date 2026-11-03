#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  Building ProxyRelay for OpenWrt / Linux"
echo "=========================================================="

mkdir -p build
cd build

cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

echo "=========================================================="
echo "  Build successful!"
echo "  Output binary: $SCRIPT_DIR/build/proxyrelay"
echo "=========================================================="

# 验证二进制可执行与版本输出
./proxyrelay --version || true
