#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/build/proxyrelay"

if [ ! -f "$BIN_PATH" ]; then
    echo "Error: Binary not found at $BIN_PATH. Please run ./build.sh first."
    exit 1
fi

PKG_NAME="proxyrelay"
PKG_VERSION="1.0.0-1"
PKG_ARCH="x86_64"
IPK_FILE="${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"

TMP_DIR=$(mktemp -d -t proxyrelay_pkg_XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

DATA_DIR="$TMP_DIR/data"
CONTROL_DIR="$TMP_DIR/control"
IPK_BUILD="$TMP_DIR/ipk"

mkdir -p "$DATA_DIR/usr/bin"
mkdir -p "$DATA_DIR/etc/init.d"
mkdir -p "$DATA_DIR/etc/config"
mkdir -p "$DATA_DIR/usr/share/proxyrelay/ui"
mkdir -p "$DATA_DIR/usr/share/rpcd/acl.d"
mkdir -p "$DATA_DIR/usr/lib/lua/luci/controller"
mkdir -p "$DATA_DIR/usr/lib/lua/luci/model/cbi"
mkdir -p "$CONTROL_DIR"
mkdir -p "$IPK_BUILD"

echo "=========================================================="
echo "  Packaging $IPK_FILE"
echo "=========================================================="

# 1. 拷贝并压缩剥离可执行程序 (strip)
cp "$BIN_PATH" "$DATA_DIR/usr/bin/proxyrelay"
strip --strip-unneeded "$DATA_DIR/usr/bin/proxyrelay"
chmod 755 "$DATA_DIR/usr/bin/proxyrelay"

# 2. 拷贝系统脚本与配置文件
cp "$SCRIPT_DIR/files/etc/init.d/proxyrelay" "$DATA_DIR/etc/init.d/proxyrelay"
chmod 755 "$DATA_DIR/etc/init.d/proxyrelay"

cp "$SCRIPT_DIR/files/etc/config/proxyrelay" "$DATA_DIR/etc/config/proxyrelay"
chmod 644 "$DATA_DIR/etc/config/proxyrelay"

cp "$SCRIPT_DIR/files/usr/share/proxyrelay/firewall.include" "$DATA_DIR/usr/share/proxyrelay/firewall.include"
chmod 755 "$DATA_DIR/usr/share/proxyrelay/firewall.include"

cp "$SCRIPT_DIR/files/usr/share/proxyrelay/component_manager.sh" "$DATA_DIR/usr/share/proxyrelay/component_manager.sh"
chmod 755 "$DATA_DIR/usr/share/proxyrelay/component_manager.sh"

cp "$SCRIPT_DIR/files/usr/share/rpcd/acl.d/luci-app-proxyrelay.json" "$DATA_DIR/usr/share/rpcd/acl.d/luci-app-proxyrelay.json"
chmod 644 "$DATA_DIR/usr/share/rpcd/acl.d/luci-app-proxyrelay.json"

cp "$SCRIPT_DIR/files/usr/lib/lua/luci/controller/proxyrelay.lua" "$DATA_DIR/usr/lib/lua/luci/controller/proxyrelay.lua"
chmod 644 "$DATA_DIR/usr/lib/lua/luci/controller/proxyrelay.lua"

cp "$SCRIPT_DIR/files/usr/lib/lua/luci/model/cbi/proxyrelay.lua" "$DATA_DIR/usr/lib/lua/luci/model/cbi/proxyrelay.lua"
chmod 644 "$DATA_DIR/usr/lib/lua/luci/model/cbi/proxyrelay.lua"

cp "$SCRIPT_DIR/ui/index.html" "$DATA_DIR/usr/share/proxyrelay/ui/index.html"
chmod 644 "$DATA_DIR/usr/share/proxyrelay/ui/index.html"

# 3. 计算安装体积 (KB)
INSTALLED_SIZE=$(du -ks "$DATA_DIR" | cut -f1)

# 4. 生成 control 文件
cat > "$CONTROL_DIR/control" << EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Depends: libc, libpthread, libstdcpp, libopenssl
Section: net
Architecture: $PKG_ARCH
Maintainer: ProxyRelay Team
Installed-Size: $INSTALLED_SIZE
Description: ProxyRelay is an enterprise-grade secondary proxy relay and transparent proxy gateway with WebUI.
EOF

# 5. 生成 conffiles 保留用户配置
cat > "$CONTROL_DIR/conffiles" << 'EOF'
/etc/config/proxyrelay
EOF

# 6. 生成 postinst 自动设置自启动与权限
cat > "$CONTROL_DIR/postinst" << 'EOF'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || {
    /etc/init.d/proxyrelay enable
    echo "ProxyRelay installed successfully. WebUI: http://<router-ip>:8080"
}
exit 0
EOF
chmod 755 "$CONTROL_DIR/postinst"

# 7. 生成 prerm 卸载前停止服务
cat > "$CONTROL_DIR/prerm" << 'EOF'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] || {
    /etc/init.d/proxyrelay stop 2>/dev/null
    /etc/init.d/proxyrelay disable 2>/dev/null
}
exit 0
EOF
chmod 755 "$CONTROL_DIR/prerm"

# 8. 打包 data.tar.gz 与 control.tar.gz
(cd "$DATA_DIR" && tar -czf "$IPK_BUILD/data.tar.gz" --owner=0 --group=0 .)
(cd "$CONTROL_DIR" && tar -czf "$IPK_BUILD/control.tar.gz" --owner=0 --group=0 .)
echo "2.0" > "$IPK_BUILD/debian-binary"

# 9. 生成 opkg 规范的 ipk 包
(cd "$IPK_BUILD" && tar -czf "$SCRIPT_DIR/$IPK_FILE" debian-binary control.tar.gz data.tar.gz)

# 打包完成，发布物保留在当前目录

echo "=========================================================="
echo "  Successfully built IPK package:"
echo "  -> $SCRIPT_DIR/$IPK_FILE"
ls -lh "$SCRIPT_DIR/$IPK_FILE"
echo "=========================================================="
