#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/build/proxyrelay"

echo "Ensuring binary is up to date..."
(cd "$SCRIPT_DIR/build" && make -j$(nproc)) || (cd "$SCRIPT_DIR" && ./build.sh)

PKG_NAME="proxyrelay"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"
PKG_ARCH="x86_64"

IPK_FILE="${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_${PKG_ARCH}.ipk"
APK_FILE="${PKG_NAME}-${PKG_VERSION}-r${PKG_RELEASE}.${PKG_ARCH}.apk"

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
echo "  Building Universal Packages for OpenWrt (21-25+)"
echo "  Target Architecture: $PKG_ARCH"
echo "=========================================================="

# 1. 拷贝二进制并剥离调试符号 (strip)
cp "$BIN_PATH" "$DATA_DIR/usr/bin/proxyrelay"
strip --strip-unneeded "$DATA_DIR/usr/bin/proxyrelay"
chmod 755 "$DATA_DIR/usr/bin/proxyrelay"

# 2. 拷贝系统配置文件与服务脚本
cp "$SCRIPT_DIR/files/etc/init.d/proxyrelay" "$DATA_DIR/etc/init.d/proxyrelay"
chmod 755 "$DATA_DIR/etc/init.d/proxyrelay"

cp "$SCRIPT_DIR/files/etc/config/proxyrelay" "$DATA_DIR/etc/config/proxyrelay"
chmod 644 "$DATA_DIR/etc/config/proxyrelay"

# 3. 拷贝防火墙重定向脚本与组件管理工具
cp "$SCRIPT_DIR/files/usr/share/proxyrelay/firewall.include" "$DATA_DIR/usr/share/proxyrelay/firewall.include"
chmod 755 "$DATA_DIR/usr/share/proxyrelay/firewall.include"

cp "$SCRIPT_DIR/files/usr/share/proxyrelay/component_manager.sh" "$DATA_DIR/usr/share/proxyrelay/component_manager.sh"
chmod 755 "$DATA_DIR/usr/share/proxyrelay/component_manager.sh"

# 4. 拷贝 LuCI 界面与服务菜单文件
cp "$SCRIPT_DIR/files/usr/share/rpcd/acl.d/luci-app-proxyrelay.json" "$DATA_DIR/usr/share/rpcd/acl.d/luci-app-proxyrelay.json"
chmod 644 "$DATA_DIR/usr/share/rpcd/acl.d/luci-app-proxyrelay.json"

cp "$SCRIPT_DIR/files/usr/lib/lua/luci/controller/proxyrelay.lua" "$DATA_DIR/usr/lib/lua/luci/controller/proxyrelay.lua"
chmod 644 "$DATA_DIR/usr/lib/lua/luci/controller/proxyrelay.lua"

cp "$SCRIPT_DIR/files/usr/lib/lua/luci/model/cbi/proxyrelay.lua" "$DATA_DIR/usr/lib/lua/luci/model/cbi/proxyrelay.lua"
chmod 644 "$DATA_DIR/usr/lib/lua/luci/model/cbi/proxyrelay.lua"

# 5. 拷贝 Web 前端静态页面
cp "$SCRIPT_DIR/ui/index.html" "$DATA_DIR/usr/share/proxyrelay/ui/index.html"
chmod 644 "$DATA_DIR/usr/share/proxyrelay/ui/index.html"

INSTALLED_SIZE=$(du -ks "$DATA_DIR" | cut -f1)

# ==========================================================
# 准备 Maintainer Scripts
# ==========================================================
cat > "$TMP_DIR/post-install" << 'EOF'
#!/bin/sh
/etc/init.d/proxyrelay enable
/etc/init.d/proxyrelay restart
/etc/init.d/rpcd reload 2>/dev/null || true
echo "[ProxyRelay] Installed successfully! WebUI: http://<router-ip>:8080"
exit 0
EOF
chmod 755 "$TMP_DIR/post-install"

cat > "$TMP_DIR/pre-deinstall" << 'EOF'
#!/bin/sh
/etc/init.d/proxyrelay stop 2>/dev/null || true
/etc/init.d/proxyrelay disable 2>/dev/null || true
exit 0
EOF
chmod 755 "$TMP_DIR/pre-deinstall"

# ==========================================================
# 打包 1: OPKG 格式 (.ipk) -> 适用于 OpenWrt 21/22/23
# ==========================================================
cat > "$CONTROL_DIR/control" << EOF
Package: $PKG_NAME
Version: ${PKG_VERSION}-${PKG_RELEASE}
Section: net
Architecture: $PKG_ARCH
Maintainer: ProxyRelay Team
Installed-Size: $INSTALLED_SIZE
Description: ProxyRelay - Secondary Proxy Relay with Web UI and LuCI integration.
EOF

cat > "$CONTROL_DIR/conffiles" << 'EOF'
/etc/config/proxyrelay
EOF

cp "$TMP_DIR/post-install" "$CONTROL_DIR/postinst"
cp "$TMP_DIR/pre-deinstall" "$CONTROL_DIR/prerm"

(cd "$DATA_DIR" && tar -czf "$IPK_BUILD/data.tar.gz" --owner=0 --group=0 .)
(cd "$CONTROL_DIR" && tar -czf "$IPK_BUILD/control.tar.gz" --owner=0 --group=0 .)
echo "2.0" > "$IPK_BUILD/debian-binary"
(cd "$IPK_BUILD" && tar -czf "$SCRIPT_DIR/$IPK_FILE" debian-binary control.tar.gz data.tar.gz)

# ==========================================================
# 打包 2: APK 格式 (.apk) -> 适用于 OpenWrt 24/25 原生 apk-tools
# ==========================================================
APK_TOOL="$SCRIPT_DIR/tools/apk-tools/src/apk"
if [ -f "$APK_TOOL" ]; then
    echo "Creating APK v3 using native apk-tools mkpkg..."
    LD_LIBRARY_PATH="$SCRIPT_DIR/tools/apk-tools/src" "$APK_TOOL" mkpkg \
        --info "name:$PKG_NAME" \
        --info "version:${PKG_VERSION}-r${PKG_RELEASE}" \
        --info "arch:$PKG_ARCH" \
        --info "description:ProxyRelay - High performance secondary proxy relay with LuCI integration" \
        --info "license:MIT" \
        --info "url:https://github.com/git-howard/ProxyRelay" \
        --info "maintainer:ProxyRelay Team" \
        --script "post-install:$TMP_DIR/post-install" \
        --script "pre-deinstall:$TMP_DIR/pre-deinstall" \
        --files "$DATA_DIR" \
        --output "$SCRIPT_DIR/$APK_FILE"
else
    echo "Warning: Native apk tool not found at $APK_TOOL, creating stream fallback..."
    APK_BUILD="$TMP_DIR/apk"
    mkdir -p "$APK_BUILD"
    cat > "$APK_BUILD/.PKGINFO" << EOF
pkgname = $PKG_NAME
pkgver = ${PKG_VERSION}-r${PKG_RELEASE}
pkgdesc = ProxyRelay - High performance secondary proxy relay with LuCI integration
url = https://github.com/git-howard/ProxyRelay
builddate = $(date +%s)
packager = ProxyRelay Team
size = $((INSTALLED_SIZE * 1024))
arch = $PKG_ARCH
license = MIT
EOF
    (cd "$APK_BUILD" && tar -czf "$TMP_DIR/apk_control.tar.gz" --owner=0 --group=0 .PKGINFO)
    (cd "$DATA_DIR" && tar -czf "$TMP_DIR/apk_data.tar.gz" --owner=0 --group=0 .)
    cat "$TMP_DIR/apk_control.tar.gz" "$TMP_DIR/apk_data.tar.gz" > "$SCRIPT_DIR/$APK_FILE"
fi

# ==========================================================
# 打包 3: 通用一键安装脚本 install.sh
# ==========================================================
cat > "$SCRIPT_DIR/install.sh" << 'EOF'
#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================================="
echo "  Installing ProxyRelay for OpenWrt"
echo "=========================================================="

if command -v apk >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/proxyrelay-1.0.0-r1.x86_64.apk" ]; then
    echo "[Installer] Installing via apk..."
    apk add --allow-untrusted "$SCRIPT_DIR/proxyrelay-1.0.0-r1.x86_64.apk"
elif command -v opkg >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/proxyrelay_1.0.0-1_x86_64.ipk" ]; then
    echo "[Installer] Installing via opkg..."
    opkg install --force-reinstall "$SCRIPT_DIR/proxyrelay_1.0.0-1_x86_64.ipk"
else
    echo "[Installer] Installing direct file copy fallback..."
    mkdir -p /usr/bin /etc/init.d /etc/config /usr/share/proxyrelay/ui
    mkdir -p /usr/share/rpcd/acl.d
    mkdir -p /usr/lib/lua/luci/controller /usr/lib/lua/luci/model/cbi
    cp -f "$SCRIPT_DIR/build/proxyrelay" /usr/bin/proxyrelay
    chmod 755 /usr/bin/proxyrelay
    cp -f "$SCRIPT_DIR/files/etc/init.d/proxyrelay" /etc/init.d/proxyrelay
    chmod 755 /etc/init.d/proxyrelay
    [ -f /etc/config/proxyrelay ] || cp "$SCRIPT_DIR/files/etc/config/proxyrelay" /etc/config/proxyrelay
    cp -f "$SCRIPT_DIR/files/usr/share/proxyrelay/firewall.include" /usr/share/proxyrelay/firewall.include
    chmod 755 /usr/share/proxyrelay/firewall.include
    cp -f "$SCRIPT_DIR/files/usr/share/proxyrelay/component_manager.sh" /usr/share/proxyrelay/component_manager.sh
    chmod 755 /usr/share/proxyrelay/component_manager.sh
    cp -f "$SCRIPT_DIR/files/usr/share/rpcd/acl.d/luci-app-proxyrelay.json" /usr/share/rpcd/acl.d/luci-app-proxyrelay.json
    cp -f "$SCRIPT_DIR/files/usr/lib/lua/luci/controller/proxyrelay.lua" /usr/lib/lua/luci/controller/proxyrelay.lua
    cp -f "$SCRIPT_DIR/files/usr/lib/lua/luci/model/cbi/proxyrelay.lua" /usr/lib/lua/luci/model/cbi/proxyrelay.lua
    cp -f "$SCRIPT_DIR/ui/index.html" /usr/share/proxyrelay/ui/index.html
    /etc/init.d/proxyrelay enable
    /etc/init.d/proxyrelay restart
    /etc/init.d/rpcd reload 2>/dev/null || true
fi

echo "=========================================================="
echo "  ProxyRelay installation complete!"
echo "  WebUI Dashboard: http://$(uci -q get network.lan.ipaddr || echo '192.168.1.1'):$(uci -q get proxyrelay.global.web_port || echo '8080')"
echo "=========================================================="
EOF
chmod 755 "$SCRIPT_DIR/install.sh"

echo "=========================================================="
echo "  Artifacts ready:"
echo "  [OpenWrt 21-23 opkg]: $SCRIPT_DIR/$IPK_FILE"
echo "  [OpenWrt 24-25 apk] : $SCRIPT_DIR/$APK_FILE"
echo "  [Universal Installer]: $SCRIPT_DIR/install.sh"
echo "=========================================================="
ls -lh "$SCRIPT_DIR/$IPK_FILE" "$SCRIPT_DIR/$APK_FILE" "$SCRIPT_DIR/install.sh"
