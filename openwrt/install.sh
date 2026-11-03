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
