#!/bin/sh
# ProxyRelay Linux/OpenWrt 组件管理器
# 支持组件：xray, mihomo, geoip, geosite
# 支持下载源：official (GitHub), ghfast (国内高速镜像)

CMD="${1:-status}"
NAME="${2}"
MIRROR="${3:-ghfast}"

LOG_FILE="/var/log/proxyrelay/component_install.log"
LOCK_FILE="/var/run/proxyrelay_comp.lock"
TMP_DIR="/tmp/proxyrelay_download"

mkdir -p /var/log/proxyrelay /etc/proxyrelay /usr/share/proxyrelay/bin /usr/bin

# 获取系统架构与映射 URL
get_arch() {
    local raw_arch=$(uname -m 2>/dev/null || echo "x86_64")
    case "$raw_arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7*|armv8l|armhf)
            echo "armv7"
            ;;
        mips)
            echo "mips"
            ;;
        mips64)
            echo "mips64"
            ;;
        mipsel|mipsle)
            echo "mipsle"
            ;;
        *)
            echo "amd64"
            ;;
    esac
}

get_url() {
    local comp="$1"
    local mir="$2"
    local raw_url=""
    local arch=$(get_arch)

    case "$comp" in
        xray)
            local xray_pkg="Xray-linux-64.zip"
            if [ "$arch" = "arm64" ]; then
                xray_pkg="Xray-linux-arm64-v8a.zip"
            elif [ "$arch" = "armv7" ]; then
                xray_pkg="Xray-linux-arm32-v7a.zip"
            elif [ "$arch" = "mips" ]; then
                xray_pkg="Xray-linux-mips32.zip"
            elif [ "$arch" = "mipsle" ]; then
                xray_pkg="Xray-linux-mips32le.zip"
            fi
            raw_url="https://github.com/XTLS/Xray-core/releases/download/v25.1.30/${xray_pkg}"
            ;;
        mihomo)
            local mihomo_pkg="mihomo-linux-amd64-v1.19.2.gz"
            if [ "$arch" = "amd64" ]; then
                # 若 CPU 不支持 AVX2 (x86-64-v3 微架构，如部分 Celeron/Atom/老旧机器)，自动选用 compatible 兼容构建
                if ! grep -q "avx2" /proc/cpuinfo 2>/dev/null; then
                    mihomo_pkg="mihomo-linux-amd64-compatible-v1.19.2.gz"
                fi
            elif [ "$arch" = "arm64" ]; then
                mihomo_pkg="mihomo-linux-arm64-v1.19.2.gz"
            elif [ "$arch" = "armv7" ]; then
                mihomo_pkg="mihomo-linux-armv7-v1.19.2.gz"
            elif [ "$arch" = "mips" ]; then
                mihomo_pkg="mihomo-linux-mips-softfloat-v1.19.2.gz"
            elif [ "$arch" = "mipsle" ]; then
                mihomo_pkg="mihomo-linux-mipsle-softfloat-v1.19.2.gz"
            fi
            raw_url="https://github.com/MetaCubeX/mihomo/releases/download/v1.19.2/${mihomo_pkg}"
            ;;
        geoip)
            raw_url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
            ;;
        geosite)
            raw_url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
            ;;
        *)
            echo ""
            return 1
            ;;
    esac

    if [ "$mir" = "official" ]; then
        echo "$raw_url"
    else
        # 默认使用 ghfast.top 加速镜像
        echo "https://ghfast.top/$raw_url"
    fi
}

check_status() {
    local xray_inst=false
    local xray_ver="未安装"
    if [ -x /usr/bin/xray ]; then
        xray_inst=true
        xray_ver=$(/usr/bin/xray version 2>/dev/null | head -n 1 | awk '{print $1" "$2}')
        [ -n "$xray_ver" ] || xray_ver="已就绪"
    fi

    local mihomo_inst=false
    local mihomo_ver="未安装"
    if [ -x /usr/bin/mihomo ]; then
        mihomo_inst=true
        mihomo_ver=$(/usr/bin/mihomo -v 2>/dev/null | head -n 1 | awk '{print $1" "$2}')
        [ -n "$mihomo_ver" ] || mihomo_ver="已就绪"
    fi

    local geoip_inst=false
    local geoip_size="未安装"
    if [ -f /etc/proxyrelay/geoip.dat ]; then
        geoip_inst=true
        local sz=$(ls -lh /etc/proxyrelay/geoip.dat 2>/dev/null | awk '{print $5}')
        geoip_size="已安装 (${sz})"
    fi

    local geosite_inst=false
    local geosite_size="未安装"
    if [ -f /etc/proxyrelay/geosite.dat ]; then
        geosite_inst=true
        local sz=$(ls -lh /etc/proxyrelay/geosite.dat 2>/dev/null | awk '{print $5}')
        geosite_size="已安装 (${sz})"
    fi

    local is_busy=false
    if [ -f "$LOCK_FILE" ]; then
        is_busy=true
    fi

    cat << EOF
{
  "busy": $is_busy,
  "components": [
    {
      "name": "xray",
      "displayName": "Xray 协议内核 (VLESS/VMess/Trojan/SS)",
      "installed": $xray_inst,
      "version": "$xray_ver",
      "path": "/usr/bin/xray",
      "desc": "支持新一代轻量高速出站代理协议"
    },
    {
      "name": "mihomo",
      "displayName": "Mihomo (Clash Meta) 代理核心",
      "installed": $mihomo_inst,
      "version": "$mihomo_ver",
      "path": "/usr/bin/mihomo",
      "desc": "支持 Clash 订阅与各种加密隧道协议"
    },
    {
      "name": "geoip",
      "displayName": "GeoIP 大陆与全球 IP 规则库",
      "installed": $geoip_inst,
      "version": "$geoip_size",
      "path": "/etc/proxyrelay/geoip.dat",
      "desc": "用于软路由透明代理自动绕过国内大陆 IP"
    },
    {
      "name": "geosite",
      "displayName": "GeoSite 域名分流规则库",
      "installed": $geosite_inst,
      "version": "$geosite_size",
      "path": "/etc/proxyrelay/geosite.dat",
      "desc": "用于智能识别国内外顶级域名并定向路由"
    }
  ]
}
EOF
}

download_file() {
    local url="$1"
    local dest="$2"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始下载: $url" >> "$LOG_FILE"
    if command -v curl >/dev/null 2>&1; then
        curl -f -L --connect-timeout 15 -m 600 -k -o "$dest" "$url" >> "$LOG_FILE" 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget --no-check-certificate -T 15 -t 3 -O "$dest" "$url" >> "$LOG_FILE" 2>&1
    elif command -v uclient-fetch >/dev/null 2>&1; then
        uclient-fetch --no-check-certificate -O "$dest" "$url" >> "$LOG_FILE" 2>&1
    else
        echo "错误: 未找到可用的下载工具 (curl/wget/uclient-fetch)" >> "$LOG_FILE"
        return 1
    fi
}

install_comp() {
    local comp="$1"
    local mir="${2:-ghfast}"

    echo "$comp" > "$LOCK_FILE"
    echo "==========================================================" > "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始安装组件: $comp (下载源: $mir)" >> "$LOG_FILE"
    echo "==========================================================" >> "$LOG_FILE"

    local url=$(get_url "$comp" "$mir")
    if [ -z "$url" ]; then
        echo "错误: 不支持的组件名称 $comp" >> "$LOG_FILE"
        rm -f "$LOCK_FILE"
        return 1
    fi

    rm -rf "$TMP_DIR"
    mkdir -p "$TMP_DIR"

    case "$comp" in
        xray)
            local zip_file="$TMP_DIR/xray.zip"
            if download_file "$url" "$zip_file"; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] 下载完成，正在解压..." >> "$LOG_FILE"
                unzip -o "$zip_file" -d "$TMP_DIR" >> "$LOG_FILE" 2>&1
                if [ -f "$TMP_DIR/xray" ]; then
                    cp -f "$TMP_DIR/xray" /usr/bin/xray
                    chmod 755 /usr/bin/xray
                    [ -f "$TMP_DIR/geoip.dat" ] && cp -f "$TMP_DIR/geoip.dat" /etc/proxyrelay/geoip.dat
                    [ -f "$TMP_DIR/geosite.dat" ] && cp -f "$TMP_DIR/geosite.dat" /etc/proxyrelay/geosite.dat
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Xray 内核安装成功: $(/usr/bin/xray version 2>/dev/null | head -n 1)" >> "$LOG_FILE"
                else
                    echo "错误: 解压包中未找到 xray 二进制" >> "$LOG_FILE"
                fi
            else
                echo "错误: 下载 Xray 失败，请切换下载源重试" >> "$LOG_FILE"
            fi
            ;;
        mihomo)
            local gz_file="$TMP_DIR/mihomo.gz"
            if download_file "$url" "$gz_file"; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] 下载完成，正在解包..." >> "$LOG_FILE"
                gunzip -c "$gz_file" > /usr/bin/mihomo 2>> "$LOG_FILE"
                chmod 755 /usr/bin/mihomo
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] Mihomo 内核安装成功: $(/usr/bin/mihomo -v 2>/dev/null | head -n 1)" >> "$LOG_FILE"
            else
                echo "错误: 下载 Mihomo 失败，请检查网络或切换源" >> "$LOG_FILE"
            fi
            ;;
        geoip)
            local dat_file="/etc/proxyrelay/geoip.dat"
            if download_file "$url" "$TMP_DIR/geoip.dat"; then
                cp -f "$TMP_DIR/geoip.dat" "$dat_file"
                chmod 644 "$dat_file"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] GeoIP 数据库安装成功 ($(ls -lh $dat_file | awk '{print $5}'))" >> "$LOG_FILE"
            else
                echo "错误: 下载 GeoIP 失败" >> "$LOG_FILE"
            fi
            ;;
        geosite)
            local dat_file="/etc/proxyrelay/geosite.dat"
            if download_file "$url" "$TMP_DIR/geosite.dat"; then
                cp -f "$TMP_DIR/geosite.dat" "$dat_file"
                chmod 644 "$dat_file"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] GeoSite 规则库安装成功 ($(ls -lh $dat_file | awk '{print $5}'))" >> "$LOG_FILE"
            else
                echo "错误: 下载 GeoSite 失败" >> "$LOG_FILE"
            fi
            ;;
    esac

    rm -rf "$TMP_DIR"
    rm -f "$LOCK_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 任务结束" >> "$LOG_FILE"
}

get_log() {
    local running=false
    if [ -f "$LOCK_FILE" ]; then
        running=true
    fi
    local current_comp=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    local logs=""
    if [ -f "$LOG_FILE" ]; then
        logs=$(tail -n 30 "$LOG_FILE")
    fi

    # 转义为 JSON 字符串输出
    cat << EOF
{
  "running": $running,
  "component": "$current_comp",
  "log": $(echo "$logs" | jq -Rs . 2>/dev/null || echo "\"$logs\"")
}
EOF
}

case "$CMD" in
    status)
        check_status
        ;;
    install)
        install_comp "$NAME" "$MIRROR"
        ;;
    log)
        get_log
        ;;
    *)
        echo "Usage: $0 {status|install <name> [mirror]|log}"
        exit 1
        ;;
esac
