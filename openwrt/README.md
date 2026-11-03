# ProxyRelay for OpenWrt (软路由/硬路由透明代理网关与二级中继)

ProxyRelay 的 OpenWrt 专用移植版本，全面剥离 Windows 桌面依赖（Win32 GUI / WebView2 / SChannel），采用纯原生 **C++17 + POSIX Sockets + OpenSSL + Linux TPROXY (透明代理) + 嵌入式 Web API 服务器** 重构。

---

## 一、 核心特性

1. **Linux 原生透明代理网关 (TPROXY & REDIRECT)**：
   - 自动接管局域网所有客户端发出的 TCP 与 UDP（含 DNS、QUIC）流量。
   - 保留客户端真实源 IP，支持按设备 IP / 网段无感绑定用户身份与日/月流量配额。
   - 兼容 OpenWrt 22.03+ 的 `fw4 (nftables)` 与经典版 `fw3 (iptables)`。
2. **多协议二级中继与智能分流**：
   - 支持上游 HTTP、SOCKS5、Xray、Clash 节点以及 DIRECT 直连与 REJECT 拦截。
   - 支持多级优先级排序与故障顺序回退（Fallback）。
   - 规则引擎支持域名通配符、正则、CIDR IP 网段及大陆 IP 白名单。
3. **内置现代化 Web 控制台 (复用原版暗黑 SPA 前端)**：
   - 内置轻量高效的 HTTP REST API 服务器，免去安装额外外部 Web 服务。
   - 局域网内任意浏览器输入 `http://<路由器IP>:8080` 即可直接操控，提供实时吞吐波形图、实时连接监控与一键断开、审计日志过滤。
4. **轻量与低资源开销**：
   - 静态编译并精简产物体积仅约 2.8MB，RAM 内存占用低至 15MB 左右，极度适配路由器有限资源。
   - 原生集成 OpenWrt `procd` 守护进程与 `uci` 配置体系。

---

## 二、 目录结构

```
openwrt/
├── CMakeLists.txt              # Linux / OpenWrt 跨平台 CMake 构建工程
├── Makefile                    # OpenWrt SDK Package 打包 Makefile (可直接放入 feeds)
├── build.sh                    # Linux / WSL 本地一键构建脚本
├── include/                    # C++ 头文件
│   ├── Common.h                # POSIX 网络与套接字抽象
│   ├── Database.h              # SQLite3 数据存储 (与原版完全兼容)
│   ├── UserManager.h           # 用户鉴权、IP 绑定与配额控制
│   ├── Rules.h                 # 分流规则引擎
│   ├── TrafficMonitor.h        # 实时速率与历史流量监控
│   ├── ConnectionLogger.h      # 访问审计日志
│   ├── RealtimeConnectionManager.h # 活跃连接管理与强行切断
│   ├── OpenSSLSession.h        # OpenSSL TLS 证书与加密通信
│   ├── ProxyServer.h           # HTTP / SOCKS5 代理及上游中继
│   ├── TProxyServer.h          # TPROXY / REDIRECT 透明代理入站监听
│   └── WebServer.h             # 嵌入式 WebUI 静态文件与 REST API 服务器
├── src/                        # C++ 源码实现
├── files/                      # OpenWrt 系统文件覆盖
│   ├── etc/config/proxyrelay   # UCI 配置文件模板
│   ├── etc/init.d/proxyrelay   # procd 服务守护启停脚本
│   └── usr/share/proxyrelay/firewall.include # nftables / iptables 防火墙重定向脚本
└── ui/                         # 现代化 Web 控制台 (已升级为 REST API 驱动)
    └── index.html
```

---

## 三、 快速编译指南

### 1. 本地 WSL2 / Linux 直接编译
```bash
cd openwrt
./build.sh
```
编译产物位于 `openwrt/build/proxyrelay`。

### 2. 使用 OpenWrt SDK 打包为 `.ipk` 安装包
1. 将 `openwrt/` 目录软链接或复制到 OpenWrt SDK 的 `package/proxyrelay`：
   ```bash
   cp -r openwrt/ /path/to/openwrt-sdk/package/proxyrelay
   ```
2. 在 SDK 根目录下执行：
   ```bash
   make package/proxyrelay/compile V=s
   ```
3. 在 `bin/packages/<架构>/base/` 下即可获得 `proxyrelay_1.0.0-1_<架构>.ipk`。

---

## 四、 路由器部署与安装 (支持 OpenWrt 21 ~ 25+)

### 1. OpenWrt 24.10 / 25.x (官方原生采用 `apk` 包管理器)
在 OpenWrt 24 及更新版本上，包管理器已切换为 `apk-tools`：
```bash
# 上传至软路由
scp proxyrelay-1.0.0-r1.x86_64.apk root@192.168.1.1:/tmp/

# 安装
apk add --allow-untrusted /tmp/proxyrelay-1.0.0-r1.x86_64.apk
```

### 2. OpenWrt 21 / 22 / 23 (采用传统 `opkg` 包管理器)
```bash
# 上传至软路由
scp proxyrelay_1.0.0-1_x86_64.ipk root@192.168.1.1:/tmp/

# 安装
opkg update
opkg install /tmp/proxyrelay_1.0.0-1_x86_64.ipk
```

### 3. 通用自适应一键安装 (任意版本自动识别)
```bash
# 解压或拷贝 openwrt 目录后直接执行
sh install.sh
```

---

## 五、 OpenWrt 24/25 fw4 防火墙联动与自愈机制

在 OpenWrt 24/25 中，系统已彻底废弃 `fw3 (iptables)`，全量采用 `fw4 (nftables)`（本程序同时兼容两者）。
ProxyRelay 在安装时会在 `/etc/config/firewall` 注册 `config include`：
```uci
config include 'proxyrelay'
	option type 'script'
	option path '/usr/share/proxyrelay/firewall.include'
	option reload '1'
```
- **默认不开启**：为确保路由器安装与启动初期网络稳定，透明代理功能**默认保持关闭状态**。管理员可在 Web 控制台【偏好设置】→【软路由透明代理网关】中一键勾选启用，或通过 UCI 执行 `uci set proxyrelay.global.tproxy_enabled=1 && uci commit proxyrelay`。
- **自动自愈**：启用透明代理后，无论接口重连、WAN 口重新获取 IP、还是在 LuCI 中修改了防火墙设置，`fw4 / fw3` 在重载时均会自动重新应用 ProxyRelay 的透明拦截规则，关闭时自动清理，永不断流。
- **免密配额**：局域网客户端发出的流量通过透明代理拦截后，自动按源 IP 匹配用户限额与分流规则。
- **WebUI 访问**：在内网浏览器输入 `http://<路由器IP>:8080` 即可随时管理节点、切换透明代理开关、监控实时吞吐与切断异常连接。
