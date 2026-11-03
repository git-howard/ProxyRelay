# ProxyRelay (二级代理中继与透明网关系统)

ProxyRelay 是一款高性能、模块化的二级代理中继与透明网关系统。支持多入站监听（HTTP / SOCKS5 / TPROXY / REDIRECT）、分流规则引擎、流量配额限制、用户/设备级访问审计以及现代化暗黑 SPA 控制台。

本项目包含两大独立平台工程：
- **[`/win`](./win)**: Windows 平台完整实现（现代化 WebView2 桌面界面、Windows 系统服务、Schannel TLS、Mihomo & Xray 内核集成）
- **[`/openwrt`](./openwrt)**: OpenWrt / Linux 软路由移植版（纯原生 C++17 POSIX、Linux TPROXY 透明代理、OpenSSL、REST API 服务器、ipk / apk 打包）

---

## 目录结构

```text
ProxyRelay/
├── win/                         # Windows 平台完整工程与发行文件
│   ├── CMakeLists.txt           # Windows MSVC CMake 构建脚本
│   ├── build.bat                # Windows 一键编译脚本
│   ├── src/                     # Windows C++ 源码实现 (WebView2, SChannel, Win32)
│   ├── include/                 # Windows C++ 头文件
│   ├── resources/               # 应用程序图标与版本资源 (app.rc, app.manifest)
│   ├── scripts/                 # 构建脚本 (版本时间戳自动化生成)
│   ├── libs/                    # 依赖库 (sqlite3, json.hpp, WebView2 SDK)
│   ├── ui/                      # 现代化 Web 控制台前端 (暗黑风格 SPA)
│   ├── WinDivert/               # WinDivert 驱动与动态库
│   ├── WinDivert.dll            # WinDivert 64 位运行库
│   ├── WinDivert64.sys          # WinDivert 驱动文件
│   ├── wintun.dll               # Wintun 虚拟网卡驱动
│   ├── xray.exe                 # 内置 Xray 核心
│   ├── mihomo-windows-amd64.exe # 内置 Mihomo (Clash Meta) 核心
│   ├── geoip.dat / geosite.dat  # 路由规则数据库
│   └── ProxyRelay.exe           # 编译生成的可执行文件
│
├── openwrt/                     # OpenWrt 软路由移植版完整工程
│   ├── CMakeLists.txt           # Linux / OpenWrt 跨平台 CMake 工程
│   ├── Makefile                 # OpenWrt SDK Package 打包规则
│   ├── build.sh                 # Linux / WSL 本地一键编译脚本
│   ├── package_all.sh           # OpenWrt 全版本 (ipk & apk) 自动化打包脚本
│   ├── install.sh               # 路由器一键通用安装脚本
│   ├── src/                     # Linux 原生 C++ 源码 (POSIX Socket, TProxy, OpenSSL)
│   ├── include/                 # Linux 头文件
│   ├── libs/                    # 独立自包含库 (sqlite3, json.hpp)
│   ├── ui/                      # 嵌入式 Web 控制台 (REST API 驱动)
│   ├── files/                   # 系统配置文件
│   │   ├── etc/config/proxyrelay           # UCI 配置文件
│   │   ├── etc/init.d/proxyrelay           # procd 守护服务脚本
│   │   └── usr/share/proxyrelay/firewall.include # nftables/iptables 防火墙透明代理规则
│   ├── proxyrelay_1.0.0-1_x86_64.ipk       # OpenWrt 21~23 (opkg) 预编译包
│   └── proxyrelay-1.0.0-r1.x86_64.apk      # OpenWrt 24~25+ (apk) 预编译包
│
├── ProxyRelay_使用帮助.md        # 系统使用与配置详细手册
├── LICENSE                      # 开源许可协议 (MIT)
└── README.md                    # 项目总览说明文档
```

---

## 快速上手与编译

### 1. Windows 版本 (`/win`)

#### 构建运行环境：
- Windows 10 / 11 / Server 2016+
- Visual Studio 2019 / 2022 / 2026 (MSVC C++17)
- CMake 3.15+

#### 一键编译：
打开终端进入 `win` 目录执行：
```bat
cd win
build.bat
```
编译成功后将在 `win/` 目录下生成 `ProxyRelay.exe`。

#### 运行与功能：
- **桌面模式**：直接双击运行 `ProxyRelay.exe`，启动现代化暗黑 SPA 控制台，托盘后台运行。
- **服务模式**：支持安装为 Windows 系统服务，无人值守自启动。

---

### 2. OpenWrt 软路由版本 (`/openwrt`)

#### 构建运行环境：
- Linux x86_64 / WSL2 (Ubuntu 20.04+)
- gcc / g++ 9+ (支持 C++17)
- OpenSSL 1.1 或 3.0+ (含静态库)

#### 本地一键编译：
```bash
cd openwrt
./build.sh
```
生成自包含静态链接二进制产物：`openwrt/build/proxyrelay`。

#### 打包与路由器安装：
```bash
cd openwrt
./package_all.sh
```
生成适用于 OpenWrt 21~23 的 `.ipk` 包与 OpenWrt 24~25 的 `.apk` 包。

#### 部署至路由器：
- **OpenWrt 24+ (apk)**：
  ```bash
  apk add --allow-untrusted /tmp/proxyrelay-1.0.0-r1.x86_64.apk
  ```
- **OpenWrt 21~23 (opkg)**：
  ```bash
  opkg install /tmp/proxyrelay_1.0.0-1_x86_64.ipk
  ```
- 访问 Web 控制台：`http://<路由器IP>:8080`

---

## 核心特性对比

| 功能特性 | Windows 版 (`/win`) | OpenWrt 软路由版 (`/openwrt`) |
| :--- | :--- | :--- |
| **界面交互** | 现代化 WebView2 桌面窗口 + 系统托盘 | 嵌入式 REST API + 浏览器暗黑 WebUI |
| **入站协议** | HTTP / HTTPS (Schannel) / SOCKS5 | HTTP / HTTPS (OpenSSL) / SOCKS5 |
| **网关代理** | 驱动级 TUN / WinDivert / 局部重定向 | Linux 内核原生 TPROXY (nftables / iptables) |
| **透明代理** | 支持客户端直连代理端口 | 局域网全设备无感透明分流（免客户端配置） |
| **服务守护** | Windows SCM Service / 桌面自启动 | Linux procd 进程看门狗守护 |
| **底层依赖** | Win32 API, GDI+, WebView2 Loader | 纯 POSIX Sockets, Linux Epoll, OpenSSL |
| **外部内核** | 集成 Windows 版 Mihomo & Xray | 支持直接连接软路由内运行的各类核心 |

---

## 许可协议
本项目采用 [MIT 许可证](LICENSE)。
