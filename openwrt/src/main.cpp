#include "Common.h"
#include "Database.h"
#include "TrafficMonitor.h"
#include "OpenSSLSession.h"
#include "Rules.h"
#include "ProxyServer.h"
#include "TProxyServer.h"
#include "UdpRelayManager.h"
#include "WebServer.h"
#include "Utils.h"
#include <iostream>
#include <csignal>
#include <getopt.h>
#include <cstring>

static std::atomic<bool> g_running{true};

static void SignalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cout << "\n[ProxyRelay] Received termination signal " << signum << ", shutting down..." << std::endl;
        g_running.store(false);
    } else if (signum == SIGHUP) {
        std::cout << "[ProxyRelay] Received SIGHUP, reloading rules and port listeners..." << std::endl;
        RuleManager::Instance().ReloadRoutingRules();
        ProxyServer::Instance().ReloadPorts();
    }
}

static void PrintUsage(const char* prog) {
    std::cout << "ProxyRelay for OpenWrt (Secondary Proxy Relay & Multi-Protocol Gateway)\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -d, --db <path>       SQLite database path (default: /etc/proxyrelay/proxy.db or ./proxy.db)\n"
              << "  -w, --web-port <port> Web management UI port (default: 8080)\n"
              << "  -p, --password <pwd>  Web management UI access password\n"
              << "  -u, --ui-dir <path>   WebUI folder path (default: /usr/share/proxyrelay/ui or ./ui)\n"
              << "  -b, --background      Run in background as daemon\n"
              << "  -h, --help            Show this help message\n"
              << "  -v, --version         Show version information\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    // 初始化系统时区，确保日志和封禁时间与本地一致
    Utils::InitTimezone();

    // 忽略 SIGPIPE，防止套接字意外对端断开退出程序；忽略 SIGCHLD 防止子进程成为僵尸进程
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    signal(SIGHUP, SignalHandler);

    std::string dbPath = "proxy.db";
    std::string uiDir = "ui";
    std::string adminPassword = "";
    int webPort = 8080;
    bool runDaemon = false;

    static struct option long_options[] = {
        {"db",         required_argument, 0, 'd'},
        {"web-port",   required_argument, 0, 'w'},
        {"password",   required_argument, 0, 'p'},
        {"ui-dir",     required_argument, 0, 'u'},
        {"background", no_argument,       0, 'b'},
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt = 0;
    while ((opt = getopt_long(argc, argv, "d:w:p:u:bhv", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'd': dbPath = optarg; break;
            case 'w': webPort = std::atoi(optarg); break;
            case 'p': adminPassword = optarg; break;
            case 'u': uiDir = optarg; break;
            case 'b': runDaemon = true; break;
            case 'v':
                std::cout << "ProxyRelay-OpenWrt v1.0.0 (Linux/POSIX/OpenSSL Relay)" << std::endl;
                return 0;
            case 'h':
            default:
                PrintUsage(argv[0]);
                return 0;
        }
    }

    if (runDaemon) {
        if (daemon(1, 0) < 0) {
            std::cerr << "Failed to daemonize process: " << strerror(errno) << std::endl;
            return 1;
        }
    }

    std::cout << "========================================================\n"
              << "  ProxyRelay for OpenWrt Gateway Starting Up\n"
              << "========================================================" << std::endl;

    // 1. 初始化数据库
    if (!Database::Instance().Initialize(dbPath)) {
        // 回退尝试 /tmp 或本地路径
        if (!Database::Instance().Initialize("/tmp/proxy.db")) {
            std::cerr << "Fatal: Failed to initialize SQLite database at " << dbPath << std::endl;
            return 1;
        }
    }
    std::cout << "[Database] SQLite initialized at: " << dbPath << std::endl;

    // 若命令行未指定 -p 管理密码，回退从数据库或 OpenWrt UCI 配置中读取
    if (adminPassword.empty()) {
        std::string dbPwd = Database::Instance().GetConfig("admin_password", "");
        if (!dbPwd.empty()) {
            adminPassword = dbPwd;
        } else {
            std::string uciPwd = Utils::Trim(Utils::ExecCmd("uci -q get proxyrelay.global.password 2>/dev/null"));
            if (!uciPwd.empty()) {
                adminPassword = uciPwd;
            }
        }
    } else {
        Database::Instance().SetConfig("admin_password", adminPassword);
    }
    if (!adminPassword.empty()) {
        std::cout << "[WebServer] Management console password protection is ENABLED." << std::endl;
    } else {
        std::cout << "[WebServer] Management console password protection is DISABLED (Open Access)." << std::endl;
    }

    // 2. 初始化 OpenSSL
    OpenSSLSession::InitializeSSL();

    // 3. 启动流量监控
    TrafficMonitor::Instance().Start();

    // 4. 初始化规则引擎
    RuleManager::Instance().Initialize();

    // 5. 启动二级代理中继服务
    ProxyServer::Instance().Start();

    // 6. 透明代理网关初始化 (根据数据库与 UCI 配置，默认为 0 不开启，需在设置菜单手动开启)
    std::string tproxyEnabledStr = Database::Instance().GetConfig("tproxy_enabled", "0");
    if (tproxyEnabledStr != "1") {
        std::string uciTproxy = Utils::Trim(Utils::ExecCmd("uci -q get proxyrelay.global.tproxy_enabled 2>/dev/null"));
        if (uciTproxy == "1") {
            tproxyEnabledStr = "1";
            Database::Instance().SetConfig("tproxy_enabled", "1");
        }
    }
    int tproxyPort = 12345;
    std::string tproxyPortStr = Database::Instance().GetConfig("tproxy_port", "12345");
    if (!tproxyPortStr.empty()) {
        tproxyPort = std::atoi(tproxyPortStr.c_str());
    }

    if (tproxyEnabledStr == "1" && tproxyPort > 0) {
        TProxyServer::Instance().Start(tproxyPort);
        std::cout << "[TProxy] Transparent proxy gateway is ENABLED on port " << tproxyPort << " (TCP/UDP)" << std::endl;
    } else {
        std::cout << "[TProxy] Transparent proxy gateway is DISABLED by default (Can be enabled in Settings)." << std::endl;
    }

    // 7. 启动嵌入式 Web 管理控制台 (支持访问控制密码)
    WebServer::Instance().Start(webPort, uiDir, adminPassword);

    std::cout << "[System] All ProxyRelay subsystems started successfully." << std::endl;

    // 主线程等待运行终止信号
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "[System] Stopping all services..." << std::endl;
    WebServer::Instance().Stop();
    TProxyServer::Instance().Stop();
    UdpRelayManager::Instance().Stop();
    ProxyServer::Instance().Stop();
    TrafficMonitor::Instance().Stop();
    OpenSSLSession::CleanupSSL();
    Database::Instance().Close();

    std::cout << "[System] ProxyRelay stopped cleanly." << std::endl;
    return 0;
}
