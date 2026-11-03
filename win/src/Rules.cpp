#include "Rules.h"
#include "Database.h"
#include "Utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <thread>
#include <fstream>
#include <urlmon.h>
#include <filesystem>
#include <algorithm>
#include <wininet.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

namespace fs = std::filesystem;

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

RuleManager::RuleManager() {
    blacklistRules_ = "127.0.0.1,10.0.0.0/8,192.168.0.0/16,172.16.0.0/16";
    bypassConfig_ = {false, false, false, ""};
    chinaIpSubUrl_ = "https://fastly.jsdelivr.net/gh/mayaxcn/china-ip-list@master/chnroute.txt";
    chinaIpSubIntervalDays_ = 7;
    chinaIpLastUpdate_ = "";
    chinaIpCidrCount_ = 0;
}

RuleManager::~RuleManager() {
    StopAutoUpdate();
}

void RuleManager::Initialize() {
    // 加载配置
// 加载配置
    // blacklistRules_ = Database::Instance().GetConfig("blacklist_rules", "127.0.0.1,10.0.0.0/8,192.168.0.0/16,172.16.0.0/16");
    
    // 从数据库表加载黑名单
    auto list = Database::Instance().GetBlacklist();
    blacklistRules_ = "";
    for (const auto& item : list) {
        if (!blacklistRules_.empty()) blacklistRules_ += ",";
        blacklistRules_ += item.ip;
    }
    // 如果数据库为空，使用默认值？不用了，让用户自己配置。或者保留默认安全策略。
    // 如果是全新安装，可能需要默认值。
    if (blacklistRules_.empty()) {
       // blacklistRules_ = "127.0.0.1"; // 最小安全
    }
    
    std::string bypassCfg = Database::Instance().GetConfig("bypass_config", "0,0,0");
    std::stringstream ss(bypassCfg);
    std::string segment;
    std::vector<int> flags;
    while(std::getline(ss, segment, ',')) {
        flags.push_back(std::atoi(segment.c_str()));
    }
    if (flags.size() >= 3) {
        bypassConfig_.enableChnRoute = flags[0] != 0;
        bypassConfig_.enableChnRoute6 = flags[1] != 0;
        bypassConfig_.enableChnList = flags[2] != 0;
    }
    
    bypassConfig_.customRules = Database::Instance().GetConfig("custom_bypass_rules", "");
    
    // 解析规则
    ParseCIDRList(blacklistRules_, blacklistCIDRs_);
    
    // 如果启用了规则，加载文件（如果存在）
    if (bypassConfig_.enableChnRoute) {
        std::ifstream f("data/chnroute.txt");
        if (f.good()) {
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            ParseCIDRList(content, chnRoute_);
        }
    }
    // (TODO: chnroute6, chnlist)
    
    // 解析自定义规则
    ParseCustomRules(bypassConfig_.customRules);
    
    // 加载路由规则
    ReloadRoutingRules();

    // 加载中国国内流量直连配置
    LoadChinaDirectConfig();

    // 启动自动更新线程
    StartAutoUpdate();
}

void RuleManager::SetBlacklist(const std::string& rules) {
    std::lock_guard<std::mutex> lock(mutex_);
    blacklistRules_ = rules;
    ParseCIDRList(rules, blacklistCIDRs_);
    Database::Instance().SetConfig("blacklist_rules", rules);
}

std::string RuleManager::GetBlacklist() const {
    return blacklistRules_;
}

void RuleManager::SetBypassConfig(const BypassConfig& config) {
    Utils::Log("SetBypassConfig: chnroute=" + std::to_string(config.enableChnRoute) + 
               ", customRules=" + config.customRules);
    
    std::lock_guard<std::mutex> lock(mutex_);
    bypassConfig_ = config;
    
    std::string val = (config.enableChnRoute ? "1" : "0") + std::string(",") +
                      (config.enableChnRoute6 ? "1" : "0") + std::string(",") +
                      (config.enableChnList ? "1" : "0");
    Database::Instance().SetConfig("bypass_config", val);
    Database::Instance().SetConfig("custom_bypass_rules", config.customRules);
    
    // 刷新解析自定义规则
    ParseCustomRules(config.customRules);
    
    // 注意：chnroute等大列表通常由更新线程处理，或者Initialize加载
    // 这里如果切换开关，应该尝试加载
}

BypassConfig RuleManager::GetBypassConfig() const {
    return bypassConfig_;
}

bool RuleManager::IsBlacklisted(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    return MatchCIDR(ip, blacklistCIDRs_);
}

bool RuleManager::ShouldBypass(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 自定义规则 - IP/CIDR 匹配
    if (!customBypassCIDRs_.empty() && MatchCIDR(ip, customBypassCIDRs_)) {
        Utils::Log("Bypass matched custom rule for IP: " + ip);
        return true;
    }
    
    // 自定义规则 - 域名匹配
    // 规则 "shanghaiit.com" 应匹配 "shanghaiit.com" 和 "*.shanghaiit.com"
    if (!domain.empty() && !customBypassDomains_.empty()) {
        std::string lowerDomain = domain;
        for (char& c : lowerDomain) c = tolower(c);
        
        for (const auto& rule : customBypassDomains_) {
            std::string lowerRule = rule;
            for (char& c : lowerRule) c = tolower(c);
            
            // 完全匹配
            if (lowerDomain == lowerRule) {
                Utils::Log("Bypass matched domain rule (exact): " + domain);
                return true;
            }
            
            // 子域名匹配: domain 以 ".rule" 结尾
            // 例如: www.shanghaiit.com 匹配规则 shanghaiit.com
            std::string suffix = "." + lowerRule;
            if (lowerDomain.length() > suffix.length() && 
                lowerDomain.substr(lowerDomain.length() - suffix.length()) == suffix) {
                Utils::Log("Bypass matched domain rule (subdomain): " + domain + " -> " + rule);
                return true;
            }
        }
    }
    
    // chnroute
    if (bypassConfig_.enableChnRoute && !chnRoute_.empty()) {
        if (MatchCIDR(ip, chnRoute_)) {
            Utils::Log("Bypass matched chnroute for IP: " + ip);
            return true;
        }
    }

    // 中国国内流量直连
    if (chinaDirectEnabled_ && IsChinaTrafficLocked(ip, domain)) {
        return true;
    }
    
    return false;
}

void RuleManager::ParseCIDRList(const std::string& content, std::vector<CIDR>& list) {
    list.clear();
    
    // 将所有分隔符统一处理：换行、逗号、空格
    std::string normalized = content;
    for (char& c : normalized) {
        if (c == ',' || c == '\r' || c == '\n') c = ' ';
    }
    
    std::stringstream ss(normalized);
    std::string token;
    while (ss >> token) {
        // token 已经被 >> 自动去除空白
        if (token.empty()) continue;
        
        unsigned int ipVal = 0;
        unsigned int maskVal = 0xFFFFFFFF;
        
        size_t slash = token.find('/');
        std::string ipStr = token;
        int prefix = 32;
        
        if (slash != std::string::npos) {
            ipStr = token.substr(0, slash);
            prefix = std::atoi(token.substr(slash + 1).c_str());
        }
        
        if (inet_pton(AF_INET, ipStr.c_str(), &ipVal) == 1) {
            if (prefix < 0) prefix = 0;
            if (prefix > 32) prefix = 32;
            
            if (prefix == 0) maskVal = 0;
            else {
                // 网络字节序mask
                unsigned int m = 0xFFFFFFFF << (32 - prefix);
                maskVal = htonl(m);
            }
            
            list.push_back({ipVal & maskVal, maskVal});
        }
    }
}

void RuleManager::ParseCustomRules(const std::string& content) {
    customBypassCIDRs_.clear();
    customBypassDomains_.clear();
    
    // 将所有分隔符统一处理：换行、逗号、空格
    std::string normalized = content;
    for (char& c : normalized) {
        if (c == ',' || c == '\r' || c == '\n') c = ' ';
    }
    
    std::stringstream ss(normalized);
    std::string token;
    while (ss >> token) {
        if (token.empty()) continue;
        
        // 判断是否为 IP/CIDR（检查是否全为数字和点和斜杠）
        bool isIP = true;
        for (char c : token) {
            if (!isdigit(c) && c != '.' && c != '/') {
                isIP = false;
                break;
            }
        }
        
        if (isIP) {
            // 解析为 CIDR
            unsigned int ipVal = 0;
            unsigned int maskVal = 0xFFFFFFFF;
            
            size_t slash = token.find('/');
            std::string ipStr = token;
            int prefix = 32;
            
            if (slash != std::string::npos) {
                ipStr = token.substr(0, slash);
                prefix = std::atoi(token.substr(slash + 1).c_str());
            }
            
            if (inet_pton(AF_INET, ipStr.c_str(), &ipVal) == 1) {
                if (prefix < 0) prefix = 0;
                if (prefix > 32) prefix = 32;
                
                if (prefix == 0) maskVal = 0;
                else {
                    unsigned int m = 0xFFFFFFFF << (32 - prefix);
                    maskVal = htonl(m);
                }
                
                customBypassCIDRs_.push_back({ipVal & maskVal, maskVal});
            }
        } else {
            // 作为域名处理
            customBypassDomains_.push_back(token);
        }
    }
    
    Utils::Log("ParseCustomRules: " + std::to_string(customBypassCIDRs_.size()) + " CIDRs, " +
               std::to_string(customBypassDomains_.size()) + " domains");
}

bool RuleManager::MatchCIDR(const std::string& ip, const std::vector<CIDR>& list) {
    unsigned int ipVal = 0;
    if (inet_pton(AF_INET, ip.c_str(), &ipVal) != 1) return false;
    
    // TODO: 使用二分查找优化性能
    for (const auto& item : list) {
        if ((ipVal & item.mask) == item.ip) {
            return true;
        }
    }
    return false;
}

void RuleManager::LoadChinaDirectConfig() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 初始化私网 / 局域网 CIDR 列表
    if (lanCIDRs_.empty()) {
        std::string lanCidrStr = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10";
        ParseCIDRList(lanCidrStr, lanCIDRs_);
    }

    // 初始化国内常见主流服务域名列表
    if (popularChinaDomains_.empty()) {
        popularChinaDomains_ = {
            "baidu.com", "bdstatic.com", "baidupcs.com", "hao123.com",
            "qq.com", "tencent.com", "wechat.com", "weixin.com", "qpic.cn", "qlogo.cn", "tenpay.com", "gtimg.com", "myqcloud.com", "kugou.com", "kuwo.cn",
            "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "alibaba.com", "alicdn.com", "1688.com", "dingtalk.com", "ele.me", "cainiao.com",
            "douyin.com", "bytedance.com", "toutiao.com", "feishu.cn", "zijieapi.com", "pstatp.com", "ixigua.com",
            "jd.com", "360buy.com", "jdpay.com",
            "163.com", "126.com", "netease.com", "yeah.net", "youdao.com",
            "bilibili.com", "bilivideo.com", "hdslb.com",
            "zhihu.com", "zhimg.com",
            "weibo.com", "sina.com", "weibo.cn", "sinaimg.cn", "sinajs.cn",
            "meituan.com", "dianping.com", "kuaishou.com", "yximgs.com",
            "xiaohongshu.com", "xhscdn.com",
            "pinduoduo.com", "yangkeduo.com", "pddpic.com",
            "ctrip.com", "qunar.com", "amap.com", "autonavi.com",
            "iqiyi.com", "youku.com", "mgtv.com", "sohu.com", "ximalaya.com", "douyu.com", "huya.com",
            "csdn.net", "gitee.com", "cnki.net", "wps.cn",
            "mi.com", "xiaomi.com", "huawei.com", "vmall.com", "oppo.com", "vivo.com", "honor.com",
            "apple.com.cn", "unionpay.com", "12306.cn", "gov.cn"
        };
    }

    chinaDirectEnabled_ = Database::Instance().GetConfig("china_direct_enabled", "1") == "1";
    chinaDirectCnDomains_ = Database::Instance().GetConfig("china_direct_cn_domains", "1") == "1";
    chinaDirectPopularSites_ = Database::Instance().GetConfig("china_direct_popular_sites", "1") == "1";
    chinaDirectIps_ = Database::Instance().GetConfig("china_direct_ips", "1") == "1";
    chinaDirectLan_ = Database::Instance().GetConfig("china_direct_lan", "1") == "1";
    chinaDirectCustom_ = Database::Instance().GetConfig("china_direct_custom", "");

    // 解析自定义白名单
    customChinaDirectCIDRs_.clear();
    customChinaDirectDomains_.clear();
    if (!chinaDirectCustom_.empty()) {
        std::string normalized = chinaDirectCustom_;
        for (char& c : normalized) {
            if (c == ',' || c == '\r' || c == '\n') c = ' ';
        }
        std::stringstream ss(normalized);
        std::string token;
        while (ss >> token) {
            if (token.empty()) continue;
            bool isIP = true;
            for (char c : token) {
                if (!isdigit(c) && c != '.' && c != '/') {
                    isIP = false;
                    break;
                }
            }
            if (isIP && token.find('.') != std::string::npos) {
                unsigned int ipVal = 0, maskVal = 0xFFFFFFFF;
                size_t slash = token.find('/');
                std::string ipStr = token;
                int prefix = 32;
                if (slash != std::string::npos) {
                    ipStr = token.substr(0, slash);
                    prefix = std::atoi(token.substr(slash + 1).c_str());
                }
                if (inet_pton(AF_INET, ipStr.c_str(), &ipVal) == 1) {
                    if (prefix < 0) prefix = 0;
                    if (prefix > 32) prefix = 32;
                    if (prefix == 0) maskVal = 0;
                    else {
                        unsigned int m = 0xFFFFFFFF << (32 - prefix);
                        maskVal = htonl(m);
                    }
                    customChinaDirectCIDRs_.push_back({ipVal & maskVal, maskVal});
                }
            } else {
                customChinaDirectDomains_.push_back(token);
            }
        }
    }

    chinaIpSubUrl_ = Database::Instance().GetConfig("china_ip_sub_url", "https://fastly.jsdelivr.net/gh/mayaxcn/china-ip-list@master/chnroute.txt");
    chinaIpSubIntervalDays_ = std::atoi(Database::Instance().GetConfig("china_ip_sub_interval_days", "7").c_str());
    chinaIpLastUpdate_ = Database::Instance().GetConfig("china_ip_last_update", "");
    chinaIpCidrCount_ = std::atoi(Database::Instance().GetConfig("china_ip_cidr_count", "0").c_str());

    // 尝试加载 chnroute.txt (如果存在)
    if (chnRoute_.empty()) {
        std::ifstream f("data/chnroute.txt");
        if (f.good()) {
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            ParseCIDRList(content, chnRoute_);
            chinaIpCidrCount_ = (int)chnRoute_.size();
        }
    }

    Utils::Log("ChinaDirectConfig: enabled=" + std::to_string(chinaDirectEnabled_) + 
               ", cnDomains=" + std::to_string(chinaDirectCnDomains_) +
               ", popularSites=" + std::to_string(chinaDirectPopularSites_) +
               ", cnIps=" + std::to_string(chinaDirectIps_) +
               ", lan=" + std::to_string(chinaDirectLan_) +
               ", customCount=" + std::to_string(customChinaDirectDomains_.size() + customChinaDirectCIDRs_.size()));
}

bool RuleManager::IsChinaTraffic(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    return IsChinaTrafficLocked(ip, domain);
}

bool RuleManager::IsChinaTrafficLocked(const std::string& ip, const std::string& domain) {
    if (!chinaDirectEnabled_) return false;

    // 1. 局域网 / 私网
    if (chinaDirectLan_) {
        if (!ip.empty() && MatchCIDR(ip, lanCIDRs_)) {
            return true;
        }
        if (domain == "localhost" || domain == "127.0.0.1" ||
            (domain.length() > 6 && domain.substr(domain.length() - 6) == ".local")) {
            return true;
        }
    }

    // 2. 自定义国内直连规则 (IP / 域名)
    if (!customChinaDirectCIDRs_.empty() && !ip.empty()) {
        if (MatchCIDR(ip, customChinaDirectCIDRs_)) {
            return true;
        }
    }
    if (!customChinaDirectDomains_.empty() && !domain.empty()) {
        if (MatchDomain(domain, customChinaDirectDomains_)) {
            return true;
        }
    }

    // 3. 中国顶级域名 (*.cn / *.中国)
    if (chinaDirectCnDomains_ && !domain.empty()) {
        std::string lowerDomain = domain;
        for (char& c : lowerDomain) c = (char)::tolower((unsigned char)c);
        while (!lowerDomain.empty() && lowerDomain.back() == '.') lowerDomain.pop_back();

        if (lowerDomain == "cn" || 
            (lowerDomain.length() > 3 && lowerDomain.substr(lowerDomain.length() - 3) == ".cn")) {
            return true;
        }
        // IDN 中文域名
        if (lowerDomain.find("\xe4\xb8\xad\xe5\x9b\xbd") != std::string::npos) {
            return true;
        }
    }

    // 4. 国内主流高频服务域名
    if (chinaDirectPopularSites_ && !domain.empty()) {
        if (MatchDomain(domain, popularChinaDomains_)) {
            return true;
        }
    }

    // 5. 中国大陆公网 IP 段 (chnroute)
    if (chinaDirectIps_ && !ip.empty()) {
        // 当已通过 SNI/Host 嗅探出真实域名时，如果域名并非已知国内站点或 .cn，
        // 极有可能是国外域名在境内被 GFW 进行 DNS 污染为虚假的国内运营商 IP（如 202.101.48.65 等）。
        // 此时绝不能仅因被污染的客户端目标 IP 落在 chnroute 中就断定为国内流量，
        // 否则将导致国外域名被误判为本地直连并直连虚假 IP 超时。
        // 因此只有在无法嗅探到域名（纯 IP 连接）时，才回退到基于目标 IP 的 chnroute 判定。
        if (domain.empty()) {
            if (!chnRoute_.empty() && MatchCIDR(ip, chnRoute_)) {
                return true;
            }
        }
    }

    return false;
}

// 辅助函数：通过 WinInet 下载网络内容（支持 HTTPS、重定向与超时设置）
static bool DownloadHttpContent(const std::string& url, std::string& outContent, std::string& outErr) {
    HINTERNET hInternet = InternetOpenA(
        "ProxyRelay/1.0 (Windows NT 10.0; Win64; x64)",
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL, NULL, 0
    );
    if (!hInternet) {
        outErr = "初始化网络请求组件失败: " + std::to_string(GetLastError());
        return false;
    }

    DWORD timeout = 25000; // 25s 超时
    InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    const char* headers = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/plain, */*\r\n";
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), headers, (DWORD)strlen(headers), flags | INTERNET_FLAG_SECURE, 0);
    if (!hUrl) {
        // 重试非强制安全连接（如 HTTP 协议）
        hUrl = InternetOpenUrlA(hInternet, url.c_str(), headers, (DWORD)strlen(headers), flags, 0);
    }

    if (!hUrl) {
        InternetCloseHandle(hInternet);
        // 回退尝试 URLDownloadToFileA
        fs::create_directories("data");
        std::string tmpFile = "data/chnroute.tmp";
        HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), tmpFile.c_str(), 0, NULL);
        if (hr == S_OK) {
            std::ifstream f(tmpFile, std::ios::binary);
            if (f.good()) {
                outContent.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                f.close();
                fs::remove(tmpFile);
                if (!outContent.empty()) return true;
            }
        }
        outErr = "无法连接至订阅源地址 (网络超时或连接失败，错误代码: " + std::to_string(GetLastError()) + ")";
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    if (HttpQueryInfoA(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusSize, NULL)) {
        if (statusCode >= 400) {
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            outErr = "订阅源服务器返回 HTTP 错误状态码: " + std::to_string(statusCode);
            return false;
        }
    }

    char buf[16384];
    DWORD bytesRead = 0;
    outContent.clear();
    while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
        outContent.append(buf, bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (outContent.empty()) {
        outErr = "订阅源返回内容为空";
        return false;
    }
    return true;
}

std::string RuleManager::GetChinaIpSubUrl() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chinaIpSubUrl_;
}

void RuleManager::SetChinaIpSubUrl(const std::string& url) {
    std::lock_guard<std::mutex> lock(mutex_);
    chinaIpSubUrl_ = url;
    Database::Instance().SetConfig("china_ip_sub_url", url);
}

int RuleManager::GetChinaIpSubIntervalDays() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chinaIpSubIntervalDays_;
}

void RuleManager::SetChinaIpSubIntervalDays(int days) {
    std::lock_guard<std::mutex> lock(mutex_);
    chinaIpSubIntervalDays_ = days;
    Database::Instance().SetConfig("china_ip_sub_interval_days", std::to_string(days));
}

std::string RuleManager::GetChinaIpLastUpdate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chinaIpLastUpdate_;
}

int RuleManager::GetChinaIpCidrCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chinaIpCidrCount_;
}

bool RuleManager::UpdateChinaIpSubscription(const std::string& customUrl, int* outCount, std::string* outError) {
    std::string targetUrl = customUrl;
    if (targetUrl.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        targetUrl = chinaIpSubUrl_;
    }
    if (targetUrl.empty()) {
        targetUrl = "https://fastly.jsdelivr.net/gh/mayaxcn/china-ip-list@master/chnroute.txt";
    }

    Utils::Log("Updating China IP subscription from: " + targetUrl);

    std::string content, downloadErr;
    if (!DownloadHttpContent(targetUrl, content, downloadErr)) {
        Utils::LogError("Failed to download China IP subscription: " + downloadErr);
        if (outError) *outError = downloadErr;
        return false;
    }

    // 预处理内容，过滤注释行
    std::string cleaned;
    std::stringstream inStream(content);
    std::string line;
    while (std::getline(inStream, line)) {
        size_t first = line.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) continue;
        if (line[first] == '#' || line[first] == ';' || 
            (first + 1 < line.size() && line[first] == '/' && line[first + 1] == '/')) {
            continue;
        }
        cleaned += line + "\n";
    }

    std::vector<CIDR> parsed;
    ParseCIDRList(cleaned, parsed);

    if (parsed.empty()) {
        std::string err = "未能从订阅地址解析到有效的国内 IP 网段 (可能返回了空数据或非 CIDR 列表)";
        Utils::LogError(err);
        if (outError) *outError = err;
        return false;
    }

    // 持久化保存至本地 data/chnroute.txt
    try {
        fs::create_directories("data");
        std::ofstream f("data/chnroute.txt", std::ios::binary | std::ios::trunc);
        if (f.good()) {
            f.write(content.data(), content.size());
            f.close();
        }
    } catch (const std::exception& e) {
        Utils::LogError("Failed to write data/chnroute.txt: " + std::string(e.what()));
    }

    std::string nowStr = Utils::FormatTime(std::time(nullptr));
    int count = (int)parsed.size();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        chnRoute_ = std::move(parsed);
        chinaIpSubUrl_ = targetUrl;
        chinaIpLastUpdate_ = nowStr;
        chinaIpCidrCount_ = count;
    }

    Database::Instance().SetConfig("china_ip_sub_url", targetUrl);
    Database::Instance().SetConfig("china_ip_last_update", nowStr);
    Database::Instance().SetConfig("china_ip_cidr_count", std::to_string(count));

    Utils::Log("China IP subscription updated successfully: " + std::to_string(count) + " CIDRs");

    if (outCount) *outCount = count;
    return true;
}

void RuleManager::StartAutoUpdate() {
    if (autoUpdateRunning_) return;
    autoUpdateRunning_ = true;
    autoUpdateThread_ = std::thread(&RuleManager::AutoUpdateLoop, this);
}

void RuleManager::StopAutoUpdate() {
    if (!autoUpdateRunning_) return;
    autoUpdateRunning_ = false;
    if (autoUpdateThread_.joinable()) {
        autoUpdateThread_.join();
    }
}

void RuleManager::TriggerUpdate() {
    std::thread([this]() {
        int count = 0;
        std::string err;
        this->UpdateChinaIpSubscription(this->chinaIpSubUrl_, &count, &err);
    }).detach();
}

void RuleManager::DownloadRules() {
    int count = 0;
    std::string err;
    UpdateChinaIpSubscription(chinaIpSubUrl_, &count, &err);
}

void RuleManager::AutoUpdateLoop() {
    Utils::Log("China IP subscription auto-update thread started");
    
    // 首次启动，稍作延迟（5秒），若尚未下载过任何 IP 段且启用了国内直连，后台自动静默拉取一次
    for (int i = 0; i < 5 && autoUpdateRunning_; i++) {
        Sleep(1000);
    }
    if (autoUpdateRunning_ && chnRoute_.empty() && chinaDirectEnabled_ && chinaDirectIps_) {
        Utils::Log("China IP list is empty, triggering initial subscription download...");
        int count = 0;
        std::string err;
        UpdateChinaIpSubscription(chinaIpSubUrl_, &count, &err);
    }

    // 主轮询循环：每 60 秒检查一次是否到达更新周期
    while (autoUpdateRunning_) {
        for (int i = 0; i < 60 && autoUpdateRunning_; i++) {
            Sleep(1000);
        }
        if (!autoUpdateRunning_) break;

        if (chinaIpSubIntervalDays_ <= 0) continue; // 仅手动更新
        if (!chinaDirectEnabled_ || !chinaDirectIps_) continue;

        bool needUpdate = false;
        if (chinaIpLastUpdate_.empty()) {
            needUpdate = true;
        } else {
            struct tm lastTm = {};
            int parsed = sscanf(chinaIpLastUpdate_.c_str(), "%d-%d-%d %d:%d:%d",
                                &lastTm.tm_year, &lastTm.tm_mon, &lastTm.tm_mday,
                                &lastTm.tm_hour, &lastTm.tm_min, &lastTm.tm_sec);
            if (parsed >= 3) {
                lastTm.tm_year -= 1900;
                lastTm.tm_mon -= 1;
                time_t lastTime = mktime(&lastTm);
                time_t now = std::time(nullptr);
                double diffSec = difftime(now, lastTime);
                if (diffSec >= (double)chinaIpSubIntervalDays_ * 86400.0) {
                    needUpdate = true;
                }
            } else {
                needUpdate = true;
            }
        }

        if (needUpdate && autoUpdateRunning_) {
            Utils::Log("China IP subscription interval elapsed, auto updating...");
            int count = 0;
            std::string err;
            UpdateChinaIpSubscription(chinaIpSubUrl_, &count, &err);
        }
    }
}

void RuleManager::ReloadRoutingRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    routingRules_.clear();
    
    auto dbRules = Database::Instance().GetEnabledRoutingRules();
    
    for (const auto& dbRule : dbRules) {
        ParsedRoutingRule rule;
        rule.id = dbRule.id;
        rule.priority = dbRule.priority;
        rule.matchType = dbRule.matchType;
        rule.matchValue = dbRule.matchValue;
        rule.proxyId = dbRule.proxyId;
        rule.targetGroup = dbRule.targetGroup;
        rule.enabled = dbRule.enabled;
        rule.isFallback = dbRule.isFallback;
        
        // 解析匹配值
        if (rule.matchType == "cidr") {
            ParseCIDRList(rule.matchValue, rule.cidrs);
        } else if (rule.matchType == "domain") {
            // 将所有分隔符统一处理
            std::string normalized = rule.matchValue;
            for (char& c : normalized) {
                if (c == ',' || c == '\r' || c == '\n') c = ' ';
            }
            std::stringstream ss(normalized);
            std::string token;
            while (ss >> token) {
                if (!token.empty()) {
                    rule.domains.push_back(token);
                }
            }
        } else {
            // 自动匹配 / 混合模式 (auto, mixed 或其他)
            // 同时解析 IP/CIDR 和域名，无需用户手动区分
            size_t estimatedCount = std::count(rule.matchValue.begin(), rule.matchValue.end(), ' ') + 
                                    std::count(rule.matchValue.begin(), rule.matchValue.end(), '\n') + 1;
            rule.cidrs.reserve(estimatedCount);
            rule.domains.reserve(estimatedCount);
            
            std::string normalized = rule.matchValue;
            for (char& c : normalized) {
                if (c == ',' || c == '\r' || c == '\n') c = ' ';
            }
            std::stringstream ss(normalized);
            std::string token;
            while (ss >> token) {
                if (token.empty()) continue;
                
                // 判断是否为 IP/CIDR（检查是否全为数字和点和斜杠）
                bool isIP = true;
                for (char c : token) {
                    if (!isdigit(c) && c != '.' && c != '/') {
                        isIP = false;
                        break;
                    }
                }
                
                if (isIP && token.find('.') != std::string::npos) {
                    // 解析为 CIDR
                    unsigned int ipVal = 0;
                    unsigned int maskVal = 0xFFFFFFFF;
                    size_t slash = token.find('/');
                    std::string ipStr = token;
                    int prefix = 32;
                    if (slash != std::string::npos) {
                        ipStr = token.substr(0, slash);
                        prefix = std::atoi(token.substr(slash + 1).c_str());
                    }
                    if (inet_pton(AF_INET, ipStr.c_str(), &ipVal) == 1) {
                        if (prefix < 0) prefix = 0;
                        if (prefix > 32) prefix = 32;
                        if (prefix == 0) maskVal = 0;
                        else {
                            unsigned int m = 0xFFFFFFFF << (32 - prefix);
                            maskVal = htonl(m);
                        }
                        rule.cidrs.push_back({ipVal & maskVal, maskVal});
                    }
                } else {
                    // 作为域名或通配符处理
                    rule.domains.push_back(token);
                }
            }
        }
        
        routingRules_.push_back(rule);
    }
    
    // 按优先级排序（数字越小优先级越高，兜底规则永远排在最后）
    std::sort(routingRules_.begin(), routingRules_.end(), 
        [](const ParsedRoutingRule& a, const ParsedRoutingRule& b) {
            if (a.isFallback != b.isFallback) {
                return !a.isFallback; // 非兜底排前，兜底规则排最后
            }
            return a.priority < b.priority;
        });
    
    Utils::Log("Loaded " + std::to_string(routingRules_.size()) + " routing rules");
}

bool RuleManager::MatchDomain(const std::string& domain, const std::vector<std::string>& rules) {
    if (domain.empty() || rules.empty()) return false;
    
    std::string lowerDomain = domain;
    for (char& c : lowerDomain) c = (char)::tolower((unsigned char)c);
    while (!lowerDomain.empty() && lowerDomain.back() == '.') {
        lowerDomain.pop_back();
    }
    if (lowerDomain.empty()) return false;
    
    for (const auto& rule : rules) {
        std::string lowerRule = rule;
        for (char& c : lowerRule) c = (char)::tolower((unsigned char)c);
        while (!lowerRule.empty() && (lowerRule.back() == '.' || ::isspace((unsigned char)lowerRule.back()))) {
            lowerRule.pop_back();
        }
        while (!lowerRule.empty() && ::isspace((unsigned char)lowerRule.front())) {
            lowerRule.erase(lowerRule.begin());
        }
        if (lowerRule.empty()) continue;
        
        // 1. 全通配符
        if (lowerRule == "*" || lowerRule == "all") {
            return true;
        }
        
        // 2. 完全匹配
        if (lowerDomain == lowerRule) {
            return true;
        }
        
        // 3. 处理以 *. 开头的规则 (如 *.google.com)
        if (lowerRule.length() > 2 && lowerRule[0] == '*' && lowerRule[1] == '.') {
            std::string baseDomain = lowerRule.substr(2); // "google.com"
            if (lowerDomain == baseDomain) {
                return true;
            }
            std::string suffix = "." + baseDomain;
            if (lowerDomain.length() > suffix.length() && 
                lowerDomain.compare(lowerDomain.length() - suffix.length(), suffix.length(), suffix) == 0) {
                return true;
            }
            // 进一步支持多级通配符 (如 *.cdn.*.com)
            if (baseDomain.find('*') != std::string::npos && WildcardMatch(lowerDomain, lowerRule)) {
                return true;
            }
            continue;
        }
        
        // 4. 处理以 . 开头的规则 (如 .google.com)
        if (lowerRule.length() > 1 && lowerRule[0] == '.') {
            std::string baseDomain = lowerRule.substr(1); // "google.com"
            if (lowerDomain == baseDomain) {
                return true;
            }
            if (lowerDomain.length() > lowerRule.length() && 
                lowerDomain.compare(lowerDomain.length() - lowerRule.length(), lowerRule.length(), lowerRule) == 0) {
                return true;
            }
            continue;
        }
        
        // 5. 包含 * 通配符的普通规则 (如 *test*.com 或 api.*.example.com)
        if (lowerRule.find('*') != std::string::npos) {
            if (WildcardMatch(lowerDomain, lowerRule)) {
                return true;
            }
            continue;
        }
        
        // 6. 普通域名规则 (如 google.com): 同时匹配 google.com 及其所有子域名 (如 www.google.com)
        std::string suffix = "." + lowerRule;
        if (lowerDomain.length() > suffix.length() && 
            lowerDomain.compare(lowerDomain.length() - suffix.length(), suffix.length(), suffix) == 0) {
            return true;
        }
    }
    return false;
}

// 通配符匹配函数：* 匹配任意数量的任意字符
bool RuleManager::WildcardMatch(const std::string& str, const std::string& pattern) {
    size_t s = 0, p = 0;
    size_t starIdx = std::string::npos, match = 0;
    
    while (s < str.length()) {
        // 当前字符匹配或 pattern 是 ?
        if (p < pattern.length() && (pattern[p] == str[s] || pattern[p] == '?')) {
            s++;
            p++;
        }
        // 遇到 *，记录位置
        else if (p < pattern.length() && pattern[p] == '*') {
            starIdx = p;
            match = s;
            p++;
        }
        // 不匹配，但之前有 *，回溯
        else if (starIdx != std::string::npos) {
            p = starIdx + 1;
            match++;
            s = match;
        }
        // 不匹配且没有 *
        else {
            return false;
        }
    }
    
    // 跳过剩余的 *
    while (p < pattern.length() && pattern[p] == '*') {
        p++;
    }
    
    return p == pattern.length();
}

int RuleManager::GetMatchingProxyId(const std::string& ip, const std::string& domain, std::string* outGroup) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 辅助函数：检查规则是否匹配
    auto checkMatch = [&](const ParsedRoutingRule& rule) -> bool {
        if (!rule.enabled) return false;
        
        if (rule.matchType == "all" || rule.matchValue == "*" || rule.matchValue == "all") {
            return true;
        } else if (rule.matchType == "cidr") {
            return !rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs);
        } else if (rule.matchType == "domain") {
            return !domain.empty() && MatchDomain(domain, rule.domains);
        } else {
            // 自动匹配 / 混合模式 (auto, mixed 或其他)
            if (!rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs)) {
                return true;
            }
            if (!domain.empty() && MatchDomain(domain, rule.domains)) {
                return true;
            }
            // 若包含 "*" 通配符则全量命中
            for (const auto& d : rule.domains) {
                if (d == "*" || d == "all") return true;
            }
        }
        return false;
    };
    
    // 严格按规则优先级顺序（已由 std::sort 保证 priority 越小越排前，兜底规则排最后）从上到下逐条评估
    for (const auto& rule : routingRules_) {
        // 在评估兜底规则前，如果开启了中国国内流量直连且命中，直接直连
        if (rule.isFallback && chinaDirectEnabled_) {
            if (IsChinaTrafficLocked(ip, domain)) {
                Utils::Log("China domestic traffic direct connection matched for " + ip + "/" + domain);
                return 0;  // 直连
            }
        }

        if (checkMatch(rule)) {
            // 明确的直连和阻断优先判定，防止 targetGroup 历史遗留残留值覆盖
            if (rule.proxyId == -2) {
                Utils::Log("Routing rule REJECT matched for " + ip + "/" + domain);
                return -2;  // 拒绝连接
            }
            if (rule.proxyId == 0) {
                Utils::Log("Routing rule DIRECT (Bypass) matched for " + ip + "/" + domain);
                return 0;   // 直连
            }
            if (!rule.targetGroup.empty() || rule.proxyId == -3) {
                if (outGroup) *outGroup = rule.targetGroup;
                Utils::Log("Routing rule GROUP '" + rule.targetGroup + "' matched for " + ip + "/" + domain);
                return -3;  // 匹配到分组
            }
            if (rule.proxyId > 0) {
                if (outGroup) *outGroup = rule.targetGroup;
                Utils::Log("Routing rule PROXY " + std::to_string(rule.proxyId) + " matched for " + ip + "/" + domain);
                return rule.proxyId;  // 使用指定代理
            }
        }
    }
    
    // 无任何规则匹配（或无兜底规则）：若开启了中国国内流量直连且命中，直接直连
    if (chinaDirectEnabled_ && IsChinaTrafficLocked(ip, domain)) {
        Utils::Log("China domestic traffic direct connection matched for " + ip + "/" + domain);
        return 0;  // 直连
    }

    // 无任何路由规则匹配，返回 -1 交由端口默认行为或 Bypass 处理
    return -1;
}

