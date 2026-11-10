#include "Rules.h"
#include "Utils.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

RuleManager::RuleManager() {
    Initialize();
}

RuleManager::~RuleManager() {
    StopAutoUpdate();
}

void RuleManager::Initialize() {
    LoadChinaDirectConfig();
    ReloadRoutingRules();
    StartAutoUpdate();
}

void RuleManager::ReloadRoutingRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    parsedRules_.clear();

    auto rawRules = Database::Instance().GetAllRoutingRules();
    for (const auto& r : rawRules) {
        if (!r.enabled) continue;

        ParsedRoutingRule pr;
        pr.id = r.id;
        pr.priority = r.priority;
        pr.matchType = r.matchType;
        pr.matchValue = r.matchValue;
        pr.proxyId = r.proxyId;
        pr.targetGroup = r.targetGroup;
        pr.enabled = r.enabled;
        pr.isFallback = r.isFallback;

        // 分割多行或逗号规则
        std::istringstream stream(r.matchValue);
        std::string line;
        while (std::getline(stream, line)) {
            auto items = Utils::Split(line, ',');
            for (auto& item : items) {
                item = Utils::Trim(item);
                if (!item.empty()) {
                    std::string lowerItem = Utils::ToLower(item);
                    pr.patterns.push_back(lowerItem);

                    bool isIP = true;
                    for (char c : item) {
                        if (!isdigit(c) && c != '.' && c != '/') {
                            isIP = false;
                            break;
                        }
                    }
                    if (isIP && item.find('.') != std::string::npos) {
                        unsigned int ipVal = 0, maskVal = 0xFFFFFFFF;
                        size_t slash = item.find('/');
                        std::string ipStr = item;
                        int prefix = 32;
                        if (slash != std::string::npos) {
                            ipStr = item.substr(0, slash);
                            prefix = std::atoi(item.substr(slash + 1).c_str());
                        }
                        if (inet_pton(AF_INET, ipStr.c_str(), &ipVal) == 1) {
                            if (prefix < 0) prefix = 0;
                            if (prefix > 32) prefix = 32;
                            if (prefix == 0) maskVal = 0;
                            else {
                                unsigned int m = 0xFFFFFFFF << (32 - prefix);
                                maskVal = htonl(m);
                            }
                            pr.cidrs.push_back({ipVal & maskVal, maskVal});
                        }
                    } else {
                        pr.domains.push_back(lowerItem);
                    }
                }
            }
        }
        parsedRules_.push_back(std::move(pr));
    }

    std::sort(parsedRules_.begin(), parsedRules_.end(),
        [](const ParsedRoutingRule& a, const ParsedRoutingRule& b) {
            if (a.isFallback != b.isFallback) {
                return !a.isFallback;
            }
            return a.priority < b.priority;
        });
}

bool RuleManager::WildcardMatch(const std::string& str, const std::string& pattern) {
    size_t s = 0, p = 0;
    size_t starIdx = std::string::npos, match = 0;

    while (s < str.length()) {
        if (p < pattern.length() && (pattern[p] == str[s] || pattern[p] == '?')) {
            s++;
            p++;
        } else if (p < pattern.length() && pattern[p] == '*') {
            starIdx = p;
            match = s;
            p++;
        } else if (starIdx != std::string::npos) {
            p = starIdx + 1;
            match++;
            s = match;
        } else {
            return false;
        }
    }

    while (p < pattern.length() && pattern[p] == '*') {
        p++;
    }

    return p == pattern.length();
}

bool RuleManager::MatchDomain(const std::string& domain, const std::vector<std::string>& rules) {
    if (domain.empty() || rules.empty()) return false;

    std::string lowerDomain = Utils::ToLower(domain);
    while (!lowerDomain.empty() && lowerDomain.back() == '.') {
        lowerDomain.pop_back();
    }
    if (lowerDomain.empty()) return false;

    for (const auto& rule : rules) {
        std::string lowerRule = Utils::ToLower(rule);
        while (!lowerRule.empty() && (lowerRule.back() == '.' || ::isspace((unsigned char)lowerRule.back()))) {
            lowerRule.pop_back();
        }
        while (!lowerRule.empty() && ::isspace((unsigned char)lowerRule.front())) {
            lowerRule.erase(lowerRule.begin());
        }
        if (lowerRule.empty()) continue;

        if (lowerRule == "*" || lowerRule == "all") return true;
        if (lowerDomain == lowerRule) return true;

        if (lowerRule.length() > 2 && lowerRule[0] == '*' && lowerRule[1] == '.') {
            std::string baseDomain = lowerRule.substr(2);
            if (lowerDomain == baseDomain) return true;
            std::string suffix = "." + baseDomain;
            if (lowerDomain.length() > suffix.length() &&
                lowerDomain.compare(lowerDomain.length() - suffix.length(), suffix.length(), suffix) == 0) {
                return true;
            }
            if (baseDomain.find('*') != std::string::npos && WildcardMatch(lowerDomain, lowerRule)) {
                return true;
            }
            continue;
        }

        if (lowerRule.length() > 1 && lowerRule[0] == '.') {
            std::string baseDomain = lowerRule.substr(1);
            if (lowerDomain == baseDomain) return true;
            if (lowerDomain.length() > lowerRule.length() &&
                lowerDomain.compare(lowerDomain.length() - lowerRule.length(), lowerRule.length(), lowerRule) == 0) {
                return true;
            }
            continue;
        }

        if (lowerRule.find('*') != std::string::npos) {
            if (WildcardMatch(lowerDomain, lowerRule)) return true;
            continue;
        }

        std::string suffix = "." + lowerRule;
        if (lowerDomain.length() > suffix.length() &&
            lowerDomain.compare(lowerDomain.length() - suffix.length(), suffix.length(), suffix) == 0) {
            return true;
        }
    }
    return false;
}

bool RuleManager::MatchCIDR(const std::string& ip, const std::vector<CIDR>& list) {
    unsigned int ipVal = 0;
    if (inet_pton(AF_INET, ip.c_str(), &ipVal) != 1) return false;

    for (const auto& item : list) {
        if ((ipVal & item.mask) == item.ip) {
            return true;
        }
    }
    return false;
}

void RuleManager::ParseCIDRList(const std::string& content, std::vector<CIDR>& list) {
    std::stringstream ss(content);
    std::string token;
    while (ss >> token) {
        if (token.empty()) continue;
        if (token[0] == '#' || token[0] == ';') continue;

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
            list.push_back({ipVal & maskVal, maskVal});
        }
    }
}

void RuleManager::LoadChinaDirectConfig() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (lanCIDRs_.empty()) {
        std::string lanCidrStr = "127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10";
        ParseCIDRList(lanCidrStr, lanCIDRs_);
    }

    if (popularChinaDomains_.empty()) {
        popularChinaDomains_ = {
            "baidu.com", "bdstatic.com", "baidupcs.com", "bdimg.com", "bcebos.com", "hao123.com",
            "qq.com", "tencent.com", "wechat.com", "weixin.com", "qpic.cn", "qlogo.cn", "tenpay.com", "gtimg.com", "myqcloud.com", "wxlivecdn.com", "smtcdns.net", "cdntip.com", "dnsv1.com", "kugou.com", "kuwo.cn",
            "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "aliyuncs.com", "alibaba.com", "alicdn.com", "tbcache.com", "mmstat.com", "tanx.com", "alibabausercontent.com", "1688.com", "dingtalk.com", "ele.me", "cainiao.com",
            "douyin.com", "douyincdn.com", "doubao.com", "volces.com", "volcengine.com", "ctobsnssdk.com", "bytedance.com", "byteimg.com", "bytednsdoc.com", "snssdk.com", "toutiao.com", "toutiaovod.com", "feishu.cn", "zijieapi.com", "pstatp.com", "ixigua.com",
            "jd.com", "360buy.com", "360buyimg.com", "jdpay.com", "jdwl.com",
            "163.com", "126.com", "126.net", "127.net", "netease.com", "yeah.net", "youdao.com",
            "bilibili.com", "bilivideo.com", "hdslb.com", "biliapi.net",
            "zhihu.com", "zhimg.com", "douban.com", "doubanio.com", "smzdm.com", "zdmimg.com",
            "weibo.com", "sina.com", "weibo.cn", "sinaimg.cn", "sinajs.cn",
            "meituan.com", "meituan.net", "dianping.com", "dpfile.com", "kuaishou.com", "yximgs.com",
            "xiaohongshu.com", "xhscdn.com",
            "pinduoduo.com", "yangkeduo.com", "pddpic.com",
            "ctrip.com", "c-ctrip.com", "qunar.com", "amap.com", "autonavi.com",
            "iqiyi.com", "iqiyipic.com", "youku.com", "ykimg.com", "mgtv.com", "sohu.com", "ximalaya.com", "douyu.com", "huya.com", "cibntv.net", "miguvideo.com",
            "csdn.net", "gitee.com", "cnki.net", "wps.cn", "oschina.net",
            "mi.com", "xiaomi.com", "miui.com", "huawei.com", "vmall.com", "dbankcdn.com", "oppo.com", "vivo.com", "honor.com",
            "eastmoney.com", "dfcfw.com", "pingan.com", "cmbchina.com", "zhipin.com", "bosszhipin.com", "58.com", "lianjia.com", "ke.com", "sf-express.com", "10010.com",
            "apple.com.cn", "icloud.com.cn", "unionpay.com", "12306.cn", "gov.cn", "oray.com", "oray.net", "qpon",
            "arpa", "lan", "local", "internal", "home", "corp", "localdomain"
        };
    }

    chinaDirectEnabled_ = Database::Instance().GetConfig("china_direct_enabled", "1") == "1";
    chinaDirectCnDomains_ = Database::Instance().GetConfig("china_direct_cn_domains", "1") == "1";
    chinaDirectPopularSites_ = Database::Instance().GetConfig("china_direct_popular_sites", "1") == "1";
    chinaDirectIps_ = Database::Instance().GetConfig("china_direct_ips", "1") == "1";
    chinaDirectLan_ = Database::Instance().GetConfig("china_direct_lan", "1") == "1";
    chinaDirectCustom_ = Database::Instance().GetConfig("china_direct_custom", "");

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

    // 从持久化存储读取国内 IP 列表文件
    if (chnRoute_.empty()) {
        std::vector<std::string> paths = {
            "/etc/proxyrelay/chnroute.txt",
            "/usr/share/proxyrelay/data/chnroute.txt",
            "data/chnroute.txt"
        };
        for (const auto& p : paths) {
            std::ifstream f(p);
            if (f.good()) {
                std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                ParseCIDRList(content, chnRoute_);
                chinaIpCidrCount_ = (int)chnRoute_.size();
                break;
            }
        }
    }
}

bool RuleManager::IsChinaTraffic(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    return IsChinaTrafficLocked(ip, domain);
}

bool RuleManager::IsChinaTrafficLocked(const std::string& ip, const std::string& domain) {
    if (!chinaDirectEnabled_) return false;

    // 1. 局域网 / 私网
    if (chinaDirectLan_) {
        if (domain.empty() && !ip.empty() && MatchCIDR(ip, lanCIDRs_)) {
            return true;
        }
        if (domain == "localhost" || domain == "127.0.0.1" ||
            (domain.length() > 6 && domain.substr(domain.length() - 6) == ".local") ||
            (domain.length() > 4 && domain.substr(domain.length() - 4) == ".lan")) {
            return true;
        }
    }

    // 2. 自定义国内直连规则 (IP / 域名)
    if (!customChinaDirectCIDRs_.empty() && !ip.empty()) {
        if (MatchCIDR(ip, customChinaDirectCIDRs_)) return true;
    }
    if (!customChinaDirectDomains_.empty() && !domain.empty()) {
        if (MatchDomain(domain, customChinaDirectDomains_)) return true;
    }

    // 3. 中国顶级域名 (*.cn / *.中国)
    if (chinaDirectCnDomains_ && !domain.empty()) {
        std::string lowerDomain = Utils::ToLower(domain);
        while (!lowerDomain.empty() && lowerDomain.back() == '.') lowerDomain.pop_back();

        if (lowerDomain == "cn" ||
            (lowerDomain.length() > 3 && lowerDomain.substr(lowerDomain.length() - 3) == ".cn")) {
            return true;
        }
        if (lowerDomain.find("\xe4\xb8\xad\xe5\x9b\xbd") != std::string::npos) {
            return true;
        }
    }

    // 4. 国内主流高频服务域名
    if (chinaDirectPopularSites_ && !domain.empty()) {
        if (MatchDomain(domain, popularChinaDomains_)) return true;
    }

    // 5. 中国大陆公网 IP 段 (chnroute)
    if (chinaDirectIps_ && !ip.empty() && !chnRoute_.empty()) {
        static const std::vector<std::string> kPoisonedForeignDomains = {
            "google.com", "googleapis.com", "gstatic.com", "youtube.com", "ytimg.com", "googlevideo.com",
            "chatgpt.com", "openai.com", "github.com", "githubusercontent.com", "x.com", "twitter.com", "twimg.com",
            "t.me", "telegram.org", "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.com",
            "wikipedia.org", "huggingface.co", "claude.ai", "anthropic.com", "discord.com", "discordapp.com",
            "reddit.com", "netflix.com", "nflxvideo.net", "docker.com", "v2ex.com", "nytimes.com", "bbc.com",
            "wsj.com", "reuters.com", "bloomberg.com", "twitch.tv", "spotify.com", "medium.com", "quora.com",
            "pinterest.com", "dropbox.com", "duckduckgo.com"
        };
        if (domain.empty() || !MatchDomain(domain, kPoisonedForeignDomains)) {
            if (MatchCIDR(ip, chnRoute_)) return true;
        }
    }

    return false;
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

bool RuleManager::DownloadHttpContent(const std::string& url, std::string& outContent, std::string& outErr) {
    std::string tmpFile = "/tmp/chnroute_" + std::to_string(Utils::GetCurrentTimestamp()) + ".tmp";
    std::string safeUrl = "";
    for (char c : url) {
        if (c == '"' || c == '$' || c == '`' || c == '\\') safeUrl += '\\';
        safeUrl += c;
    }
    std::string cmd = "curl -s -L -k --max-time 30 -A \"Mozilla/5.0 (ProxyRelay/OpenWrt)\" \"" + safeUrl + "\" -o \"" + tmpFile + "\" 2>/dev/null";
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::string fallback = "wget -q --no-check-certificate --timeout=30 -O \"" + tmpFile + "\" \"" + safeUrl + "\" 2>/dev/null";
        int r = system(fallback.c_str());
        (void)r;
    }

    std::ifstream f(tmpFile, std::ios::binary);
    if (!f.is_open()) {
        outErr = "无法连接至订阅源地址 (网络超时或无法访问)";
        return false;
    }
    outContent.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    unlink(tmpFile.c_str());

    if (outContent.empty()) {
        outErr = "订阅源返回内容为空";
        return false;
    }
    return true;
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

    std::cout << "[RuleManager] Updating China IP subscription from: " << targetUrl << std::endl;

    std::string content, downloadErr;
    if (!DownloadHttpContent(targetUrl, content, downloadErr)) {
        std::cerr << "[RuleManager] Download failed: " << downloadErr << std::endl;
        if (outError) *outError = downloadErr;
        return false;
    }

    std::vector<CIDR> parsed;
    ParseCIDRList(content, parsed);

    if (parsed.empty()) {
        std::string err = "未能从订阅地址解析到有效的国内 IP 网段 (格式不匹配)";
        std::cerr << "[RuleManager] " << err << std::endl;
        if (outError) *outError = err;
        return false;
    }

    // 持久化存储至 /etc/proxyrelay/chnroute.txt
    mkdir("/etc/proxyrelay", 0755);
    std::ofstream out("/etc/proxyrelay/chnroute.txt", std::ios::binary | std::ios::trunc);
    if (out.is_open()) {
        out.write(content.data(), content.size());
        out.close();
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

    std::cout << "[RuleManager] China IP subscription updated successfully: " << count << " CIDRs" << std::endl;

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

void RuleManager::AutoUpdateLoop() {
    for (int i = 0; i < 5 && autoUpdateRunning_; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (autoUpdateRunning_ && chnRoute_.empty() && chinaDirectEnabled_ && chinaDirectIps_) {
        int count = 0;
        std::string err;
        UpdateChinaIpSubscription(chinaIpSubUrl_, &count, &err);
    }

    while (autoUpdateRunning_) {
        for (int i = 0; i < 60 && autoUpdateRunning_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!autoUpdateRunning_) break;

        if (chinaIpSubIntervalDays_ <= 0) continue;
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
            int count = 0;
            std::string err;
            UpdateChinaIpSubscription(chinaIpSubUrl_, &count, &err);
        }
    }
}

int RuleManager::GetMatchingProxyId(const std::string& ip, const std::string& domain, std::string* outGroup, bool* outIsFallback) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string lowerDomain = Utils::ToLower(domain);

    // 1. 优先评估普通非兜底规则（已由 std::sort 保证优先级越小越先匹配）
    for (const auto& rule : parsedRules_) {
        if (rule.isFallback) continue;

        if (rule.matchType == "all") {
            if (outGroup) *outGroup = rule.targetGroup;
            if (outIsFallback) *outIsFallback = false;
            return rule.proxyId;
        }

        if (!domain.empty() && (rule.matchType == "domain" || rule.matchType == "auto")) {
            if (MatchDomain(domain, rule.domains.empty() ? rule.patterns : rule.domains)) {
                if (outGroup) *outGroup = rule.targetGroup;
                if (outIsFallback) *outIsFallback = false;
                return rule.proxyId;
            }
        }

        if (!ip.empty() && (rule.matchType == "cidr" || rule.matchType == "auto")) {
            if (!rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs)) {
                if (outGroup) *outGroup = rule.targetGroup;
                if (outIsFallback) *outIsFallback = false;
                return rule.proxyId;
            }
            if (rule.cidrs.empty()) {
                for (const auto& cidr : rule.patterns) {
                    if (Utils::MatchCIDR(ip, cidr)) {
                        if (outGroup) *outGroup = rule.targetGroup;
                        if (outIsFallback) *outIsFallback = false;
                        return rule.proxyId;
                    }
                }
            }
        }
    }

    // 2. 在评估兜底规则前，如果开启了中国国内流量直连且命中，直接直连
    if (chinaDirectEnabled_ && IsChinaTrafficLocked(ip, domain)) {
        if (outIsFallback) *outIsFallback = false;
        return 0; // 国内流量直连
    }

    // 3. 评估默认兜底规则
    for (const auto& rule : parsedRules_) {
        if (!rule.isFallback) continue;

        if (rule.matchType == "all" || rule.matchValue == "*" || rule.matchValue == "all") {
            if (outGroup) *outGroup = rule.targetGroup;
            if (outIsFallback) *outIsFallback = true;
            return rule.proxyId;
        }
        if (!domain.empty() && (rule.matchType == "domain" || rule.matchType == "auto")) {
            if (MatchDomain(domain, rule.domains.empty() ? rule.patterns : rule.domains)) {
                if (outGroup) *outGroup = rule.targetGroup;
                if (outIsFallback) *outIsFallback = true;
                return rule.proxyId;
            }
        }
        if (!ip.empty() && (rule.matchType == "cidr" || rule.matchType == "auto")) {
            if (!rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs)) {
                if (outGroup) *outGroup = rule.targetGroup;
                if (outIsFallback) *outIsFallback = true;
                return rule.proxyId;
            }
        }
    }

    // 4. 无任何规则匹配：若开启了中国国内流量直连且命中，直接直连
    if (chinaDirectEnabled_ && IsChinaTrafficLocked(ip, domain)) {
        if (outIsFallback) *outIsFallback = false;
        return 0;
    }

    if (outIsFallback) *outIsFallback = true;
    return -1; // 无匹配，由上游端口默认行为处理
}

bool RuleManager::IsDirectIP(const std::string& ip) {
    if (Utils::MatchCIDR(ip, "127.0.0.0/8") ||
        Utils::MatchCIDR(ip, "10.0.0.0/8") ||
        Utils::MatchCIDR(ip, "172.16.0.0/12") ||
        Utils::MatchCIDR(ip, "192.168.0.0/16") ||
        Utils::MatchCIDR(ip, "169.254.0.0/16") ||
        Utils::MatchCIDR(ip, "100.64.0.0/10")) {
        return true;
    }
    return false;
}
