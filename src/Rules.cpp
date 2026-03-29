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

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "ws2_32.lib")

namespace fs = std::filesystem;

RuleManager& RuleManager::Instance() {
    static RuleManager instance;
    return instance;
}

RuleManager::RuleManager() {
    blacklistRules_ = "127.0.0.1,10.0.0.0/8,192.168.0.0/16,172.16.0.0/16";
    bypassConfig_ = {false, false, false, ""};
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

void RuleManager::StartAutoUpdate() {
   // TODO
}

void RuleManager::StopAutoUpdate() {
   // TODO
}

void RuleManager::TriggerUpdate() {
    std::thread([this]() {
        this->DownloadRules();
    }).detach();
}

void RuleManager::DownloadRules() {
    fs::create_directories("data");
    
    // 下载chnroute
    HRESULT hr = URLDownloadToFileA(NULL, "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt", "data/chnroute.txt", 0, NULL);
    if (hr == S_OK) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (bypassConfig_.enableChnRoute) {
            std::ifstream f("data/chnroute.txt");
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            ParseCIDRList(content, chnRoute_);
        }
    }
    // TODO: others
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
        rule.enabled = dbRule.enabled;
        
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
        } else if (rule.matchType == "mixed") {
            // 混合类型：同时解析 IP/CIDR 和域名
            // 预估条目数量并预留空间
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
                        rule.cidrs.push_back({ipVal & maskVal, maskVal});
                    }
                } else {
                    // 作为域名处理
                    rule.domains.push_back(token);
                }
            }
        }
        
        routingRules_.push_back(rule);
    }
    
    // 按优先级排序（数字越小优先级越高）
    std::sort(routingRules_.begin(), routingRules_.end(), 
        [](const ParsedRoutingRule& a, const ParsedRoutingRule& b) {
            return a.priority < b.priority;
        });
    
    Utils::Log("Loaded " + std::to_string(routingRules_.size()) + " routing rules");
}

bool RuleManager::MatchDomain(const std::string& domain, const std::vector<std::string>& rules) {
    if (domain.empty() || rules.empty()) return false;
    
    std::string lowerDomain = domain;
    for (char& c : lowerDomain) c = tolower(c);
    
    for (const auto& rule : rules) {
        std::string lowerRule = rule;
        for (char& c : lowerRule) c = tolower(c);
        
        // 完全匹配
        if (lowerDomain == lowerRule) {
            return true;
        }
        
        // 通配符匹配：支持 * 匹配任意字符
        if (lowerRule.find('*') != std::string::npos) {
            // 简单通配符匹配实现
            if (WildcardMatch(lowerDomain, lowerRule)) {
                return true;
            }
        } else {
            // 子域名匹配: domain 以 ".rule" 结尾
            std::string suffix = "." + lowerRule;
            if (lowerDomain.length() > suffix.length() && 
                lowerDomain.substr(lowerDomain.length() - suffix.length()) == suffix) {
                return true;
            }
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

int RuleManager::GetMatchingProxyId(const std::string& ip, const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 辅助函数：检查规则是否匹配
    auto checkMatch = [&](const ParsedRoutingRule& rule) -> bool {
        if (!rule.enabled) return false;
        
        if (rule.matchType == "all") {
            return true;
        } else if (rule.matchType == "cidr") {
            return !rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs);
        } else if (rule.matchType == "domain") {
            return !domain.empty() && MatchDomain(domain, rule.domains);
        } else if (rule.matchType == "mixed") {
            if (!rule.cidrs.empty() && MatchCIDR(ip, rule.cidrs)) {
                return true;
            }
            if (!domain.empty() && MatchDomain(domain, rule.domains)) {
                return true;
            }
        }
        return false;
    };
    
    // 第一阶段：优先匹配代理规则（proxyId > 0），按规则优先级顺序
    for (const auto& rule : routingRules_) {
        if (rule.proxyId > 0 && checkMatch(rule)) {
            return rule.proxyId;
        }
    }
    
    // 第二阶段：匹配直连规则（proxyId = 0）
    for (const auto& rule : routingRules_) {
        if (rule.proxyId == 0 && checkMatch(rule)) {
            return 0;  // 直连
        }
    }
    
    // 没有匹配的规则，返回 -1 表示使用默认逻辑
    return -1;
}

