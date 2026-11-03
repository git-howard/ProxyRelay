#include "UserManager.h"
#include "Utils.h"

#include "Rules.h"
#include <ctime>
#include <sstream>
#include <winsock2.h>
#include <ws2tcpip.h>

UserManager& UserManager::Instance() {
    static UserManager instance;
    return instance;
}

bool UserManager::Authenticate(const std::string& username, const std::string& password,
                               const std::string& clientIP, UserInfo& user) {
    auto& db = Database::Instance();

    // 1. 检查白名单 (直接放行检查，但仍需匹配策略)
    bool isWhitelisted = db.IsWhitelisted(clientIP);

    if (!isWhitelisted) {
        // 2. 检查黑名单 (支持CIDR)
        if (RuleManager::Instance().IsBlacklisted(clientIP) || db.IsBlacklisted(clientIP)) {
             Utils::Log("Auth rejected: IP blacklisted - " + clientIP);
             return false;
        }
        
        // 3. 检查自动封禁
        if (db.IsAutoBanned(clientIP)) {
             Utils::Log("Auth rejected: IP auto-banned - " + clientIP);
             return false;
        }
    }

    // 检查全局免认证IP表 (兼容旧配置)
    if (db.IsNoAuthIP(clientIP)) {
        user.username = "no-auth";
        user.id = 0;
        user.enabled = true;
        Utils::Log("Auth Bypassed: IP is in No-Auth list - " + clientIP);
        return true;
    }

    std::vector<UserInfo> allUsers = db.GetAllUsers();
    std::string currentDate = Utils::GetCurrentDate();
    
    bool userFound = false;
    bool authFailedDueToLimit = false;
    bool authFailedDueToIP = false;
    bool authFailedDueToPass = false;
    bool authFailedDueToExpire = false;
    bool authFailedDueToDisable = false;

    bool isExplicit = !username.empty();

    // 如果显式指定了用户名，但该用户被禁用，直接拒绝
    if (isExplicit) {
        for (const auto& u : allUsers) {
            if (u.username == username && !u.enabled) {
                authFailedDueToDisable = true;
                Utils::Log("Auth failed: user disabled - " + username);
                return false;
            }
        }
    }

    bool hasHigherPriorityPasswordUser = false;

    // 核心认证顺序：严格按用户优先级 (priority ASC, id ASC) 评估
    for (const auto& u : allUsers) {
        if (!u.enabled) continue;
        if (!u.expiryDate.empty() && currentDate > u.expiryDate) continue;

        // 检验客户端 IP 是否符合该用户的允许范围 (如 * 或 CIDR 或单IP)
        if (!Utils::IsIPAllowed(clientIP, u.allowedIPs)) {
            continue;
        }

        // 当前用户 u 的 IP 符合要求
        if (u.password.empty()) {
            // 用户无密码：根据 IP 匹配即可
            // 若存在更高优先级的密码用户，且当前访问尚未通过密码认证，则不允许降级穿透至免密用户
            if (hasHigherPriorityPasswordUser) {
                Utils::Log("Auth failed: blocked from falling through to no-password user '" + u.username + "' due to higher-priority password user for IP " + clientIP);
                if (isExplicit) db.RecordAuthFailure(clientIP);
                return false;
            }

            // 流量配额检验
            if (!CheckTrafficLimit(u.id)) {
                authFailedDueToLimit = true;
                continue;
            }

            user = u;
            db.ClearAuthFailure(clientIP);
            Utils::Log("Auth Bypassed (Priority Match No-Password): User '" + u.username + "' allowed by IP '" + clientIP + "'");
            return true;
        } else {
            // 用户有密码：只要采用密码认证方式都需密码正确
            if (!isExplicit) {
                // 客户端未提供凭据，但该 IP 命中了更高优先级的密码用户，必须要求密码认证，不能直接放行
                Utils::Log("Auth required: Password user '" + u.username + "' has higher priority for IP " + clientIP);
                return false;
            }

            // 客户端提供了用户名和密码
            if (u.username == username) {
                if (u.password != password) {
                    authFailedDueToPass = true;
                    db.RecordAuthFailure(clientIP);
                    Utils::Log("Auth failed: Password mismatch for " + username);
                    return false;
                }
                if (!CheckTrafficLimit(u.id)) {
                    authFailedDueToLimit = true;
                    Utils::Log("Auth failed: Traffic limit exceeded for " + username);
                    return false;
                }

                user = u;
                db.ClearAuthFailure(clientIP);
                Utils::Log("Auth success (Priority Match Password): " + username + " from " + clientIP);
                return true;
            } else {
                // 提供的凭据不是该用户，标记存在更高优先级的密码用户，继续查看后续用户
                hasHigherPriorityPasswordUser = true;
                continue;
            }
        }
    }

    // 如果不是显式登录（即只是探测是否为免密IP连接），不记录失败也不记录封禁
    bool isExplicitAuth = (!username.empty() || !password.empty());

    if (isExplicitAuth) {
        // 认证失败的日志记录
        if (authFailedDueToDisable) {
            Utils::Log("Auth failed: user disabled - " + username);
        } else if (authFailedDueToExpire) {
            Utils::Log("Auth failed: account expired - " + username);
        } else if (authFailedDueToLimit) {
            Utils::Log("Auth failed: traffic limit exceeded for user - " + username);
        } else if (authFailedDueToIP) {
            Utils::Log("Auth failed: IP not allowed - " + username + " from " + clientIP);
        } else if (authFailedDueToPass) {
            Utils::Log("Auth failed: wrong password - " + username);
        } else {
            Utils::Log("Auth failed: user not found - " + username + " from " + clientIP);
        }

        if (!isWhitelisted && !Utils::IsPrivateIP(clientIP)) {
            bool policyEnabled = (db.GetConfig("ban_policy_enabled", "1") != "0");
            if (policyEnabled) {
                db.RecordLoginFailure(clientIP);
                
                int N = std::atoi(db.GetConfig("login_fail_window", "5").c_str());
                int M = std::atoi(db.GetConfig("login_fail_limit", "10").c_str());
                int T = std::atoi(db.GetConfig("ban_duration", "60").c_str());
                
                if (N <= 0) N = 5;
                if (M <= 0) M = 10;
                if (T <= 0) T = 60;
                
                int failures = db.GetLoginFailures(clientIP, N);
                if (failures >= M) {
                    db.AddToAutoBan(clientIP, time(nullptr) + T * 60);
                    Utils::Log("IP Auto-banned: " + clientIP + " for " + std::to_string(T) + " minutes (Failed " + std::to_string(failures) + " times in " + std::to_string(N) + " minutes)");
                }
            }
        }
    }

    if (!isWhitelisted) {
        static time_t lastClean = 0;
        if (time(nullptr) - lastClean > 3600) {
            db.CleanOldLoginFailures(60 * 24);
            lastClean = time(nullptr);
        }
    }
    return false;
}

bool UserManager::CheckTrafficLimit(int userId) {
    if (userId == 0) return true; // 免认证用户不限制流量

    UserInfo user;
    if (!Database::Instance().GetUser(userId, user)) {
        return false;
    }
    
    // 检查每日限制
    if (user.dailyLimit > 0) {
        int64_t dailyUsage = Database::Instance().GetUserDailyUsage(userId);
        if (dailyUsage >= user.dailyLimit) {
            return false;
        }
    }
    
    // 检查每月限制
    if (user.monthlyLimit > 0) {
        int64_t monthlyUsage = Database::Instance().GetUserMonthlyUsage(userId);
        if (monthlyUsage >= user.monthlyLimit) {
            return false;
        }
    }
    
    return true;
}

bool UserManager::CheckIPAllowed(int userId, const std::string& clientIP) {
    UserInfo user;
    if (!Database::Instance().GetUser(userId, user)) {
        return false;
    }
    return Utils::IsIPAllowed(clientIP, user.allowedIPs);
}

bool UserManager::IsTargetAllowed(const std::string& targetIP, const std::string& targetDomain,
                                  const std::string& allowedTargets) {
    // 空或 * 表示无限制
    if (allowedTargets.empty() || allowedTargets == "*") return true;
    
    // 将所有分隔符统一处理：逗号、换行、空格
    std::string normalized = allowedTargets;
    for (char& c : normalized) {
        if (c == ',' || c == '\r' || c == '\n') c = ' ';
    }
    
    std::istringstream ss(normalized);
    std::string token;
    while (ss >> token) {
        if (token.empty() || token == "*") return true;
        
        // 判断是否为 IP/CIDR（检查是否全为数字和点和斜杠）
        bool isIP = true;
        for (char c : token) {
            if (!isdigit(c) && c != '.' && c != '/') {
                isIP = false;
                break;
            }
        }
        
        if (isIP) {
            // IP/CIDR 匹配
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
                unsigned int cidrNet = ipVal & maskVal;
                
                // 检查 targetIP
                if (!targetIP.empty()) {
                    unsigned int tgtVal = 0;
                    if (inet_pton(AF_INET, targetIP.c_str(), &tgtVal) == 1) {
                        if ((tgtVal & maskVal) == cidrNet) return true;
                    }
                }
            }
        } else {
            // 域名匹配
            std::string lowerRule = token;
            for (char& c : lowerRule) c = tolower(c);
            
            std::string lowerDomain = targetDomain;
            for (char& c : lowerDomain) c = tolower(c);
            
            if (!lowerDomain.empty()) {
                // 完全匹配
                if (lowerDomain == lowerRule) return true;
                
                // 通配符匹配（简单支持 * ）
                if (lowerRule.find('*') != std::string::npos) {
                    // 简单通配符：*.example.com
                    size_t starPos = lowerRule.find('*');
                    if (starPos == 0 && lowerRule.size() > 1 && lowerRule[1] == '.') {
                        // *.example.com -> 匹配 example.com 和 sub.example.com
                        std::string suffix = lowerRule.substr(1); // .example.com
                        if (lowerDomain == lowerRule.substr(2) || 
                            (lowerDomain.length() > suffix.length() && 
                             lowerDomain.substr(lowerDomain.length() - suffix.length()) == suffix)) {
                            return true;
                        }
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
            
            // 也对 targetIP 做域名规则的精确匹配（如果填了IP形式的域名规则）
            if (!targetIP.empty()) {
                std::string lowerIP = targetIP;
                for (char& c : lowerIP) c = tolower(c);
                if (lowerIP == lowerRule) return true;
            }
        }
    }
    
    return false;
}
