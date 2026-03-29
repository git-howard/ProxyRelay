#include "UserManager.h"
#include "Utils.h"

#include "Rules.h"
#include <ctime>

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

    // 按顺序遍历用户（由于 GetAllUsers 已经 ORDER BY priority ASC，顺序由用户调整上下决定）
    for (const auto& u : allUsers) {
        if (!u.enabled) {
            if (u.username == username && !username.empty()) {
                userFound = true;
                authFailedDueToDisable = true;
            }
            continue;
        }

        bool ipAllowed = Utils::IsIPAllowed(clientIP, u.allowedIPs);

        // 策略1: 无密码IP匹配 (只要该用户没设密码且指定了允许的IP，凡是该IP来的都算作该用户，不论传输的用户名是什么)
        bool matchIPNoPass = u.password.empty() && u.allowedIPs != "*" && ipAllowed;

        // 策略2: 用户名密码匹配
        bool matchUserPass = (!username.empty() && u.username == username && u.password == password);

        if (matchUserPass) {
            userFound = true;
        }

        // 如果命中了任何一条策略
        if (matchIPNoPass || matchUserPass) {
            // 如果是因为账号密码命中，但IP不符合
            if (matchUserPass && !ipAllowed) {
                authFailedDueToIP = true;
                continue; // 尝试匹配下一个策略/用户
            }

            // 检查账户到期
            if (!u.expiryDate.empty() && currentDate > u.expiryDate) {
                authFailedDueToExpire = true;
                continue; // 尝试匹配下一个策略/用户
            }

            // 检查流量限制
            if (CheckTrafficLimit(u.id)) {
                user = u;
                if (matchIPNoPass) {
                    Utils::Log("Auth Bypassed (IP Match By Order): User '" + u.username + "' allowed by IP '" + clientIP + "'");
                } else {
                    Utils::Log("Auth success (User/Pass Match By Order): " + username + " from " + clientIP);
                }
                return true;
            } else {
                authFailedDueToLimit = true;
                continue; // 继续下一个用户试试
            }
        } else if (u.username == username && !username.empty() && ipAllowed) {
            // 用户名对上了，IP也对上了，但密码不对并且不是免密码的IP
            authFailedDueToPass = true;
        }
    }

    // 认证失败的日志记录
    if (authFailedDueToDisable) {
        Utils::Log("Auth failed: user disabled - " + username);
    } else if (authFailedDueToExpire) {
        Utils::Log("Auth failed: account expired - " + username);
    } else if (authFailedDueToLimit) {
        Utils::Log("Auth failed: traffic limit exceeded for matched user");
    } else if (authFailedDueToIP) {
        Utils::Log("Auth failed: IP not allowed - " + username + " from " + clientIP);
    } else if (authFailedDueToPass) {
        Utils::Log("Auth failed: wrong password - " + username);
    } else {
        Utils::Log("Auth failed: user not found or no matching policy for - " + username + " from " + clientIP);
    }

    if (!isWhitelisted) {
        db.RecordLoginFailure(clientIP);
        
        int N = std::atoi(db.GetConfig("login_fail_window", "5").c_str());
        int M = std::atoi(db.GetConfig("login_fail_limit", "5").c_str());
        int T = std::atoi(db.GetConfig("ban_duration", "60").c_str());
        
        if (N <= 0) N = 5;
        if (M <= 0) M = 5;
        if (T <= 0) T = 60;
        
        int failures = db.GetLoginFailures(clientIP, N);
        if (failures >= M) {
            db.AddToAutoBan(clientIP, time(nullptr) + T * 60);
            Utils::Log("IP Auto-banned: " + clientIP + " for " + std::to_string(T) + " minutes");
        }
        
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
