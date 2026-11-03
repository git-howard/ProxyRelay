#pragma once

#include "Database.h"
#include <string>

class UserManager {
public:
    static UserManager& Instance();
    
    // 认证用户
    bool Authenticate(const std::string& username, const std::string& password, 
                      const std::string& clientIP, UserInfo& user);
    
    // 检查流量限制
    bool CheckTrafficLimit(int userId);
    
    // 检查IP是否允许
    bool CheckIPAllowed(int userId, const std::string& clientIP);
    
    // 检查目标是否在用户的容许访问列表中
    static bool IsTargetAllowed(const std::string& targetIP, const std::string& targetDomain,
                                const std::string& allowedTargets);
    
private:
    UserManager() = default;
};
