#pragma once

#include "Common.h"
#include <string>
#include <thread>
#include <atomic>
#include <unordered_set>
#include <mutex>
#include "json.hpp"

class WebServer {
public:
    static WebServer& Instance();

    bool Start(int port = 8080, const std::string& uiPath = "ui", const std::string& adminPassword = "");
    void Stop();
    bool IsRunning() const { return running_.load(); }

    void SetAdminPassword(const std::string& pwd) { adminPassword_ = pwd; }
    std::string GetAdminPassword() const { return adminPassword_; }
    bool VerifyPassword(const std::string& pwd) const;
    std::string GenerateSessionToken();
    bool ValidateSessionToken(const std::string& token);
    void InvalidateSessionToken(const std::string& token);

    nlohmann::json DispatchApi(const std::string& action, const nlohmann::json& params);

private:
    WebServer() = default;
    ~WebServer();

    void ServerThread(int port);
    void HandleClient(SOCKET clientSock);

    std::string ReadUiFile(const std::string& filename);

    std::atomic<bool> running_{false};
    std::thread thread_;
    SOCKET listenSock_ = INVALID_SOCKET;
    std::string uiFolderPath_ = "ui";
    std::string adminPassword_;

    mutable std::mutex authMutex_;
    std::unordered_set<std::string> validTokens_;
};
