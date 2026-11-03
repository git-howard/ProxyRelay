#pragma once

#include "Common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <string>
#include <memory>
#include <mutex>

class OpenSSLSession {
public:
    OpenSSLSession();
    ~OpenSSLSession();

    static bool InitializeSSL();
    static void CleanupSSL();

    static bool LoadCertificates(const std::string& certPath, const std::string& keyPath);
    static bool ReloadCertificates(const std::string& certPath, const std::string& keyPath, std::string& err);
    static bool GenerateSelfSignedCert(const std::string& certPath = "",
                                       const std::string& keyPath = "",
                                       const std::string& domains = "");
    static bool ResetToDefaultCert();

    static std::string GetDefaultCertDir();
    static std::string GetActiveCertPath();
    static std::string GetActiveKeyPath();
    static std::string GetCertStatusInfo();
    static std::string GetCertDetails(const std::string& certPath);

    bool AcceptHandshake(SOCKET sock);
    bool ConnectHandshake(SOCKET sock);

    int Read(char* buf, int len);
    int Write(const char* buf, int len);
    int Peek(char* buf, int len);
    bool HasPendingData() const;
    void Close();

private:
    SSL* ssl_ = nullptr;
    static SSL_CTX* serverCtx_;
    static SSL_CTX* clientCtx_;
    static std::recursive_mutex sslMutex_;

    static std::string activeCertPath_;
    static std::string activeKeyPath_;
    static std::string certStatusInfo_;
};
