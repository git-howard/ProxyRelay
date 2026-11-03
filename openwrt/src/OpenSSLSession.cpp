#include "OpenSSLSession.h"
#include "Database.h"
#include <iostream>
#include <sstream>
#include <filesystem>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace fs = std::filesystem;

SSL_CTX* OpenSSLSession::serverCtx_ = nullptr;
SSL_CTX* OpenSSLSession::clientCtx_ = nullptr;
std::recursive_mutex OpenSSLSession::sslMutex_;
std::string OpenSSLSession::activeCertPath_;
std::string OpenSSLSession::activeKeyPath_;
std::string OpenSSLSession::certStatusInfo_ = "初始化中...";

OpenSSLSession::OpenSSLSession() = default;

OpenSSLSession::~OpenSSLSession() {
    Close();
}

void OpenSSLSession::Close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
}

std::string OpenSSLSession::GetDefaultCertDir() {
    if (fs::exists("/etc/proxyrelay")) {
        std::string d = "/etc/proxyrelay/certs";
        try { fs::create_directories(d); } catch (...) {}
        return d;
    }
    std::string d = "cert";
    try { fs::create_directories(d); } catch (...) {}
    return d;
}

std::string OpenSSLSession::GetActiveCertPath() {
    std::lock_guard<std::recursive_mutex> lock(sslMutex_);
    if (!activeCertPath_.empty() && fs::exists(activeCertPath_)) return activeCertPath_;
    return GetDefaultCertDir() + "/server.crt";
}

std::string OpenSSLSession::GetActiveKeyPath() {
    std::lock_guard<std::recursive_mutex> lock(sslMutex_);
    if (!activeKeyPath_.empty() && fs::exists(activeKeyPath_)) return activeKeyPath_;
    return GetDefaultCertDir() + "/server.key";
}

std::string OpenSSLSession::GetCertStatusInfo() {
    std::lock_guard<std::recursive_mutex> lock(sslMutex_);
    return certStatusInfo_;
}

std::string OpenSSLSession::GetCertDetails(const std::string& certPath) {
    if (!fs::exists(certPath)) return "证书文件未就绪";
    FILE* fp = fopen(certPath.c_str(), "r");
    if (!fp) return "无法读取证书文件";
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) return "PEM 证书解析失败";

    char subject[256] = {0};
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject) - 1);

    ASN1_TIME* notAfter = X509_get_notAfter(cert);
    std::string expStr;
    if (notAfter) {
        BIO* b = BIO_new(BIO_s_mem());
        if (b) {
            ASN1_TIME_print(b, notAfter);
            char buf[128] = {0};
            int n = BIO_read(b, buf, sizeof(buf) - 1);
            if (n > 0) expStr = std::string(buf, n);
            BIO_free(b);
        }
    }
    X509_free(cert);

    std::string res = subject;
    if (!expStr.empty()) res += " (到期: " + expStr + ")";
    return res;
}

bool OpenSSLSession::InitializeSSL() {
    std::lock_guard<std::recursive_mutex> lock(sslMutex_);
    if (serverCtx_) return true;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    serverCtx_ = SSL_CTX_new(TLS_server_method());
    clientCtx_ = SSL_CTX_new(TLS_client_method());

    if (!serverCtx_ || !clientCtx_) {
        std::cerr << "Failed to create OpenSSL context." << std::endl;
        return false;
    }

    // 设置安全选项
    SSL_CTX_set_min_proto_version(serverCtx_, TLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(clientCtx_, TLS1_2_VERSION);

    std::string defaultDir = GetDefaultCertDir();
    std::string defaultCert = defaultDir + "/server.crt";
    std::string defaultKey = defaultDir + "/server.key";

    std::string certMode = Database::Instance().GetConfig("https_cert_mode", "self_signed");
    std::string customCert = Database::Instance().GetConfig("https_cert_file", "");
    std::string customKey = Database::Instance().GetConfig("https_key_file", "");

    bool loaded = false;
    if (certMode == "custom" && !customCert.empty() && !customKey.empty()) {
        if (LoadCertificates(customCert, customKey)) {
            activeCertPath_ = customCert;
            activeKeyPath_ = customKey;
            certStatusInfo_ = "自定义证书已生效 [" + GetCertDetails(customCert) + "]";
            loaded = true;
        }
    }

    if (!loaded) {
        if (!fs::exists(defaultCert) || !fs::exists(defaultKey)) {
            std::cout << "[OpenSSL] Generating self-signed certificate in " << defaultDir << "..." << std::endl;
            GenerateSelfSignedCert(defaultCert, defaultKey, Database::Instance().GetConfig("cert_domains", ""));
        }
        LoadCertificates(defaultCert, defaultKey);
        activeCertPath_ = defaultCert;
        activeKeyPath_ = defaultKey;
        certStatusInfo_ = "内置自签名证书已就绪 [" + GetCertDetails(defaultCert) + "]";
    }

    return true;
}

void OpenSSLSession::CleanupSSL() {
    std::lock_guard<std::recursive_mutex> lock(sslMutex_);
    if (serverCtx_) {
        SSL_CTX_free(serverCtx_);
        serverCtx_ = nullptr;
    }
    if (clientCtx_) {
        SSL_CTX_free(clientCtx_);
        clientCtx_ = nullptr;
    }
    EVP_cleanup();
}

bool OpenSSLSession::LoadCertificates(const std::string& certPath, const std::string& keyPath) {
    if (!fs::exists(certPath) || !fs::exists(keyPath)) return false;

    if (SSL_CTX_use_certificate_file(serverCtx_, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(serverCtx_, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        return false;
    }
    if (!SSL_CTX_check_private_key(serverCtx_)) {
        return false;
    }
    return true;
}

bool OpenSSLSession::ReloadCertificates(const std::string& certPath, const std::string& keyPath, std::string& err) {
    if (!fs::exists(certPath)) {
        err = "公钥证书文件不存在: " + certPath;
        return false;
    }
    if (!fs::exists(keyPath)) {
        err = "私钥文件不存在: " + keyPath;
        return false;
    }

    SSL_CTX* tempCtx = SSL_CTX_new(TLS_server_method());
    if (!tempCtx) {
        err = "无法创建 OpenSSL 上下文";
        return false;
    }
    SSL_CTX_set_min_proto_version(tempCtx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(tempCtx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        char buf[256] = {0};
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf) - 1);
        err = std::string("无效的公钥证书文件 (需为 PEM 格式): ") + buf;
        SSL_CTX_free(tempCtx);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(tempCtx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        char buf[256] = {0};
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf) - 1);
        err = std::string("无效的私钥文件 (需为 PEM 格式): ") + buf;
        SSL_CTX_free(tempCtx);
        return false;
    }

    if (!SSL_CTX_check_private_key(tempCtx)) {
        err = "私钥与公钥证书不匹配！请确认私钥与当前证书配套。";
        SSL_CTX_free(tempCtx);
        return false;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(sslMutex_);
        SSL_CTX* oldCtx = serverCtx_;
        serverCtx_ = tempCtx;
        if (oldCtx) {
            SSL_CTX_free(oldCtx);
        }
        activeCertPath_ = certPath;
        activeKeyPath_ = keyPath;
        certStatusInfo_ = "自定义证书已生效 [" + GetCertDetails(certPath) + "]";
    }
    return true;
}

bool OpenSSLSession::GenerateSelfSignedCert(const std::string& certPath, const std::string& keyPath, const std::string& domains) {
    std::string targetCert = certPath.empty() ? (GetDefaultCertDir() + "/server.crt") : certPath;
    std::string targetKey = keyPath.empty() ? (GetDefaultCertDir() + "/server.key") : keyPath;

    try {
        fs::create_directories(fs::path(targetCert).parent_path());
    } catch (...) {}

    EVP_PKEY* pkey = EVP_PKEY_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 315360000L); // 10 years

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"CN", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"ProxyRelay", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"ProxyRelay Local Gateway", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // 添加扩展与 SAN
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);

    X509_EXTENSION* ext_bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, (char*)"CA:FALSE");
    if (ext_bc) {
        X509_add_ext(x509, ext_bc, -1);
        X509_EXTENSION_free(ext_bc);
    }

    std::string sanStr = "DNS:localhost,IP:127.0.0.1,IP:::1,DNS:ProxyRelay";
    if (!domains.empty()) {
        std::stringstream ss(domains);
        std::string item;
        while (std::getline(ss, item, ',')) {
            while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) item.erase(item.begin());
            while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) item.pop_back();
            if (item.empty()) continue;

            bool isIp = true;
            for (char c : item) {
                if (c != '.' && (c < '0' || c > '9') && c != ':') { isIp = false; break; }
            }
            sanStr += isIp ? (",IP:" + item) : (",DNS:" + item);
        }
    }

    X509_EXTENSION* ext_san = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, (char*)sanStr.c_str());
    if (ext_san) {
        X509_add_ext(x509, ext_san, -1);
        X509_EXTENSION_free(ext_san);
    }

    X509_sign(x509, pkey, EVP_sha256());

    FILE* fKey = fopen(targetKey.c_str(), "wb");
    if (fKey) {
        PEM_write_PrivateKey(fKey, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fKey);
    }

    FILE* fCert = fopen(targetCert.c_str(), "wb");
    if (fCert) {
        PEM_write_X509(fCert, x509);
        fclose(fCert);
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    std::string err;
    ReloadCertificates(targetCert, targetKey, err);
    {
        std::lock_guard<std::recursive_mutex> lock(sslMutex_);
        certStatusInfo_ = "内置自签名证书已重新生成 [" + GetCertDetails(targetCert) + "]";
    }
    return true;
}

bool OpenSSLSession::ResetToDefaultCert() {
    std::string defaultCert = GetDefaultCertDir() + "/server.crt";
    std::string defaultKey = GetDefaultCertDir() + "/server.key";
    if (!fs::exists(defaultCert) || !fs::exists(defaultKey)) {
        GenerateSelfSignedCert(defaultCert, defaultKey, Database::Instance().GetConfig("cert_domains", ""));
    }
    std::string err;
    if (ReloadCertificates(defaultCert, defaultKey, err)) {
        {
            std::lock_guard<std::recursive_mutex> lock(sslMutex_);
            certStatusInfo_ = "内置自签名证书已就绪 [" + GetCertDetails(defaultCert) + "]";
        }
        return true;
    }
    return false;
}

bool OpenSSLSession::AcceptHandshake(SOCKET sock) {
    if (!serverCtx_) return false;
    ssl_ = SSL_new(serverCtx_);
    if (!ssl_) return false;

    SSL_set_fd(ssl_, sock);
    int ret = SSL_accept(ssl_);
    if (ret <= 0) {
        Close();
        return false;
    }
    return true;
}

bool OpenSSLSession::ConnectHandshake(SOCKET sock) {
    if (!clientCtx_) return false;
    ssl_ = SSL_new(clientCtx_);
    if (!ssl_) return false;

    SSL_set_fd(ssl_, sock);
    int ret = SSL_connect(ssl_);
    if (ret <= 0) {
        Close();
        return false;
    }
    return true;
}

int OpenSSLSession::Read(char* buf, int len) {
    if (!ssl_) return -1;
    return SSL_read(ssl_, buf, len);
}

int OpenSSLSession::Write(const char* buf, int len) {
    if (!ssl_) return -1;
    return SSL_write(ssl_, buf, len);
}

int OpenSSLSession::Peek(char* buf, int len) {
    if (!ssl_) return -1;
    return SSL_peek(ssl_, buf, len);
}

bool OpenSSLSession::HasPendingData() const {
    if (!ssl_) return false;
    return SSL_pending(ssl_) > 0;
}
