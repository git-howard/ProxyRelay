#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <vector>
#include <mutex>
#include <memory>
#include <string>
#include <chrono>

#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>

class SchannelSession {
public:
    SchannelSession();
    ~SchannelSession();

    // 初始化全局凭据句柄（在 ProxyServer 启动时调用）
    static bool InitializeCredentials(bool forceReload = false);
    // 释放全局凭据句柄（在 ProxyServer 停止时调用）
    static void FreeCredentials();
    // 重新加载凭据
    static bool ReloadCredentials();

    // 从指定公钥证书和私钥文件路径加载并应用自定义证书
    static bool LoadCertAndKeyFromFiles(const std::string& certPath, const std::string& keyPath, std::string& errMessage);
    // 从 PFX/P12 文件路径加载并应用
    static bool LoadPfxFromFile(const std::string& pfxPath, const std::string& password, std::string& errMessage);

    // 检查证书有效期，若不足 24 小时且磁盘上有更新的证书则自动热重载更新
    static bool CheckAndUpdateCertIfExpiring();

    // 生成或重新生成指定自定义域名的自签名证书
    static bool GenerateSelfSignedCert(const std::string& customDomains, std::string& errMessage);

    // 恢复默认内置自签名证书
    static bool ResetToDefaultCert();
    // 导出当前使用的公钥证书为文件
    static bool ExportCurrentCert(const std::string& exportPath);

    // 获取当前证书描述与剩余有效期
    static std::string GetCertStatusInfo();
    static int64_t GetCurrentCertExpiry();

    // 解析指定证书文件的有效期和基本信息
    static bool ParseCertFileExpiry(const std::string& certPath, int64_t& outExpiry, std::string& outSubject, std::string& outIssuer);

    // 执行 TLS 握手，阻塞式
    bool Handshake(SOCKET sock);

    // 从 SSL 连接读取明文数据（非阻塞/阻塞均支持，-2 代表 WOULDBLOCK）
    int Read(SOCKET sock, char* buf, int len);

    // 加密并向 SSL 连接发送明文数据
    int Write(SOCKET sock, const char* buf, int len);

    // 释放当前会话上下文
    void Close();

    // 检查内部是否还有待读取的明文或待解密的密文数据
    bool HasPendingData() const { return !outBuf_.empty() || (!inBuf_.empty() && !needMoreData_); }

    // 解析并纠偏证书文件路径（支持网络驱动器盘符飘移与本地相对路径自动探测）
    static std::string ResolveExistingFilePath(const std::string& inputPath);
    // 保存自定义证书与私钥至本地可靠镜像目录 (certs/)
    static bool SaveCertMirror(const std::string& certPath, const std::string& keyPathOrPass, bool isPfx);
    // 获取本地镜像文件路径
    static std::string GetLocalMirrorCertPath(bool isPfx);
    static std::string GetLocalMirrorKeyPath();

private:
    static CredHandle hCreds_;
    static bool credsInitialized_;
    static std::mutex credsMutex_;

    static int64_t currentCertExpiry_;
    static std::string currentCertMode_;
    static std::string currentCertSubject_;
    static std::string currentCertIssuer_;
    static std::chrono::steady_clock::time_point lastExpiryCheckTime_;
    static int64_t lastAutoReloadUnixTime_;
    static bool isLoadedFromMirror_;
    static bool customCertLoadFailed_;
    static std::string lastCertError_;

    CtxtHandle hContext_;
    bool contextValid_ = false;

    // 内部缓冲区，保存接收的未解密数据（密文）
    std::vector<char> inBuf_;
    // 内部缓冲区，保存已解密但未被上层取走的明文数据
    std::vector<char> outBuf_;
    // 标记当前密文数据是否不完整（DecryptMessage 返回 SEC_E_INCOMPLETE_MESSAGE），需从网络读取更多
    bool needMoreData_ = false;

    // 辅助函数：生成或获取自签名证书
    static PCCERT_CONTEXT GetOrCreateSelfSignedCert(const std::string& customDomains = "", bool forceRecreate = false);
    // 辅助函数：根据文件加载自定义证书上下文
    static PCCERT_CONTEXT LoadCustomCertContext(const std::string& certPath, const std::string& keyPath, std::string& errMessage);
};
