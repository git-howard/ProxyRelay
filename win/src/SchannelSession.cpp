#include "SchannelSession.h"
#include "Utils.h"
#include "Database.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <filesystem>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

// 静态成员变量初始化
CredHandle SchannelSession::hCreds_;
bool SchannelSession::credsInitialized_ = false;
std::mutex SchannelSession::credsMutex_;

int64_t SchannelSession::currentCertExpiry_ = 0;
std::string SchannelSession::currentCertMode_ = "default";
std::string SchannelSession::currentCertSubject_ = "";
std::string SchannelSession::currentCertIssuer_ = "";
std::chrono::steady_clock::time_point SchannelSession::lastExpiryCheckTime_ = std::chrono::steady_clock::now();
int64_t SchannelSession::lastAutoReloadUnixTime_ = 0;
bool SchannelSession::isLoadedFromMirror_ = false;
bool SchannelSession::customCertLoadFailed_ = false;
std::string SchannelSession::lastCertError_ = "";

std::string SchannelSession::GetLocalMirrorCertPath(bool isPfx) {
    return isPfx ? "certs/custom_cert.pfx" : "certs/custom_cert.crt";
}

std::string SchannelSession::GetLocalMirrorKeyPath() {
    return "certs/custom_key.key";
}

bool SchannelSession::SaveCertMirror(const std::string& certPath, const std::string& keyPathOrPass, bool isPfx) {
    if (certPath.empty()) return false;
    try {
        std::filesystem::create_directories("certs");
        std::string mirrorCert = GetLocalMirrorCertPath(isPfx);
        std::filesystem::path pSrcCert = std::filesystem::u8path(certPath);
        std::filesystem::path pMirrorCert = std::filesystem::u8path(mirrorCert);

        if (std::filesystem::exists(pSrcCert)) {
            bool needCopy = true;
            if (std::filesystem::exists(pMirrorCert)) {
                try {
                    if (std::filesystem::equivalent(pSrcCert, pMirrorCert)) {
                        needCopy = false;
                    }
                } catch (...) {}
            }
            if (needCopy) {
                std::filesystem::copy_file(pSrcCert, pMirrorCert, std::filesystem::copy_options::overwrite_existing);
            }
        }

        if (!isPfx && !keyPathOrPass.empty()) {
            std::string mirrorKey = GetLocalMirrorKeyPath();
            std::filesystem::path pSrcKey = std::filesystem::u8path(keyPathOrPass);
            std::filesystem::path pMirrorKey = std::filesystem::u8path(mirrorKey);
            if (std::filesystem::exists(pSrcKey)) {
                bool needCopy = true;
                if (std::filesystem::exists(pMirrorKey)) {
                    try {
                        if (std::filesystem::equivalent(pSrcKey, pMirrorKey)) {
                            needCopy = false;
                        }
                    } catch (...) {}
                }
                if (needCopy) {
                    std::filesystem::copy_file(pSrcKey, pMirrorKey, std::filesystem::copy_options::overwrite_existing);
                }
            }
        }
        Database::Instance().SetConfig("https_cert_mirror_file", mirrorCert);
        if (!isPfx) {
            Database::Instance().SetConfig("https_key_mirror_file", GetLocalMirrorKeyPath());
        }
        Utils::Log("Schannel: Successfully mirrored custom certificate to local persistent cache: " + mirrorCert);
        return true;
    } catch (const std::exception& e) {
        Utils::LogError(std::string("Schannel: Failed to mirror custom certificate to local cache: ") + e.what());
        return false;
    }
}

std::string SchannelSession::ResolveExistingFilePath(const std::string& inputPath) {
    if (inputPath.empty()) return "";

    // 1. 直接检查输入路径（绝对路径或相对路径）是否存在
    try {
        std::filesystem::path p = std::filesystem::u8path(inputPath);
        if (std::filesystem::exists(p)) {
            return inputPath;
        }
    } catch (...) {}

    // 2. 如果包含驱动器盘符 (如 "Y:\cert\cert.crt" 或 "Y:/cert/cert.crt")
    // 检测系统中是否存在相同相对目录结构的其他驱动器盘符（如 NAS 或外接盘映射从 Y: 变为 Z:）
    if (inputPath.size() >= 3 && inputPath[1] == ':' && (inputPath[2] == '\\' || inputPath[2] == '/')) {
        std::string subPath = inputPath.substr(2); // e.g. "\cert\cert.crt"

        // 遍历当前系统中所有有效驱动器盘符 (从 Z 到 C，优先检索网络映射驱动器与数据盘)
        DWORD drivesMask = GetLogicalDrives();
        for (char drive = 'Z'; drive >= 'A'; --drive) {
            if (drivesMask & (1 << (drive - 'A'))) {
                std::string candidate = std::string(1, drive) + ":" + subPath;
                try {
                    if (std::filesystem::exists(std::filesystem::u8path(candidate))) {
                        Utils::Log("Schannel: Resolved path [" + inputPath + "] across drives -> [" + candidate + "]");
                        return candidate;
                    }
                } catch (...) {}
            }
        }
    }

    return "";
}

static int64_t FileTimeToUnixTime(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    if (uli.QuadPart < 116444736000000000ULL) return 0;
    return (int64_t)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static std::string FormatUnixTime(int64_t t) {
    if (t <= 0) return "未知";
    time_t rawTime = (time_t)t;
    struct tm tmInfo;
    localtime_s(&tmInfo, &rawTime);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmInfo);
    return std::string(buf);
}

void ExportCertToFile(PCCERT_CONTEXT pCert, const std::string& filename) {
    std::ofstream out(std::filesystem::u8path(filename), std::ios::binary);
    if (out.is_open()) {
        out.write((char*)pCert->pbCertEncoded, pCert->cbCertEncoded);
        out.close();
        Utils::Log("Schannel: Exported certificate to " + filename);
    } else {
        Utils::LogError("Schannel: Failed to export certificate to " + filename);
    }
}

SchannelSession::SchannelSession() {
    SecInvalidateHandle(&hContext_);
}

SchannelSession::~SchannelSession() {
    Close();
}

void SchannelSession::Close() {
    if (contextValid_) {
        DeleteSecurityContext(&hContext_);
        SecInvalidateHandle(&hContext_);
        contextValid_ = false;
    }
    inBuf_.clear();
    outBuf_.clear();
    needMoreData_ = false;
}

bool SchannelSession::InitializeCredentials(bool forceReload) {
    std::lock_guard<std::mutex> lock(credsMutex_);
    if (credsInitialized_ && !forceReload) return true;
    if (credsInitialized_) {
        FreeCredentialsHandle(&hCreds_);
        SecInvalidateHandle(&hCreds_);
        credsInitialized_ = false;
    }

    std::string certPath = Database::Instance().GetConfig("https_cert_file", "");
    std::string keyPath = Database::Instance().GetConfig("https_key_file", "");
    std::string certMode = Database::Instance().GetConfig("https_cert_mode", "default");

    PCCERT_CONTEXT pCert = nullptr;
    std::string errMessage;
    isLoadedFromMirror_ = false;
    customCertLoadFailed_ = false;
    lastCertError_ = "";

    if (certMode == "custom") {
        bool isPfx = false;
        if (certPath.size() >= 4) {
            std::string ext = certPath.substr(certPath.size() - 4);
            for (char& c : ext) c = (char)tolower(c);
            if (ext == ".pfx" || ext == ".p12") isPfx = true;
        }

        // 1. 优先尝试解析并加载用户指定或智能纠偏后的原证书路径
        std::string resolvedCert = ResolveExistingFilePath(certPath);
        std::string resolvedKey = isPfx ? keyPath : ResolveExistingFilePath(keyPath);

        if (!resolvedCert.empty() && (isPfx || !resolvedKey.empty())) {
            pCert = LoadCustomCertContext(resolvedCert, resolvedKey, errMessage);
            if (pCert) {
                currentCertMode_ = "custom";
                Utils::Log("Schannel: Successfully loaded custom certificate from " + resolvedCert);
                // 成功从原路径加载后自动同步更新本地镜像
                SaveCertMirror(resolvedCert, resolvedKey, isPfx);
                // 若发生盘符变动纠偏，自动更新数据库配置
                if (resolvedCert != certPath) {
                    Database::Instance().SetConfig("https_cert_file", resolvedCert);
                    certPath = resolvedCert;
                }
                if (!isPfx && !resolvedKey.empty() && resolvedKey != keyPath) {
                    Database::Instance().SetConfig("https_key_file", resolvedKey);
                    keyPath = resolvedKey;
                }
            } else {
                Utils::LogError("Schannel: Failed to load custom certificate from " + resolvedCert + ": " + errMessage);
            }
        }

        // 2. 若原路径无法访问（例如网络盘在开机阶段未挂载、Windows服务环境下无网络盘符），无缝从本地持久镜像加载
        if (!pCert) {
            std::string mirrorCert = GetLocalMirrorCertPath(isPfx);
            std::string mirrorKey = isPfx ? keyPath : GetLocalMirrorKeyPath();
            if (std::filesystem::exists(std::filesystem::u8path(mirrorCert))) {
                std::string mirrorErr;
                pCert = LoadCustomCertContext(mirrorCert, mirrorKey, mirrorErr);
                if (pCert) {
                    currentCertMode_ = "custom";
                    isLoadedFromMirror_ = true;
                    Utils::Log("Schannel: Original certificate path [" + certPath + "] not accessible, seamlessly loaded from persistent local mirror: " + mirrorCert);
                } else {
                    Utils::LogError("Schannel: Failed to load from local mirror [" + mirrorCert + "]: " + mirrorErr);
                }
            }
        }

        // 3. 若用户设置了自定义证书但原路径和本地镜像均不可用，标记错误状态
        if (!pCert) {
            customCertLoadFailed_ = true;
            lastCertError_ = errMessage.empty() ? ("证书文件无法读取: " + certPath) : errMessage;
            Utils::LogError("Schannel: Custom certificate unavailable (" + lastCertError_ + "), temporarily falling back to self-signed certificate");
        }
    }

    if (!pCert) {
        std::string domains = Database::Instance().GetConfig("self_signed_cert_domains", "localhost,127.0.0.1,::1,ProxyRelay");
        pCert = GetOrCreateSelfSignedCert(domains, false);
        currentCertMode_ = "default";
    }

    if (!pCert) {
        Utils::LogError("Schannel: Failed to get or create certificate context");
        return false;
    }

    // 提取并记录证书信息
    currentCertExpiry_ = FileTimeToUnixTime(pCert->pCertInfo->NotAfter);
    char subjectBuf[256] = {0};
    CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectBuf, sizeof(subjectBuf));
    currentCertSubject_ = subjectBuf;

    char issuerBuf[256] = {0};
    CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuerBuf, sizeof(issuerBuf));
    currentCertIssuer_ = issuerBuf;

    // 导出公钥证书到本地 ProxyRelay.crt
    ExportCertToFile(pCert, "ProxyRelay.crt");

    SCHANNEL_CRED schannelCred = {0};
    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCred.cCreds = 1;
    schannelCred.paCred = &pCert;
    schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    schannelCred.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;

    TimeStamp tsExpiry;
    SECURITY_STATUS status = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME_A,
        SECPKG_CRED_INBOUND,
        NULL,
        &schannelCred,
        NULL,
        NULL,
        &hCreds_,
        &tsExpiry
    );

    CertFreeCertificateContext(pCert);

    if (status == SEC_E_OK) {
        credsInitialized_ = true;
        Utils::Log("Schannel: Credentials initialized successfully (Mode: " + currentCertMode_ + 
                   ", Subject: " + currentCertSubject_ + ", Expiry: " + FormatUnixTime(currentCertExpiry_) + ")");
        return true;
    } else {
        Utils::LogError("Schannel: AcquireCredentialsHandle failed with code: " + std::to_string(status));
        return false;
    }
}

void SchannelSession::FreeCredentials() {
    std::lock_guard<std::mutex> lock(credsMutex_);
    if (credsInitialized_) {
        FreeCredentialsHandle(&hCreds_);
        SecInvalidateHandle(&hCreds_);
        credsInitialized_ = false;
        Utils::Log("Schannel: Credentials freed");
    }
}

bool SchannelSession::ReloadCredentials() {
    return InitializeCredentials(true);
}

// 将 PKCS#1 RSA DER 私钥包装为标准 PKCS#8 DER
static std::vector<BYTE> WrapPkcs1RsaToPkcs8(const std::vector<BYTE>& rsaDer) {
    static const BYTE rsaAlgId[] = {
        0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x05, 0x00
    };

    auto encodeLength = [](size_t len) -> std::vector<BYTE> {
        std::vector<BYTE> res;
        if (len < 128) {
            res.push_back((BYTE)len);
        } else if (len < 256) {
            res.push_back(0x81);
            res.push_back((BYTE)len);
        } else if (len < 65536) {
            res.push_back(0x82);
            res.push_back((BYTE)(len >> 8));
            res.push_back((BYTE)(len & 0xff));
        } else {
            res.push_back(0x83);
            res.push_back((BYTE)(len >> 16));
            res.push_back((BYTE)((len >> 8) & 0xff));
            res.push_back((BYTE)(len & 0xff));
        }
        return res;
    };

    std::vector<BYTE> octetLen = encodeLength(rsaDer.size());
    std::vector<BYTE> octetString;
    octetString.push_back(0x04);
    octetString.insert(octetString.end(), octetLen.begin(), octetLen.end());
    octetString.insert(octetString.end(), rsaDer.begin(), rsaDer.end());

    static const BYTE version[] = { 0x02, 0x01, 0x00 };

    std::vector<BYTE> body;
    body.insert(body.end(), version, version + 3);
    body.insert(body.end(), rsaAlgId, rsaAlgId + sizeof(rsaAlgId));
    body.insert(body.end(), octetString.begin(), octetString.end());

    std::vector<BYTE> seqLen = encodeLength(body.size());
    std::vector<BYTE> pkcs8;
    pkcs8.push_back(0x30);
    pkcs8.insert(pkcs8.end(), seqLen.begin(), seqLen.end());
    pkcs8.insert(pkcs8.end(), body.begin(), body.end());

    return pkcs8;
}

// 解析 PEM 或 DER 证书（支持包含中间证书的多证书链 bundle）
static std::vector<PCCERT_CONTEXT> ParseCertificates(const std::string& certData) {
    std::vector<PCCERT_CONTEXT> certs;
    size_t pos = 0;
    while ((pos = certData.find("-----BEGIN CERTIFICATE-----", pos)) != std::string::npos) {
        size_t endPos = certData.find("-----END CERTIFICATE-----", pos);
        if (endPos == std::string::npos) break;
        size_t blockEnd = certData.find("-----", endPos + 9);
        if (blockEnd == std::string::npos) blockEnd = certData.size();
        else blockEnd += 5;

        std::string pemBlock = certData.substr(pos, blockEnd - pos);

        DWORD derLen = 0;
        if (CryptStringToBinaryA(pemBlock.c_str(), (DWORD)pemBlock.size(), CRYPT_STRING_ANY, NULL, &derLen, NULL, NULL)) {
            std::vector<BYTE> der(derLen);
            if (CryptStringToBinaryA(pemBlock.c_str(), (DWORD)pemBlock.size(), CRYPT_STRING_ANY, der.data(), &derLen, NULL, NULL)) {
                PCCERT_CONTEXT pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), derLen);
                if (pCert) certs.push_back(pCert);
            }
        }
        pos = blockEnd;
    }

    if (!certs.empty()) return certs;

    DWORD derLen = 0;
    if (CryptStringToBinaryA(certData.c_str(), (DWORD)certData.size(), CRYPT_STRING_ANY, NULL, &derLen, NULL, NULL)) {
        std::vector<BYTE> der(derLen);
        if (CryptStringToBinaryA(certData.c_str(), (DWORD)certData.size(), CRYPT_STRING_ANY, der.data(), &derLen, NULL, NULL)) {
            PCCERT_CONTEXT pCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), derLen);
            if (pCert) {
                certs.push_back(pCert);
                return certs;
            }
        }
    }

    PCCERT_CONTEXT pDerCert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE*)certData.data(), (DWORD)certData.size());
    if (pDerCert) certs.push_back(pDerCert);

    return certs;
}

// 解析私钥数据为 DER 字节（支持 PKCS#8、PKCS#1 RSA、SEC1 ECC）
static std::vector<BYTE> ParsePrivateKeyDer(const std::string& keyData) {
    size_t beginPos = keyData.find("-----BEGIN ");
    if (beginPos != std::string::npos) {
        size_t endHeader = keyData.find("-----", beginPos + 11);
        if (endHeader != std::string::npos) {
            size_t dataStart = endHeader + 5;
            size_t endPos = keyData.find("-----END ", dataStart);
            if (endPos != std::string::npos) {
                std::string base64Data = keyData.substr(dataStart, endPos - dataStart);
                DWORD derLen = 0;
                if (CryptStringToBinaryA(base64Data.c_str(), (DWORD)base64Data.size(), CRYPT_STRING_BASE64_ANY, NULL, &derLen, NULL, NULL)) {
                    std::vector<BYTE> der(derLen);
                    if (CryptStringToBinaryA(base64Data.c_str(), (DWORD)base64Data.size(), CRYPT_STRING_BASE64_ANY, der.data(), &derLen, NULL, NULL)) {
                        return der;
                    }
                }
            }
        }
    }

    DWORD derLen = 0;
    if (CryptStringToBinaryA(keyData.c_str(), (DWORD)keyData.size(), CRYPT_STRING_ANY, NULL, &derLen, NULL, NULL)) {
        std::vector<BYTE> der(derLen);
        if (CryptStringToBinaryA(keyData.c_str(), (DWORD)keyData.size(), CRYPT_STRING_ANY, der.data(), &derLen, NULL, NULL)) {
            return der;
        }
    }

    return std::vector<BYTE>(keyData.begin(), keyData.end());
}

PCCERT_CONTEXT SchannelSession::LoadCustomCertContext(const std::string& certPath, const std::string& keyPath, std::string& errMessage) {
    if (certPath.empty()) {
        errMessage = "证书路径不能为空";
        return nullptr;
    }

    // 1. 读取证书文件
    std::ifstream certFile(std::filesystem::u8path(certPath), std::ios::binary);
    if (!certFile.is_open()) {
        errMessage = "无法读取证书文件: " + certPath;
        return nullptr;
    }
    std::string certContent((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
    certFile.close();

    if (certContent.empty()) {
        errMessage = "证书文件内容为空: " + certPath;
        return nullptr;
    }

    // 检查是否为 PFX / PKCS#12 格式
    bool isPfx = false;
    if (certPath.size() >= 4) {
        std::string ext = certPath.substr(certPath.size() - 4);
        for (char& c : ext) c = (char)tolower(c);
        if (ext == ".pfx" || ext == ".p12") isPfx = true;
    }
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)certContent.size();
    pfxBlob.pbData = (BYTE*)certContent.data();
    if (!isPfx && PFXIsPFXBlob(&pfxBlob)) {
        isPfx = true;
    }

    if (isPfx) {
        std::wstring wPass = Utils::StringToWString(keyPath);
        HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, wPass.c_str(), CRYPT_EXPORTABLE | PKCS12_ALWAYS_CNG_KSP);
        if (!hPfxStore) {
            errMessage = "PFX 证书包导入失败 (密码错误或文件损坏)，错误码: " + std::to_string(GetLastError());
            return nullptr;
        }

        PCCERT_CONTEXT pCert = NULL;
        PCCERT_CONTEXT pFoundCert = NULL;
        while ((pCert = CertEnumCertificatesInStore(hPfxStore, pCert)) != NULL) {
            DWORD dwSize = 0;
            if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize) ||
                CertGetCertificateContextProperty(pCert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, NULL, &dwSize)) {
                pFoundCert = CertDuplicateCertificateContext(pCert);
                break;
            }
        }
        CertCloseStore(hPfxStore, 0);

        if (!pFoundCert) {
            errMessage = "PFX 证书包中未找到有效的私钥";
            return nullptr;
        }

        HCERTSTORE hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, "MY");
        PCCERT_CONTEXT pStoreCert = NULL;
        if (hMyStore) {
            CertAddCertificateContextToStore(hMyStore, pFoundCert, CERT_STORE_ADD_REPLACE_EXISTING, &pStoreCert);
            CertCloseStore(hMyStore, 0);
        }
        CertFreeCertificateContext(pFoundCert);
        return pStoreCert;
    }

    // 2. PEM / DER 证书解析
    std::vector<PCCERT_CONTEXT> certs = ParseCertificates(certContent);
    if (certs.empty()) {
        errMessage = "无法解析证书数据 (PEM/DER 格式无效)";
        return nullptr;
    }
    PCCERT_CONTEXT pLeafCert = certs[0];

    // 将链上的中间证书加入当前用户的 CA 存储区，以便 Schannel 自动组装完整证书链
    if (certs.size() > 1) {
        HCERTSTORE hCaStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, "CA");
        if (hCaStore) {
            for (size_t i = 1; i < certs.size(); ++i) {
                CertAddCertificateContextToStore(hCaStore, certs[i], CERT_STORE_ADD_REPLACE_EXISTING, NULL);
                CertFreeCertificateContext(certs[i]);
            }
            CertCloseStore(hCaStore, 0);
        }
    }

    // 3. 读取私钥文件
    if (keyPath.empty()) {
        CertFreeCertificateContext(pLeafCert);
        errMessage = "PEM 模式下私钥文件路径不能为空";
        return nullptr;
    }

    std::ifstream keyFile(std::filesystem::u8path(keyPath), std::ios::binary);
    if (!keyFile.is_open()) {
        CertFreeCertificateContext(pLeafCert);
        errMessage = "无法读取私钥文件: " + keyPath;
        return nullptr;
    }
    std::string keyContent((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());
    keyFile.close();

    if (keyContent.empty()) {
        CertFreeCertificateContext(pLeafCert);
        errMessage = "私钥文件内容为空: " + keyPath;
        return nullptr;
    }

    std::vector<BYTE> keyDer = ParsePrivateKeyDer(keyContent);
    if (keyDer.empty()) {
        CertFreeCertificateContext(pLeafCert);
        errMessage = "私钥文件格式无效";
        return nullptr;
    }

    // 4. 导入私钥到 CryptoAPI CSP 或 CNG KSP
    bool keyImported = false;
    CRYPT_KEY_PROV_INFO provInfo = {0};
    std::wstring containerName = L"ProxyRelay_CustomCert_Key";

    // 4.1 优先尝试通过 CryptoAPI (PROV_RSA_AES) 导入 RSA 私钥 (PKCS#1 RSA)
    DWORD dwBlobLen = 0;
    BYTE* pBlob = nullptr;
    if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, keyDer.data(), (DWORD)keyDer.size(), CRYPT_DECODE_ALLOC_FLAG, NULL, &pBlob, &dwBlobLen)) {
        HCRYPTPROV hCryptProv = 0;
        LPCSTR szContainer = "ProxyRelay_CustomCert_Key";
        if (!CryptAcquireContextA(&hCryptProv, szContainer, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
            if (GetLastError() == (DWORD)NTE_EXISTS) {
                CryptAcquireContextA(&hCryptProv, szContainer, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_DELETEKEYSET | CRYPT_SILENT);
                CryptAcquireContextA(&hCryptProv, szContainer, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT);
            }
        }

        if (hCryptProv) {
            HCRYPTKEY hCKey = 0;
            if (CryptImportKey(hCryptProv, pBlob, dwBlobLen, 0, CRYPT_EXPORTABLE, &hCKey)) {
                CryptDestroyKey(hCKey);
                keyImported = true;

                provInfo.pwszContainerName = (LPWSTR)containerName.c_str();
                provInfo.pwszProvName = (LPWSTR)MS_ENH_RSA_AES_PROV_W;
                provInfo.dwProvType = PROV_RSA_AES;
                provInfo.dwFlags = 0;
                provInfo.dwKeySpec = AT_KEYEXCHANGE;
            }
            CryptReleaseContext(hCryptProv, 0);
        }
        LocalFree(pBlob);
    }

    // 4.2 若非 PKCS#1 RSA 或 CryptoAPI 失败，尝试 CNG (PKCS#8 RSA / ECC)
    if (!keyImported) {
        NCRYPT_PROV_HANDLE hProv = 0;
        if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
            NCRYPT_KEY_HANDLE hKey = 0;
            SECURITY_STATUS ss = NCryptImportKey(hProv, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hKey, keyDer.data(), (DWORD)keyDer.size(), NCRYPT_SILENT_FLAG);
            if (ss != ERROR_SUCCESS) {
                // 尝试将 PKCS#1 转换为 PKCS#8 后导入
                std::vector<BYTE> pkcs8 = WrapPkcs1RsaToPkcs8(keyDer);
                ss = NCryptImportKey(hProv, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hKey, pkcs8.data(), (DWORD)pkcs8.size(), NCRYPT_SILENT_FLAG);
            }
            if (ss == ERROR_SUCCESS) {
                CertSetCertificateContextProperty(pLeafCert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, (const void*)hKey);
                keyImported = true;
            }
            NCryptFreeObject(hProv);
        }
    }

    if (!keyImported) {
        CertFreeCertificateContext(pLeafCert);
        errMessage = "导入私钥失败 (请确认证书与私钥格式是否匹配)";
        return nullptr;
    }

    // 将密钥提供程序信息绑定至证书
    if (provInfo.pwszContainerName) {
        CertSetCertificateContextProperty(pLeafCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &provInfo);
    }

    // 将证书添加到当前用户的 MY 存储中
    HCERTSTORE hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, "MY");
    PCCERT_CONTEXT pStoreCert = NULL;
    if (hMyStore) {
        CertAddCertificateContextToStore(hMyStore, pLeafCert, CERT_STORE_ADD_REPLACE_EXISTING, &pStoreCert);
        CertCloseStore(hMyStore, 0);
    }
    CertFreeCertificateContext(pLeafCert);

    if (!pStoreCert) {
        errMessage = "将证书加入 MY 存储区失败";
        return nullptr;
    }

    // 5. 校验 Schannel 凭据可用性
    SCHANNEL_CRED schannelCred = {0};
    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCred.cCreds = 1;
    schannelCred.paCred = &pStoreCert;
    schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    schannelCred.dwFlags = 0;

    CredHandle testCreds;
    TimeStamp tsExpiry;
    SECURITY_STATUS testStatus = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME_A,
        SECPKG_CRED_INBOUND,
        NULL,
        &schannelCred,
        NULL,
        NULL,
        &testCreds,
        &tsExpiry
    );

    if (testStatus != SEC_E_OK) {
        CertFreeCertificateContext(pStoreCert);
        errMessage = "Schannel 凭据测试失败，错误码: 0x" + std::to_string(testStatus);
        return nullptr;
    }

    FreeCredentialsHandle(&testCreds);
    return pStoreCert;
}

bool SchannelSession::LoadCertAndKeyFromFiles(const std::string& certPath, const std::string& keyPath, std::string& errMessage) {
    if (certPath.empty()) {
        errMessage = "证书文件路径不能为空";
        return false;
    }
    if (keyPath.empty()) {
        errMessage = "私钥文件路径不能为空";
        return false;
    }

    std::string resolvedCert = ResolveExistingFilePath(certPath);
    std::string resolvedKey = ResolveExistingFilePath(keyPath);
    std::string effectiveCert = resolvedCert.empty() ? certPath : resolvedCert;
    std::string effectiveKey = resolvedKey.empty() ? keyPath : resolvedKey;

    PCCERT_CONTEXT pCert = LoadCustomCertContext(effectiveCert, effectiveKey, errMessage);
    if (!pCert) {
        return false;
    }
    CertFreeCertificateContext(pCert);

    // 校验成功，保存到数据库
    Database::Instance().SetConfig("https_cert_file", effectiveCert);
    Database::Instance().SetConfig("https_key_file", effectiveKey);
    Database::Instance().SetConfig("https_cert_mode", "custom");

    // 持久化保存至本地可靠镜像
    SaveCertMirror(effectiveCert, effectiveKey, false);

    // 重新加载全局凭据
    return ReloadCredentials();
}

bool SchannelSession::LoadPfxFromFile(const std::string& pfxPath, const std::string& password, std::string& errMessage) {
    if (pfxPath.empty()) {
        errMessage = "PFX 文件路径不能为空";
        return false;
    }

    std::string resolvedPfx = ResolveExistingFilePath(pfxPath);
    std::string effectivePfx = resolvedPfx.empty() ? pfxPath : resolvedPfx;

    PCCERT_CONTEXT pCert = LoadCustomCertContext(effectivePfx, password, errMessage);
    if (!pCert) {
        return false;
    }
    CertFreeCertificateContext(pCert);

    Database::Instance().SetConfig("https_cert_file", effectivePfx);
    Database::Instance().SetConfig("https_key_file", password);
    Database::Instance().SetConfig("https_cert_mode", "custom");

    // 持久化保存至本地可靠镜像
    SaveCertMirror(effectivePfx, password, true);

    return ReloadCredentials();
}

bool SchannelSession::CheckAndUpdateCertIfExpiring() {
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastExpiryCheckTime_).count() < 60) {
        return false;
    }
    lastExpiryCheckTime_ = now;

    std::string certPath = Database::Instance().GetConfig("https_cert_file", "");
    std::string keyPath = Database::Instance().GetConfig("https_key_file", "");
    std::string certMode = Database::Instance().GetConfig("https_cert_mode", "default");

    if (certMode != "custom" || certPath.empty()) {
        return false;
    }

    std::string resolvedCert = ResolveExistingFilePath(certPath);
    if (resolvedCert.empty()) {
        resolvedCert = GetLocalMirrorCertPath(false);
        if (!std::filesystem::exists(std::filesystem::u8path(resolvedCert))) {
            resolvedCert = GetLocalMirrorCertPath(true);
        }
    }
    if (resolvedCert.empty() || !std::filesystem::exists(std::filesystem::u8path(resolvedCert))) {
        return false;
    }

    int64_t currentUnixTime = (int64_t)time(nullptr);
    int64_t remainingSeconds = currentCertExpiry_ - currentUnixTime;

    // 当自定义证书可用时间不足 7 天 (7 * 86400 秒 = 604800 秒) 或已过期时：
    // 每 24 小时 (86400 秒) 自动重新加载一次证书（或在检测到磁盘证书更新时立刻重新加载）
    if (remainingSeconds < 7 * 86400) {
        int64_t diskCertExpiry = 0;
        std::string subject, issuer;
        bool hasNewerCert = false;
        if (ParseCertFileExpiry(resolvedCert, diskCertExpiry, subject, issuer)) {
            if (diskCertExpiry > currentCertExpiry_) {
                hasNewerCert = true;
            }
        }

        int64_t secondsSinceLastReload = (lastAutoReloadUnixTime_ > 0) ? (currentUnixTime - lastAutoReloadUnixTime_) : 86400;
        bool needPeriodicReload = (secondsSinceLastReload >= 86400);

        if (hasNewerCert || needPeriodicReload) {
            Utils::Log("Schannel: Custom certificate remaining time < 7 days (" + 
                       std::to_string(remainingSeconds > 0 ? (remainingSeconds / 86400) : 0) + " days left). " +
                       (hasNewerCert ? "Detected newer certificate on disk. " : "24h reload interval reached. ") +
                       "Auto reloading custom certificate from " + resolvedCert + "...");

            lastAutoReloadUnixTime_ = currentUnixTime;
            if (ReloadCredentials()) {
                Utils::Log("Schannel: Custom certificate auto-reloaded successfully! New expiry: " + FormatUnixTime(currentCertExpiry_));
                return true;
            } else {
                Utils::LogError("Schannel: Custom certificate auto-reload failed");
            }
        }
    }
    return false;
}

bool SchannelSession::ResetToDefaultCert() {
    Database::Instance().SetConfig("https_cert_file", "");
    Database::Instance().SetConfig("https_key_file", "");
    Database::Instance().SetConfig("https_cert_mode", "default");
    try {
        std::filesystem::remove(std::filesystem::u8path(GetLocalMirrorCertPath(false)));
        std::filesystem::remove(std::filesystem::u8path(GetLocalMirrorCertPath(true)));
        std::filesystem::remove(std::filesystem::u8path(GetLocalMirrorKeyPath()));
    } catch (...) {}
    return ReloadCredentials();
}

bool SchannelSession::ExportCurrentCert(const std::string& exportPath) {
    std::ifstream src(std::filesystem::u8path("ProxyRelay.crt"), std::ios::binary);
    std::ofstream dst(std::filesystem::u8path(exportPath), std::ios::binary);
    if (src.is_open() && dst.is_open()) {
        dst << src.rdbuf();
        return true;
    }
    return false;
}

std::string SchannelSession::GetCertStatusInfo() {
    if (!credsInitialized_) {
        InitializeCredentials();
    }
    std::string certModeConfig = Database::Instance().GetConfig("https_cert_mode", "default");
    int64_t now = (int64_t)time(nullptr);
    int64_t remainingSec = currentCertExpiry_ - now;
    std::string expiryStr = (currentCertExpiry_ > 0) ? FormatUnixTime(currentCertExpiry_) : "未知";

    if (currentCertMode_ == "custom") {
        std::string remainText;
        if (remainingSec > 7 * 86400) {
            remainText = "剩余 " + std::to_string(remainingSec / 86400) + " 天";
        } else if (remainingSec > 86400) {
            remainText = "剩余 " + std::to_string(remainingSec / 86400) + " 天 (不足7天，已开启每24小时自动重载)";
        } else if (remainingSec > 0) {
            remainText = "剩余 " + std::to_string(remainingSec / 3600) + " 小时 (不足7天，已开启每24小时自动重载)";
        } else {
            remainText = "已过期 (不足7天，已开启每24小时自动重载)";
        }
        std::string mirrorTag = isLoadedFromMirror_ ? " [本地镜像备用]" : "";
        return "自定义证书: " + (currentCertSubject_.empty() ? "SSL/TLS Server" : currentCertSubject_) +
               mirrorTag + " (有效期至: " + expiryStr + ", " + remainText + ")";
    } else if (certModeConfig == "custom" && customCertLoadFailed_) {
        std::string daysStr = (remainingSec > 0) ? ("剩余 " + std::to_string(remainingSec / 86400) + " 天") : "已过期";
        return "自定义证书加载失败: " + lastCertError_ + " (临时使用自签名证书保底: " + expiryStr + ", " + daysStr + ")";
    } else {
        std::string daysStr = (remainingSec > 0) ? ("剩余 " + std::to_string(remainingSec / 86400) + " 天") : "已过期";
        return "内置自签名证书 (有效期至: " + expiryStr + ", " + daysStr + ")";
    }
}

int64_t SchannelSession::GetCurrentCertExpiry() {
    return currentCertExpiry_;
}

bool SchannelSession::ParseCertFileExpiry(const std::string& certPath, int64_t& outExpiry, std::string& outSubject, std::string& outIssuer) {
    std::string resolved = ResolveExistingFilePath(certPath);
    std::string path = resolved.empty() ? certPath : resolved;
    std::ifstream certFile(std::filesystem::u8path(path), std::ios::binary);
    if (!certFile.is_open()) return false;
    std::string certContent((std::istreambuf_iterator<char>(certFile)), std::istreambuf_iterator<char>());
    certFile.close();

    if (certContent.empty()) return false;

    // 尝试作为 PFX 文件
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.cbData = (DWORD)certContent.size();
    pfxBlob.pbData = (BYTE*)certContent.data();
    if (PFXIsPFXBlob(&pfxBlob)) {
        HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE | PKCS12_ALWAYS_CNG_KSP);
        if (hPfxStore) {
            PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hPfxStore, NULL);
            if (pCert) {
                outExpiry = FileTimeToUnixTime(pCert->pCertInfo->NotAfter);
                char subjectBuf[256] = {0};
                CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectBuf, sizeof(subjectBuf));
                outSubject = subjectBuf;
                char issuerBuf[256] = {0};
                CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuerBuf, sizeof(issuerBuf));
                outIssuer = issuerBuf;
                CertFreeCertificateContext(pCert);
                CertCloseStore(hPfxStore, 0);
                return true;
            }
            CertCloseStore(hPfxStore, 0);
        }
    }

    // 尝试作为 PEM / DER 证书
    std::vector<PCCERT_CONTEXT> certs = ParseCertificates(certContent);
    if (certs.empty()) return false;

    PCCERT_CONTEXT pCert = certs[0];
    outExpiry = FileTimeToUnixTime(pCert->pCertInfo->NotAfter);

    char subjectBuf[256] = {0};
    CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectBuf, sizeof(subjectBuf));
    outSubject = subjectBuf;

    char issuerBuf[256] = {0};
    CertGetNameStringA(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuerBuf, sizeof(issuerBuf));
    outIssuer = issuerBuf;

    for (PCCERT_CONTEXT c : certs) {
        CertFreeCertificateContext(c);
    }
    return true;
}

static std::string BuildDnsNamesParam(const std::string& domainsStr) {
    std::vector<std::string> domains;
    std::stringstream ss(domainsStr);
    std::string item;
    while (std::getline(ss, item, ',')) {
        size_t start = item.find_first_not_of(" \t\r\n;");
        size_t end = item.find_last_not_of(" \t\r\n;");
        if (start != std::string::npos && end != std::string::npos) {
            std::string d = item.substr(start, end - start + 1);
            if (!d.empty()) {
                std::string escaped;
                for (char c : d) {
                    if (c == '\'') escaped += "''";
                    else escaped += c;
                }
                domains.push_back(escaped);
            }
        }
    }

    if (domains.empty()) {
        domains.push_back("localhost");
        domains.push_back("127.0.0.1");
        domains.push_back("::1");
        domains.push_back("ProxyRelay");
    }

    std::string result;
    for (size_t i = 0; i < domains.size(); i++) {
        if (i > 0) result += ",";
        result += "'" + domains[i] + "'";
    }
    return result;
}

bool SchannelSession::GenerateSelfSignedCert(const std::string& customDomains, std::string& errMessage) {
    std::string domains = customDomains;
    if (domains.empty()) {
        domains = Database::Instance().GetConfig("self_signed_cert_domains", "localhost,127.0.0.1,::1,ProxyRelay");
    }
    Database::Instance().SetConfig("self_signed_cert_domains", domains);
    Database::Instance().SetConfig("https_cert_mode", "default");
    Database::Instance().SetConfig("https_cert_file", "");
    Database::Instance().SetConfig("https_key_file", "");

    PCCERT_CONTEXT pCert = GetOrCreateSelfSignedCert(domains, true);
    if (!pCert) {
        errMessage = "生成自签名证书失败 (PowerShell 执行异常)";
        return false;
    }
    CertFreeCertificateContext(pCert);

    return ReloadCredentials();
}

PCCERT_CONTEXT SchannelSession::GetOrCreateSelfSignedCert(const std::string& customDomains, bool forceRecreate) {
    std::string domains = customDomains;
    if (domains.empty()) {
        domains = Database::Instance().GetConfig("self_signed_cert_domains", "localhost,127.0.0.1,::1,ProxyRelay");
    }
    std::string lastDomains = Database::Instance().GetConfig("last_generated_self_signed_domains", "");
    if (!forceRecreate && !lastDomains.empty() && lastDomains != domains) {
        forceRecreate = true;
    }

    HCERTSTORE hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        "MY"
    );
    if (!hStore) {
        Utils::LogError("Schannel: Failed to open MY certificate store");
        return NULL;
    }

    // 如果强制重新生成，则删除旧自签名证书
    if (forceRecreate) {
        PCCERT_CONTEXT pOld = NULL;
        while ((pOld = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR_A,
            "ProxyRelay HTTPS",
            pOld
        )) != NULL) {
            PCCERT_CONTEXT pDel = CertDuplicateCertificateContext(pOld);
            CertDeleteCertificateFromStore(pDel);
            pOld = NULL;
        }
    } else {
        // 查找已有的有效证书
        PCCERT_CONTEXT pCert = NULL;
        while (true) {
            pCert = CertFindCertificateInStore(
                hStore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SUBJECT_STR_A,
                "ProxyRelay HTTPS",
                pCert
            );
            if (!pCert) break;

            DWORD dwSize = 0;
            if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize) ||
                CertGetCertificateContextProperty(pCert, CERT_NCRYPT_KEY_HANDLE_PROP_ID, NULL, &dwSize)) {
                PCCERT_CONTEXT pGoodCert = CertDuplicateCertificateContext(pCert);
                CertFreeCertificateContext(pCert);
                CertCloseStore(hStore, 0);
                Utils::Log("Schannel: Found existing valid self-signed certificate");
                return pGoodCert;
            } else {
                Utils::Log("Schannel: Found broken certificate without private key, deleting...");
                PCCERT_CONTEXT pCertToDelete = CertDuplicateCertificateContext(pCert);
                CertDeleteCertificateFromStore(pCertToDelete);
                pCert = NULL;
            }
        }
    }
    CertCloseStore(hStore, 0);

    // 构建 DnsName 参数
    std::string dnsParam = BuildDnsNamesParam(domains);
    Utils::Log("Schannel: Creating self-signed certificate with domains: " + dnsParam + " via PowerShell...");

    std::string psCmd = "powershell -NoProfile -NonInteractive -Command \""
        "$cert = New-SelfSignedCertificate -DnsName " + dnsParam + " -CertStoreLocation 'Cert:\\CurrentUser\\My' "
        "-Subject 'CN=ProxyRelay HTTPS Proxy v2' -KeyAlgorithm RSA -KeyLength 2048 "
        "-KeyUsage DigitalSignature,KeyEncipherment -Type SSLServerAuthentication "
        "-NotAfter (Get-Date).AddYears(10); "
        "if ($cert) { "
        "  Export-Certificate -Cert $cert -FilePath 'ProxyRelay.crt' | Out-Null; "
        "  Write-Output 'OK'; "
        "} else { Write-Output 'FAIL'; }\"";

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, (LPSTR)psCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        Utils::LogError("Schannel: Failed to launch PowerShell, error=" + std::to_string(GetLastError()));
        return NULL;
    }

    // 记录最新生成的域名配置
    Database::Instance().SetConfig("last_generated_self_signed_domains", domains);

    hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_A,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        "MY"
    );
    if (!hStore) {
        Utils::LogError("Schannel: Failed to reopen MY certificate store");
        return NULL;
    }

    PCCERT_CONTEXT pCert = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_A,
        "ProxyRelay HTTPS",
        NULL
    );

    if (pCert) {
        Utils::Log("Schannel: Self-signed certificate created successfully via PowerShell with custom domains");
    } else {
        Utils::LogError("Schannel: PowerShell certificate creation failed - certificate not found in store");
    }

    CertCloseStore(hStore, 0);
    return pCert;
}

bool SchannelSession::Handshake(SOCKET sock) {
    if (!credsInitialized_) {
        if (!InitializeCredentials()) return false;
    }

    SecBufferDesc outBufferDesc, inBufferDesc;
    SecBuffer outBuffers[1], inBuffers[2];
    DWORD dwSSPIFlags, dwSSPIOutFlags;
    TimeStamp tsExpiry;
    SECURITY_STATUS scRet;

    dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                  ASC_REQ_REPLAY_DETECT |
                  ASC_REQ_CONFIDENTIALITY |
                  ASC_REQ_EXTENDED_ERROR |
                  ASC_REQ_ALLOCATE_MEMORY |
                  ASC_REQ_STREAM;

    inBuf_.resize(4096);
    int totalReceived = 0;
    bool firstCall = true;

    while (true) {
        if (firstCall || scRet == SEC_E_INCOMPLETE_MESSAGE) {
            int received = recv(sock, inBuf_.data() + totalReceived, (int)inBuf_.size() - totalReceived, 0);
            if (received <= 0) {
                return false;
            }
            totalReceived += received;
            if (totalReceived == inBuf_.size()) {
                inBuf_.resize(inBuf_.size() * 2);
            }
        }

        inBuffers[0].pvBuffer = inBuf_.data();
        inBuffers[0].cbBuffer = totalReceived;
        inBuffers[0].BufferType = SECBUFFER_TOKEN;

        inBuffers[1].pvBuffer = NULL;
        inBuffers[1].cbBuffer = 0;
        inBuffers[1].BufferType = SECBUFFER_EMPTY;

        inBufferDesc.cBuffers = 2;
        inBufferDesc.pBuffers = inBuffers;
        inBufferDesc.ulVersion = SECBUFFER_VERSION;

        outBuffers[0].pvBuffer = NULL;
        outBuffers[0].cbBuffer = 0;
        outBuffers[0].BufferType = SECBUFFER_TOKEN;

        outBufferDesc.cBuffers = 1;
        outBufferDesc.pBuffers = outBuffers;
        outBufferDesc.ulVersion = SECBUFFER_VERSION;

        scRet = AcceptSecurityContext(
            &hCreds_,
            contextValid_ ? &hContext_ : NULL,
            &inBufferDesc,
            dwSSPIFlags,
            SECURITY_NATIVE_DREP,
            &hContext_,
            &outBufferDesc,
            &dwSSPIOutFlags,
            &tsExpiry
        );

        if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ||
            (FAILED(scRet) && (dwSSPIOutFlags & ASC_RET_EXTENDED_ERROR))) {
            contextValid_ = true;
        }

        if (outBuffers[0].cbBuffer != 0 && outBuffers[0].pvBuffer != NULL) {
            int sent = send(sock, (const char*)outBuffers[0].pvBuffer, outBuffers[0].cbBuffer, 0);
            FreeContextBuffer(outBuffers[0].pvBuffer);
            if (sent <= 0) {
                return false;
            }
        }

        if (scRet == SEC_E_INCOMPLETE_MESSAGE) {
            firstCall = false;
            continue;
        }

        if (scRet == SEC_E_OK) {
            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                size_t extraLen = inBuffers[1].cbBuffer;
                size_t usedLen = totalReceived - extraLen;
                std::vector<char> remaining(inBuf_.begin() + usedLen, inBuf_.begin() + totalReceived);
                inBuf_ = std::move(remaining);
            } else {
                inBuf_.clear();
            }
            return true;
        }

        if (scRet == SEC_I_CONTINUE_NEEDED) {
            if (inBuffers[1].BufferType == SECBUFFER_EXTRA && inBuffers[1].cbBuffer > 0) {
                size_t extraLen = inBuffers[1].cbBuffer;
                size_t usedLen = totalReceived - extraLen;
                std::memmove(inBuf_.data(), inBuf_.data() + usedLen, extraLen);
                totalReceived = (int)extraLen;
            } else {
                totalReceived = 0;
            }
            firstCall = false;
            continue;
        }

        Utils::LogError("Schannel: AcceptSecurityContext failed, error=" + std::to_string(scRet));
        return false;
    }
}

int SchannelSession::Write(SOCKET sock, const char* buf, int len) {
    if (!contextValid_) return -1;

    SecPkgContext_StreamSizes sizes;
    SECURITY_STATUS status = QueryContextAttributes(&hContext_, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (status != SEC_E_OK) return -1;

    int totalSent = 0;
    while (totalSent < len) {
        int chunkLen = (std::min)((int)sizes.cbMaximumMessage, len - totalSent);
        std::vector<char> messageBuf(sizes.cbHeader + chunkLen + sizes.cbTrailer);

        SecBuffer buffers[4];
        buffers[0].pvBuffer = messageBuf.data();
        buffers[0].cbBuffer = sizes.cbHeader;
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

        buffers[1].pvBuffer = messageBuf.data() + sizes.cbHeader;
        buffers[1].cbBuffer = chunkLen;
        buffers[1].BufferType = SECBUFFER_DATA;
        std::memcpy(buffers[1].pvBuffer, buf + totalSent, chunkLen);

        buffers[2].pvBuffer = messageBuf.data() + sizes.cbHeader + chunkLen;
        buffers[2].cbBuffer = sizes.cbTrailer;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

        buffers[3].pvBuffer = NULL;
        buffers[3].cbBuffer = 0;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        status = EncryptMessage(&hContext_, 0, &desc, 0);
        if (status != SEC_E_OK) {
            Utils::LogError("Schannel: EncryptMessage failed, error=" + std::to_string(status));
            return -1;
        }

        int toSend = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent < toSend) {
            int n = send(sock, messageBuf.data() + sent, toSend - sent, 0);
            if (n <= 0) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    Sleep(5);
                    continue;
                }
                return -1;
            }
            sent += n;
        }
        totalSent += chunkLen;
    }
    return totalSent;
}

int SchannelSession::Read(SOCKET sock, char* buf, int len) {
    if (!contextValid_) return -1;

    while (outBuf_.empty()) {
        if (inBuf_.empty() || needMoreData_) {
            char temp[4096];
            int received = recv(sock, temp, sizeof(temp), 0);
            if (received <= 0) {
                int err = WSAGetLastError();
                if (received == SOCKET_ERROR && err == WSAEWOULDBLOCK) {
                    return -2;
                }
                return received;
            }
            inBuf_.insert(inBuf_.end(), temp, temp + received);
            needMoreData_ = false;
        }

        SecPkgContext_StreamSizes sizes;
        SECURITY_STATUS status = QueryContextAttributes(&hContext_, SECPKG_ATTR_STREAM_SIZES, &sizes);
        if (status != SEC_E_OK) return -1;

        SecBuffer buffers[4];
        buffers[0].pvBuffer = inBuf_.data();
        buffers[0].cbBuffer = (DWORD)inBuf_.size();
        buffers[0].BufferType = SECBUFFER_DATA;

        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        status = DecryptMessage(&hContext_, &desc, 0, NULL);

        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            needMoreData_ = true;
            char temp[4096];
            int received = recv(sock, temp, sizeof(temp), 0);
            if (received <= 0) {
                int err = WSAGetLastError();
                if (received == SOCKET_ERROR && err == WSAEWOULDBLOCK) {
                    return -2;
                }
                return received;
            }
            inBuf_.insert(inBuf_.end(), temp, temp + received);
            needMoreData_ = false;
            continue;
        }

        if (status == SEC_I_CONTEXT_EXPIRED) {
            return 0;
        }

        if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE) {
            Utils::LogError("Schannel: DecryptMessage failed, error=" + std::to_string(status));
            return -1;
        }

        SecBuffer* pDataBuffer = NULL;
        SecBuffer* pExtraBuffer = NULL;
        for (int i = 0; i < 4; i++) {
            if (!pDataBuffer && buffers[i].BufferType == SECBUFFER_DATA) {
                pDataBuffer = &buffers[i];
            }
            if (!pExtraBuffer && buffers[i].BufferType == SECBUFFER_EXTRA) {
                pExtraBuffer = &buffers[i];
            }
        }

        if (pDataBuffer && pDataBuffer->cbBuffer > 0) {
            const char* decryptedData = (const char*)pDataBuffer->pvBuffer;
            outBuf_.insert(outBuf_.end(), decryptedData, decryptedData + pDataBuffer->cbBuffer);
        }

        if (pExtraBuffer && pExtraBuffer->cbBuffer > 0) {
            size_t extraLen = pExtraBuffer->cbBuffer;
            size_t usedLen = inBuf_.size() - extraLen;
            std::vector<char> remaining(inBuf_.begin() + usedLen, inBuf_.end());
            inBuf_ = std::move(remaining);
        } else {
            inBuf_.clear();
        }
    }

    int toCopy = (std::min)((int)outBuf_.size(), len);
    std::memcpy(buf, outBuf_.data(), toCopy);
    outBuf_.erase(outBuf_.begin(), outBuf_.begin() + toCopy);
    return toCopy;
}
