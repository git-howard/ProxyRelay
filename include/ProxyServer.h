#pragma once

#include "Database.h"
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <map>
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>

class ProxyServer {
public:
    static ProxyServer& Instance();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }
    
    // 重新加载配置
    void ReloadPorts();
    
    // 获取状态
    int GetActiveConnections() const { return activeConnections_.load(); }
    std::vector<int> GetListeningPorts() const;
    
    // 自动代理监听
    void StartAutoProxyListener();
    void StopAutoProxyListener();
    
    // 健康检查
    void StartProxyChecker();
    void StopProxyChecker();
    bool IsProxyAvailable(int portId);
    
private:
    ProxyServer() = default;
    ~ProxyServer();
    
    void ListenerThread(ProxyPort port);
    void HandleClient(SOCKET clientSocket, const std::string& clientAddr, ProxyPort port);
    
    void CheckerThread();
    bool CheckProxyConnectivity(const ProxyPort& port, const std::vector<std::string>& targets);
    
    // HTTP代理处理
    void HandleHttpProxy(SOCKET clientSocket, const std::string& clientAddr, 
                         const ProxyPort& port, int userId, const std::string& username,
                         const std::string& initialRequest);
                         
    // SOCKS5代理处理
    void HandleSocks5Proxy(SOCKET clientSocket, const std::string& clientAddr,
                           const ProxyPort& port, int userId, const std::string& username,
                           const std::string& initialData);
    
    // 连接上游代理
    SOCKET ConnectToUpstream(const ProxyPort& port);
    SOCKET ConnectToSocks5(const ProxyPort& port, const std::string& targetHost, int targetPort);
    SOCKET ConnectToHttpProxy(const ProxyPort& port, const std::string& targetHost, int targetPort);
    
    // 数据转发
    void RelayData(SOCKET client, SOCKET upstream, int userId, int portId);
    
    // 带缓冲区的数据转发（非阻塞模式）
    void RelayDataBuffered(SOCKET client, SOCKET upstream, int userId, int portId);
    
    // 获取缓冲区大小配置（单位KB）
    int GetBufferSizeKB();
    
    // 环形缓冲区结构
    struct RingBuffer {
        std::vector<char> data;
        size_t readPos = 0;
        size_t writePos = 0;
        size_t capacity = 0;
        
        void init(size_t cap) {
            data.resize(cap);
            capacity = cap;
            readPos = writePos = 0;
        }
        
        size_t available() const {
            return (writePos - readPos + capacity) % capacity;
        }
        
        size_t freeSpace() const {
            return capacity - available() - 1;  // 留一个字节区分满和空
        }
        
        bool isEmpty() const { return readPos == writePos; }
        bool isFull() const { return freeSpace() == 0; }
        
        // 写入数据，返回实际写入的字节数
        size_t write(const char* buf, size_t len) {
            size_t free = freeSpace();
            if (free == 0) return 0;
            size_t toWrite = (len < free) ? len : free;
            
            for (size_t i = 0; i < toWrite; i++) {
                data[writePos] = buf[i];
                writePos = (writePos + 1) % capacity;
            }
            return toWrite;
        }
        
        // 读取数据，返回实际读取的字节数
        size_t read(char* buf, size_t maxLen) {
            size_t avail = available();
            if (avail == 0) return 0;
            size_t toRead = (maxLen < avail) ? maxLen : avail;
            
            for (size_t i = 0; i < toRead; i++) {
                buf[i] = data[readPos];
                readPos = (readPos + 1) % capacity;
            }
            return toRead;
        }
        
        // 查看可读数据指针（不移动读指针）
        const char* peekData() const { return &data[readPos]; }
        
        // 获取连续可读长度（到缓冲区末尾或写指针）
        size_t contiguousReadLen() const {
            if (writePos >= readPos) return writePos - readPos;
            return capacity - readPos;
        }
        
        // 消费已读数据
        void consume(size_t len) {
            readPos = (readPos + len) % capacity;
        }
    };
    
    std::atomic<bool> running_{false};
    std::atomic<int> activeConnections_{0};
    
    std::mutex portsMutex_;
    std::map<int, std::thread> listenerThreads_;
    std::map<int, SOCKET> listenSockets_;
    
    std::thread autoProxyThread_;
    SOCKET autoProxySocket_ = INVALID_SOCKET;
    
    // 健康检查状态
    struct ProxyStatus {
        bool isAvailable = true;
        int failCount = 0;
        std::chrono::steady_clock::time_point nextCheckTime;
    };
    std::map<int, ProxyStatus> proxyStatus_;
    std::mutex statusMutex_;
    std::thread checkerThread_;
    
    bool wsaInitialized_ = false;
};
