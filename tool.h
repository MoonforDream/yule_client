#ifndef _TOOL_H_
#define _TOOL_H_

#include "macro.h"
#include <iostream>
#include <mutex>
#include <chrono>
#include <regex>
#include <cstdlib>
#include <string>

#ifdef _WIN32

#include <windivert.h>
#include <ws2tcpip.h>
// 转换 网络字节序IP 地址为字符串
std::string ConvertIP(UINT32 addr);

//代理日志信息结构体
struct log_s{
    uint32_t o_srcaddr;     //原起始地址
    uint32_t o_dstaddr;     //原目标地址
    uint16_t o_srcport;     //原起始端口
    uint16_t o_dstport;     //原目标端口
    uint32_t n_srcaddr;     //新起始地址
    uint32_t n_dstaddr;     //新目标地址
    uint16_t n_srcport;     //新起始端口
    uint16_t n_dstport;     //新目标端口
    int o_protocol;         //原协议字段,1代表udp,0代表tcp
    int n_protocol;         //新协议字段,1代表udp,0代表tcp
};
#else


#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>



std::string ConvertIP(uint32_t addr);

#endif

// 判断是否为IPv4地址
bool isIPv4Address(const std::string& address);
// 判断是否为IPv6地址
bool isIPv6Address(const std::string& address);
// 判断是否为域名
bool isDomainName(const std::string& address);
// 综合判断地址类型
char getAddressType(const std::string& address);
// 验证地址合法性
bool isValidAddress(const std::string& address);
//处理ipv4地址以及域名转换为网络字节序地址
uint32_t handle_ipv4_domain(const char *ip);
//执行系统命令，用于加载/卸载内核模块
void escmd(const char* cmd);

//雪花算法类:生成唯一认证id
class snowflake{
public:
    snowflake()=default;
    long long nextid();

    ~snowflake()=default;
    snowflake(snowflake& other)=delete;
    void operator=(const snowflake&)=delete;
    static snowflake* getsnowflake(){
        std::lock_guard<std::mutex>lock(__mx);
        if(sf== nullptr){
            sf=new snowflake();
        }
        return sf;
    }
private:
    long long timegen() const{
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
    }
    long long nextmillis(long long lasttimestamp){
        auto timestamp=timegen();
        while (timestamp<=lasttimestamp) timestamp=timegen();
        return timestamp;
    }
    // Unix时间戳起点：1970-01-01 00:00:00 UTC
    static const long long twepoch = 1288834974657LL;
    static const int workerid_bits=5;
    static const int dataid_bits=5;
    static const int sequence_bits=12;

    static const int workerid_shift=sequence_bits;
    static const int dataid_shift=sequence_bits+workerid_bits;
    static const int timestamp_shift=sequence_bits+workerid_bits+dataid_bits;
    static const int sequence_mask=0xFFFFFFFF^(0xFFFFFFFF<<sequence_bits);
    int _dataid=21;
    int _workerid=14;
    long long _sequence=0;
    long long _lasttimestamp=-1;
    std::mutex _mx;

    static snowflake* sf;
    static std::mutex __mx;
};

#endif
