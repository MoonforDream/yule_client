#ifndef _PROXY_H_
#define _PROXY_H_
#define MAXBUF 65535

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <iprtrmib.h>
#include <iphlpapi.h>
#include <string.h>
#include <string>
#include <unordered_map>
#include <map>
#include "tool.h"
#include "udpproxy.h"
#include <thread>

#pragma comment(lib, "ws2_32.lib")

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



struct point{
    UINT32 addr;
    USHORT port;
    bool operator==(const point& other) const {
        return addr == other.addr && port == other.port;
    }
//    bool operator<(const point& ep) const {
//        return (addr < ep.addr || (addr == ep.addr && port < ep.port));
//    }
    point() { }
    point(UINT32 _addr, USHORT _port) : addr(_addr), port(_port) { }
};

template<>
struct std::hash<point> {
    size_t operator()(const point& p) const {
        return hash<UINT32>()(p.addr) ^ hash<USHORT>()(p.port);
    }
};

//static std::unordered_map<std::string,int> plist;   //加速游戏进程名映射表
static std::mutex mx;       //重定向操作锁
//static std::map<point,point> tcpmmp;    //tcp重定向映射表
//static std::map<point,point> udpmmp;    //udp重定向映射表
static std::unordered_map<point,point> tcpmmp;
static std::unordered_map<point,point> udpmmp;
static std::mutex cache_mx; //进程表缓存锁
static std::unordered_map<USHORT, std::pair<std::string, std::chrono::steady_clock::time_point>> pc_cache;
extern int cache_rep;

extern int numThreads; // 代理监听线程数
static std::vector<std::thread> threads;   //代理监听数组

static HANDLE handle;  //网卡句柄
extern std::unordered_map<std::string,int> proxy_mmp;

//开启代理
void startproxy(std::string r_ip,int r_port,uint64_t authid);
//结束代理
void endproxy();
//截取流量,网卡句柄，代理服务器ip，代理服务器端口号,代理游戏进程名
void intercept_pkg(HANDLE handle,std::string proxy_ip,int proxy_port,uint64_t authid);
//对于代理的进程或ip，处理其tcp流量
void handle_tcp(PWINDIVERT_IPHDR &ip_header,PWINDIVERT_TCPHDR &tcp_header,
                PWINDIVERT_UDPHDR &udp_header,WINDIVERT_ADDRESS addr,std::string proxy_ip,int proxy_port,uint64_t authid,uint8_t *packet);
//对于代理的进程或ip，处理其udp出站流量
void handle_udp_out(PWINDIVERT_IPHDR &ip_header,PWINDIVERT_TCPHDR &tcp_header,
                    PWINDIVERT_UDPHDR &udp_header,WINDIVERT_ADDRESS addr,std::string proxy_ip,int proxy_port,uint64_t authid);
//对于代理的进程或ip，处理其udp进站流量
void handle_udp_in(PWINDIVERT_IPHDR &ip_header,PWINDIVERT_TCPHDR &tcp_header,
                   PWINDIVERT_UDPHDR &udp_header,WINDIVERT_ADDRESS addr,point src,point dst);


//void handle_udp_mtcphs(PWINDIVERT_IPHDR &iph,PWINDIVERT_UDPHDR &udph,mtcphs* fake_tcph,uint8_t *packet_data);

//打印转发日志
//void log_redirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort, int direction,int o_protocol,int n_protocol);
//通过获取进程名
//通过缓存获取进程名
std::string getpname_cache(USHORT port);
//通过端口获取进程名
std::string getprocessname(USHORT port,int proctol);
std::string getprocessname(USHORT port);
//通过udp端口获取进程名
std::string getprocessbyudp(USHORT port);
//通过tcp端口获取进程名
std::string getprocessbytcp(USHORT port);
//通过进程id获取进程名
std::string getprocessbypid(DWORD pid);

#else
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <mutex>
#include "tool.h"
#include "udpproxy.h"
#include "wrap.h"


struct point{
    uint32_t addr;
    uint16_t port;
    bool operator<(const point& ep) const {
        return (addr < ep.addr || (addr == ep.addr && port < ep.port));
    }
    point() { }
    point(uint32_t _addr, uint16_t _port) : addr(_addr), port(_port) { }
};


class PROXY{
public:
    PROXY()=default;
    ~PROXY(){
        endproxy();
    }
    //开启代理
    void startproxy();
    //结束代理
    void endproxy();

    static PROXY* getProxy(){
        std::lock_guard<std::mutex> lock(mx);
        if (p == nullptr) {
            p = new PROXY();
        }
        return p;
    }
//    static int handle_pkg(struct nfq_q_handle *qhd, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
    PROXY(PROXY& other) = delete;            // 禁止复制构造
    void operator=(const PROXY&) = delete;           // 禁止赋值操作
private:
    static PROXY* p;
    static std::mutex mx;
    struct nfq_handle *h= nullptr;
    struct nfq_q_handle *qh= nullptr;
    int nf_fd;
};



//static std::mutex mx;       //重定向操作锁
static std::map<point,point> tcpmmp;    //tcp重定向映射表
static std::map<point,point> udpmmp;    //udp重定向映射表

//初始化raw套接字
void init_socket();
//处理截取流量
int handle_pkg(struct nfq_q_handle *qhd, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
//判断ip包版本
int getipv(const uint8_t *packet_data);
//打印转发和接收包日志
void log_redirect(log_s lgs,int flag);
//将需要处理的udp流量伪装成tcp,适用于封装游戏服务器回应内容
void handle_udp_tcp(iphdr* ip_header,udphdr* udp_header,tcphdr* tcp_header,log_s &lgs,uint8_t* packet_data);
//将需要处理的udp流量伪装成mtcphs,适用于封装游戏客户端发送内容
void handle_udp_mtcphs(iphdr* ip_header,udphdr* udp_header,mtcphs* fake_tcphdr,log_s &lgs,uint8_t *packet_data);

//将需要处理的mtcphs流量解伪装成udp,适用于解封装游戏客户端发送内容
void handle_mtcphs_udp(iphdr *ip_header,mtcphs *fake_tcphdr,udphdr *udp_header,log_s &lgs,uint8_t *packet_data);

#endif


#endif 
