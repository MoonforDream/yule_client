#ifndef _CLI_H_
#define _CLI_H_

#ifdef _WIN32

#include "wrap.h"
#include "proxy.h"
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

class CLIENT {
public:
    CLIENT(const char* ip, int port);
    virtual ~CLIENT();

    void init();  // 客户端配置初始化以及启动

protected:
    SOCKET cfd;  // 客户端套接字
    sockaddr_in ser_addr;  // 服务端地址结构
    const char* IP;  // 服务端IP地址
    int PORT;  // 服务端端口号
    char buf[BUFSIZ];  // 缓冲区
};

class SOCKS_CLI : public CLIENT {
public:
    SOCKS_CLI(const char* ip, int port, std::string user, std::string pass);

    void handleconnect();
    void consult_method();
    void auth_send();
    void proxy_request();
    int proxy_recv();

private:
    int step = 0;
    char socks_ver = 0x05;
    int socks_nmethod = 1;
    char socks_method[1] = {0x02};
    char rep_suf = 0x00;
    char rep_fail = 0x01;
    std::string User;
    int Userlen;
    std::string Pass;
    int Passlen;
};

#else


#include "wrap.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <string>

class CLIENT{
public:
    CLIENT(const char *ip,int port):IP(ip),PORT(port){
        init();
    }
    void init();   //客户端配置初始化以及启动
    ~CLIENT(){
        Close(cfd);
    }
protected:
    int cfd;     //客户端套接字
    sockaddr_in ser_addr;    //服务端地址结构
    const char *IP;     //服务端IP地址
    int PORT;    //服务端端口号
    char buf[BUFSIZ];   //缓冲区
};


class SOCKS_CLI:public CLIENT{
public:
    SOCKS_CLI(const char *ip,int port,std::string user,std::string pass,const char *redirect_addr,const char* redirect_port,char type):CLIENT(ip,port),User(user),Pass(pass),dest_addr(redirect_addr),dest_port(redirect_port),addrtype(type){}
    //客户端操作函数
    void handleconnect();
    //协商认证方法
    void consult_method();
    //用户认证请求发送函数
    void auth_send();
    //发送代理转发信息
    void proxy_request();
    //接收处理代理转发回应信息
    int proxy_recv();
    //获取指定端口号流量
    void get_stream();
    //开启线程捕获包
    static void thread_func(const std::string& device);
    //处理数据包回调函数
    static void handle_pkg(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet);
    //截取流量
    void intercept_pkg();
    ~SOCKS_CLI(){};
private:
    int step=0;  //客户端协商认证步骤
    char socks_ver=0x05;   //默认SOCKS协议版本号
    /*
     * 默认支持两种协商方法
     * 0x00:不需要认证
     * 0x02:用户名、密码认证
    */
    int socks_nmethod=1;
    char socks_method[1]={0x02};
    char rep_suf=0x00;
    char rep_fail=0x01;
    std::string User;
    int Userlen=User.length();
    std::string Pass;
    int Passlen=Pass.length();
    const char* dest_addr;
    const char* dest_port;
    int iplen=strlen(dest_addr);
    int portlen=strlen(dest_port);
    char addrtype;
};

#endif

#endif
