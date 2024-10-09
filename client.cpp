#ifdef _WIN32
#include "client.h"
#include <cstdio>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>


CLIENT::~CLIENT() {
    closesocket(cfd);
    WSACleanup();
}

void CLIENT::init() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        perr_exit("WSAStartup failed");
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, IP, &ser_addr.sin_addr);

    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd == INVALID_SOCKET) {
        perr_exit("Socket creation failed");
    }

    int opt = 1;
    setsockopt(cfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    if (connect(cfd, (sockaddr*)&ser_addr, sizeof(ser_addr)) == SOCKET_ERROR) {
        perr_exit("Connect failed");
    }
}





#else


#include <cstdio>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include "include/client.h"
#include "include/wrap.h"
#include "include/macro.h"
#include "include/tool.h"
#include <thread>
#include <vector>


CLIENT::~CLIENT() {
    Close(cfd);
}

void CLIENT::init(){
//    bzero(&ser_addr,sizeof(ser_addr));
    memset(&ser_addr,0, sizeof(ser_addr));
    ser_addr.sin_family=AF_INET;
    ser_addr.sin_port=htons(PORT);
//    in_addr_t _ip=;
    ser_addr.sin_addr.s_addr=inet_addr(IP);
//    ser_addr.sin_addr.s_addr=htonl(INADDR_ANY);

    cfd=Socket(AF_INET,SOCK_STREAM,0);
    int opt=1;
    int ret=setsockopt(cfd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    if(ret==-1) perr_exit("setsockopt error");
    Connect(cfd,(struct sockaddr *)&ser_addr,sizeof(ser_addr));
    return;
}




void SOCKS_CLI::get_stream() {
    char errbuf[PCAP_ERRBUF_SIZE];
    // 查找可用网络接口
    char *dev = pcap_lookupdev(errbuf);
//    std::string dev = get_first_device();
//    const char *dev="WLAN";
//    char *dev=get_first_device();
    printf("device: %s\n",dev);
    if (!dev) {
        std::cerr << "Couldn't find default device: " << errbuf << std::endl;
        return;
    }
    //开启线程
    std::vector<std::thread> threads;
    for (int i = 0; i < 1; ++i) {
        threads.emplace_back(&SOCKS_CLI::thread_func, dev);
    }

    for (auto& thread : threads) {
        thread.join();
    }
}






void SOCKS_CLI::thread_func(const std::string& device) {
    char errbuf[PCAP_ERRBUF_SIZE]; // 存储错误信息的缓冲区
    int snaplen = 65535; // 捕获数据包的长度
    int promisc = 1; // 混杂模式
    int to_ms = 1000; // 等待捕获的超时时间

    // 打开捕获设备
    pcap_t* handle = pcap_create(device.c_str(), errbuf);
    if (handle == nullptr) {
        printf("Could not create pcap handle: %s\n", errbuf);
        return;
    }
    pcap_set_snaplen(handle, snaplen);
    pcap_set_promisc(handle, promisc);
    pcap_set_timeout(handle, to_ms);
    pcap_set_immediate_mode(handle, 1);      // 开启immediate模式
    //开启会话
    if (pcap_activate(handle) != 0) {
        printf("Could not activate pcap handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    //设置过滤器，捕获指定端口流量
    std::string filter = "dst host 8.134.71.137";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, 0) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return;
    }
    //将编译好的过滤器设置到会话中
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return;
    }


    // 循环捕获数据包
    while (true) {
        struct pcap_pkthdr* packet_header;
        const u_char* packet_content;
        int res = pcap_next_ex(handle, &packet_header, &packet_content);
        if (res == 1) {
            handle_pkg(nullptr, packet_header, packet_content);
        } else if (res == -1) {
            printf("Error occurred while capturing packets: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        } else if (res == 0) {
            printf("Timeout occurred while waiting for packets\n");
        }
    }
    pcap_close(handle);
}



void SOCKS_CLI::handle_pkg(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet){
    // 获取以太网帧头部
    struct ethhdr *eth = (struct ethhdr *)packet;

    // 跳过以太网帧头部，获取IP数据报头部f
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    //协议字段距离IP数据包头部距离
    int iphdr_len = iph->ihl * 4;
    // 检查IP协议类型
    if (iph->protocol == IPPROTO_TCP) {
        // 如果是TCP协议，获取TCP头部
        struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct ethhdr) + iphdr_len);
        std::cout << "TCP Packet captured" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(*(in_addr*)&iph->saddr) << std::endl;
        std::cout << "Source Port: " << ntohs(tcph->source) << std::endl;
        //TCP connect包也就是TCP握手的第一步
        if(tcph->syn&&!tcph->ack){
            std::cout<<"TCP connection packet"<<std::endl;
            tcph->dest=htons(55555);
            iph->daddr=handle_ipv4_domain("yuul.cn",DOMAIN);
        }
        std::cout << "Destination IP: " << inet_ntoa(*(in_addr*)&iph->daddr) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcph->dest) << std::endl;
    }
    else if (iph->protocol == IPPROTO_UDP) {
        // 如果是UDP协议，获取UDP头部
        struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct ethhdr) + iphdr_len);
        std::cout << "UDP Packet captured" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(*(in_addr*)&iph->saddr) << std::endl;
        std::cout << "Source Port: " << ntohs(udph->source) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(*(in_addr*)&iph->daddr) << std::endl;
        std::cout << "Destination Port: " << ntohs(udph->dest) << std::endl;
    }
}
#endif


CLIENT::CLIENT(const char* ip, int port) : IP(ip), PORT(port) {
    init();
}

SOCKS_CLI::SOCKS_CLI(const char* ip, int port, std::string user, std::string pass)
        : CLIENT(ip, port), User(user), Pass(pass){
    Userlen = user.length();
    Passlen = pass.length();
}






void SOCKS_CLI::handleconnect(){
    //协商认证方法
    consult_method();
    while (1) {
        int n = Read(cfd, buf, sizeof(buf));
        //子协商，开始认证
        if (n > 0 && step == 0) {
            auth_send();
        } else if (n > 0 && step == 1) {
            proxy_request();
        }else{
            Close(cfd);
            endproxy();
            printf("server close...\n");
        }
    }
}



void SOCKS_CLI::consult_method(){
    buf[0]=socks_ver;
    buf[1]=socks_nmethod;
    buf[2]=socks_method[0];
    Write(cfd,buf,3);
//    std::cout<<"consult step "<<step<<std::endl;
//    printf("consult step %d\n",step);
    log("consult step 0");
}

void SOCKS_CLI::auth_send(){
    if(buf[0]!=socks_ver) perr_exit("socks协议号不正确1");
    if(buf[1]==socks_method[0]){
        char data[1024];
        data[0]=socks_ver;
        data[1]=Userlen;
        memcpy(data+2,User.c_str(),Userlen);
        data[2+Userlen]=Passlen;
        memcpy(data+3+Userlen,Pass.c_str(),Passlen);
        Write(cfd,data,strlen(data));
        step++;
        log("consult step 1");
//        printf("consult step %d\n",step);
//        std::cout<<"consult step "<<step<<std::endl;
//        bzero(buf, sizeof(buf));
        memset(buf,0,sizeof(buf));
    }
}


void SOCKS_CLI::proxy_request(){
    char data[1024];
    uint64_t authid=0;
    if(buf[0]!=socks_ver) perr_exit("socks协议号不正确2");
    if(buf[1]==rep_fail) perr_exit("socks5认证失败");
    log("consult successfully!");
//    printf("consult successfully!\n");
    memcpy(&authid,buf+2,sizeof(authid));
    if(authid!=0){
        startproxy("8.134.71.137",5006,authid);
    }
    step++;
    memset(buf,0,sizeof(buf));
}

int SOCKS_CLI::proxy_recv(){
    if(buf[0]!=socks_ver) perr_exit("socks协议号不正确3");
    if(buf[1]==SUCCESS){
        printf("successfully proxy!\n");
        return 0;
    }else{
        printf("proxy fail!\n");
    }
    return -1;
    /* bzero(buf,sizeof(buf));
    step++; */
}
