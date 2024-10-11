
#include "log.h"
#include "proxy.h"
#include "tool.h"


#ifdef _WIN32

#include <unistd.h>

std::unordered_map<std::string,int>proxy_mmp;
int numThreads=1;
int cache_rep=0;

void startproxy(std::string r_ip,int r_port,uint64_t authid){
    //网卡句柄，打开网卡,截取
    handle = WinDivertOpen(
            "(tcp and tcp.DstPort!=80 and tcp.DstPort!=443 and tcp.SrcPort!=80 and tcp.SrcPort!=443 and tcp.SrcPort!=22 and tcp.DstPort!=22) or udp",
            WINDIVERT_LAYER_NETWORK, 0, 0);
    //WINDIVERT_FLAG_SNIFF捕获
//  handle = WinDivertOpen(
//          "tcp and (tcp.DstPort==80 or tcp.DstPort==443 or tcp.SrcPort==80 or tcp.SrcPort==443 or tcp.SrcPort==5005 or tcp.SrcPort==5006) and (tcp.SrcPort!=22 and tcp.DstPort!=22)",
//          WINDIVERT_LAYER_NETWORK, 0,0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Error opening filter: " << GetLastError() << std::endl;
        return;
    }
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(intercept_pkg,handle,r_ip,r_port,authid);
    }

}

void endproxy(){
    for (auto& thread : threads) {
        thread.join();
    }
    WinDivertClose(handle);
}


void intercept_pkg(HANDLE handle,std::string proxy_ip,int proxy_port,uint64_t authid) {
    uint8_t packet[MAXBUF];
    UINT recvsize=0;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ip6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    while (true) {

        if (!WinDivertRecv(handle, packet, sizeof(packet), &recvsize, &addr)) {
            std::cerr << "Failed to receive packet: " << GetLastError() << std::endl;
            continue;
        }
        //包头部解析api
        WinDivertHelperParsePacket(packet, recvsize, &ip_header, &ip6_header, NULL, NULL,NULL,
                                   &tcp_header, &udp_header, NULL, NULL,NULL,NULL);
        if(ip_header&&(ip_header->SrcAddr== handle_ipv4_domain("127.0.0.1")||ip_header->DstAddr== handle_ipv4_domain("127.0.0.1"))){
            goto sendpkg;
        }
        if (ip_header&&tcp_header) {
            std::string ps=addr.Outbound? getpname_cache(tcp_header->SrcPort): getpname_cache(tcp_header->DstPort);
            // TCP连接请求的处理
            if(proxy_mmp[ps]==1&&!addr.Outbound){
//            if(proxy_mmp[ps]==1){
                handle_tcp(ip_header,tcp_header,udp_header,addr,proxy_ip,proxy_port,authid,packet);
                recvsize=ntohs(ip_header->Length);
            }
        }
        if(ip_header&&udp_header){
            std::string ps= getpname_cache(udp_header->SrcPort);
            if(addr.Outbound&&proxy_mmp[ps]==1){
                handle_udp_out(ip_header,tcp_header,udp_header,addr,proxy_ip,proxy_port,authid);
                recvsize= ntohs(ip_header->Length);
            }
        }
        // 重新计算校验和
        WinDivertHelperCalcChecksums(packet, recvsize, &addr, 0);
        sendpkg:
        UINT writeLen = 0;
        if (!WinDivertSend(handle, packet, recvsize,&writeLen, &addr)) {
            std::cerr << "Failed to send packet: " << GetLastError() << std::endl;
        }
    }
}




void handle_tcp(PWINDIVERT_IPHDR &ip_header, PWINDIVERT_TCPHDR &tcp_header, PWINDIVERT_UDPHDR &udp_header,
                WINDIVERT_ADDRESS addr, std::string proxy_ip, int proxy_port,uint64_t authid,uint8_t *packet) {
    point src = {ip_header->SrcAddr, tcp_header->SrcPort};
    point dst = {ip_header->DstAddr, tcp_header->DstPort};
    if (addr.Outbound) {
        log_s lgs{};
        lgs.o_protocol=0;
        lgs.o_srcaddr=ip_header->SrcAddr;
        lgs.o_srcport=tcp_header->SrcPort;
        lgs.o_dstaddr=ip_header->DstAddr;
        lgs.o_dstport=tcp_header->DstPort;
        // 修改目标IP和端口
        mx.lock();
        tcpmmp[src] = dst;
        mx.unlock();
        uint payloadlen= ntohs(ip_header->Length)-(ip_header->HdrLength<<2)-(tcp_header->HdrLength<<2);
        auto payload=(uint8_t *)(packet+(ip_header->HdrLength << 2) + (tcp_header->HdrLength << 2));
        authpkg ag{};
        ag.id='$';
        ag.authid=authid;
        ag.addr=ip_header->DstAddr;
        ag.port=tcp_header->DstPort;
        memmove(payload+authl,payload,payloadlen);
        memcpy(payload,&ag,authl);
        payloadlen+=authl;
        ip_header->Length= htons(ntohs(ip_header->Length)+authl);
        ip_header->DstAddr = handle_ipv4_domain(proxy_ip.c_str());
        tcp_header->DstPort = htons(proxy_port);
        ip_header->Checksum=0;
        tcp_header->Checksum=0;
        lgs.n_protocol=0;
        lgs.n_srcaddr=ip_header->SrcAddr;
        lgs.n_srcport=tcp_header->SrcPort;
        lgs.n_dstaddr=ip_header->DstAddr;
        lgs.n_srcport=tcp_header->DstPort;
        log_redirect(lgs,0);
        //打印转发信息
//        log_redirect(ip_header->SrcAddr, tcp_header->SrcPort, ip_header->DstAddr, tcp_header->DstPort,
//                     dst.addr, dst.port, 0, 0,0);
    } else {
        //对tcp入站流量修改
        if (tcpmmp.find(dst) != tcpmmp.end()) {
            log_s lgs{};
            lgs.o_protocol=0;
            lgs.o_srcaddr=ip_header->SrcAddr;
            lgs.o_srcport=tcp_header->SrcPort;
            lgs.o_dstaddr=ip_header->DstAddr;
            lgs.o_dstport=tcp_header->DstPort;
            point op = tcpmmp[dst];
            ip_header->SrcAddr = op.addr;
            tcp_header->SrcPort = op.port;
            lgs.n_protocol=0;
            lgs.n_srcaddr=ip_header->SrcAddr;
            lgs.n_srcport=tcp_header->SrcPort;
            lgs.n_dstaddr=ip_header->DstAddr;
            lgs.n_srcport=tcp_header->DstPort;
            log_redirect(lgs,1);
            //打印转发信息
//            log_redirect(ip_header->SrcAddr, tcp_header->SrcPort, src.addr, src.port, ip_header->DstAddr,
//                         tcp_header->DstPort, 1, 0,0);
        }
        //对udp进站流量处理
        else if (udpmmp.find(dst) != udpmmp.end()) {
            handle_udp_in(ip_header,tcp_header,udp_header,addr,src,dst);
        }
    }
}

void handle_udp_out(PWINDIVERT_IPHDR &ip_header,PWINDIVERT_TCPHDR &tcp_header,
                    PWINDIVERT_UDPHDR &udp_header,WINDIVERT_ADDRESS addr,std::string proxy_ip,int proxy_port,uint64_t authid){
    log_s lgs{};
    lgs.n_protocol=1;
    lgs.n_srcaddr=ip_header->SrcAddr;
    lgs.n_srcport=udp_header->SrcPort;
    lgs.n_dstaddr=ip_header->DstAddr;
    lgs.n_dstport=udp_header->DstPort;
    point src={ip_header->SrcAddr,udp_header->SrcPort};
    point dst={ip_header->DstAddr,udp_header->DstPort};
    mx.lock();
    udpmmp[src] = dst;
    mx.unlock();
    proxy_ix px{};
    px.dstport=htons(proxy_port);
    px.srcport=udp_header->SrcPort;
    px.dstaddr= handle_ipv4_domain(proxy_ip.c_str());
    uint payloadlen=ntohs(udp_header->Length)-udpl;
    auto *payload=(uint8_t *)(udp_header+1);
    authpkg ag{};
    ag.authid=authid;
    ag.addr=ip_header->DstAddr;
    ag.port=udp_header->DstPort;
    memmove(payload+authl,payload,payloadlen);
    memcpy(payload,&ag,authl);
    payloadlen+=authl;
    memmove((uint8_t *)(udp_header)+tcpl,payload,payloadlen);
    tcp_header=(PWINDIVERT_TCPHDR )udp_header;
    memset(tcp_header,0,tcpl);
    //修改目标ip和目标端口，并且进行伪装tcp
    fake_tcp(ip_header,tcp_header,px);
    udp_header= nullptr;
    lgs.o_protocol=0;
    lgs.o_srcaddr=ip_header->SrcAddr;
    lgs.o_srcport=tcp_header->SrcPort;
    lgs.o_dstaddr=ip_header->DstAddr;
    lgs.o_dstport=tcp_header->DstPort;
    log_redirect(lgs,0);
//    log_redirect(ip_header->SrcAddr, tcp_header->SrcPort, ip_header->DstAddr, tcp_header->DstPort,
//                 dst.addr, dst.port, 0,1,0);
}


void handle_udp_in(PWINDIVERT_IPHDR &ip_header,PWINDIVERT_TCPHDR &tcp_header,
                   PWINDIVERT_UDPHDR &udp_header,WINDIVERT_ADDRESS addr,point src,point dst){
    log_s lgs{};
    lgs.o_protocol=0;
    lgs.o_srcaddr=ip_header->SrcAddr;
    lgs.o_srcport=tcp_header->SrcPort;
    lgs.o_dstaddr=ip_header->DstAddr;
    lgs.o_dstport=tcp_header->DstPort;
    point op = udpmmp[dst];
    uint payloadlen= ntohs(ip_header->Length)-(ip_header->HdrLength<<2)-tcpl;
    auto payload = (uint8_t *) (tcp_header + 1);
    proxy_ix px{};
    px.srcport = op.port;
    px.dstaddr = op.addr;
    px.dstport = tcp_header->DstPort;
    memmove((uint8_t *)(tcp_header)+udpl,payload,payloadlen);
    memset(payload+payloadlen,0,tcpl-udpl);
    udp_header=(PWINDIVERT_UDPHDR )tcp_header;
    memset(udp_header,0,udpl);
    parse_fake(ip_header, udp_header, payloadlen,px);
    tcp_header = nullptr;
    lgs.n_protocol=1;
    lgs.n_srcaddr=ip_header->SrcAddr;
    lgs.n_srcport=udp_header->SrcPort;
    lgs.n_dstaddr=ip_header->DstAddr;
    lgs.n_dstport=udp_header->DstPort;
    log_redirect(lgs,1);
//    log_redirect(ip_header->SrcAddr, udp_header->SrcPort, src.addr, src.port, ip_header->DstAddr,
//                 udp_header->DstPort, 1, 0,1);
}



//// 打印日志
//void log_redirect(UINT32 srcAddr, USHORT srcPort, UINT32 proxyAddr, USHORT proxyPort, UINT32 dstAddr, USHORT dstPort,
//                  int direction, int o_protocol,int n_protocol) {
//    const char *o_s = o_protocol ? "UDP" : "TCP";
//    const char *n_s=n_protocol?"UDP":"TCP";
//    if (direction == 0) {
//        printf("[Redirect]: (%s)",o_s);
//        std::cout << "[" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << " -> "
//                  << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]";
//        std::cout << " -> ("<<n_s<<")[" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << " -> "
//                  << ConvertIP(proxyAddr) << ":" << ntohs(proxyPort) << "]" << std::endl;
//    } else if (direction == 1) {
//        printf("[Received]: (%s)",o_s);
//        std::cout << "[" << ConvertIP(proxyAddr) << ":" << ntohs(proxyPort) << " -> "
//                  << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]";
//        std::cout <<  " -> ("<<n_s<<")[" << ConvertIP(srcAddr) << ":" << ntohs(srcPort) << " -> "
//                  << ConvertIP(dstAddr) << ":" << ntohs(dstPort) << "]" << std::endl;
//    } else {
//        std::cout << "X Error ";
//    }
//}



std::string getprocessbypid(DWORD pid) {
    std::string processName = "Unknown";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == pid) {
                    processName = pe32.szExeFile;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processName;
}

std::string getpname_cache(USHORT port) {
    auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(cache_mx);
        auto it = pc_cache.find(port);
        if (it != pc_cache.end()) {
            // 检查缓存是否过期（5秒）
            if (now - it->second.second < std::chrono::seconds(cache_rep)) {
                return it->second.first;
            } else {
                pc_cache.erase(it);
            }
        }
    }
    // 如果缓存中没有，或者已过期，重新获取
    std::string process_name = getprocessname(port);
    {
        std::lock_guard<std::mutex> lock(cache_mx);
        pc_cache[port] = { process_name, now };
    }
    return process_name;
}


std::string getprocessname(USHORT port,int proctol) {
    if (proctol == 0) {
        return getprocessbytcp(port);
    } else if (proctol == 1) {
        return getprocessbyudp(port);
    }
}

std::string getprocessname(USHORT port) {
    std::string s= getprocessbyudp(port);
    return (s!=""&&s!="Process not found"&&s!="Unknown")?s: getprocessbytcp(port);
}

std::string getprocessbytcp(USHORT port) {
    ULONG bufferSize = 0;
    DWORD dwRetVal = 0;
    PVOID pTable = nullptr;
    GetExtendedTcpTable(nullptr, &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    pTable = malloc(bufferSize);
    if (pTable == nullptr) {
        std::cerr << "Error allocating memory for TCP table." << std::endl;
        return "";
    }
    dwRetVal = GetExtendedTcpTable(pTable, &bufferSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (dwRetVal != NO_ERROR) {
        std::cerr << "Failed to get extended table: " << dwRetVal << std::endl;
        free(pTable);
        return "";
    }
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID) pTable;
    for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
        if (pTcpTable->table[i].dwLocalPort == port) {
            std::string processName = getprocessbypid(pTcpTable->table[i].dwOwningPid);
            free(pTable);
            return processName;
        }
    }
    free(pTable);
    return "Process not found";
}




std::string getprocessbyudp(USHORT port) {
    ULONG bufferSize = 0;
    DWORD dwRetVal = 0;
    PVOID pTable = nullptr;

    GetExtendedUdpTable(nullptr, &bufferSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    pTable = malloc(bufferSize);
    if (pTable == nullptr) {
        std::cerr << "Error allocating memory for UDP table." << std::endl;
        return "";
    }

    dwRetVal = GetExtendedUdpTable(pTable, &bufferSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRetVal != NO_ERROR) {
        std::cerr << "Failed to get extended UDP table: " << dwRetVal << std::endl;
        free(pTable);
        return "";
    }

    PMIB_UDPTABLE_OWNER_PID pUdpTable = (PMIB_UDPTABLE_OWNER_PID) pTable;
    for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
        if (pUdpTable->table[i].dwLocalPort == port) {
            std::string processName = getprocessbypid(pUdpTable->table[i].dwOwningPid);
            free(pTable);
            return processName;
        }
    }

    free(pTable);
    return "Process not found";
}


#else
#include "proxy.h"
#include <linux/netfilter.h>
#include <csignal>


PROXY* PROXY::p = nullptr;
std::mutex PROXY::mx;



void PROXY::startproxy(){
    int rv;
    char buf[MAXBUF];
    qh= nullptr;
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        endproxy();
        exit(1);
    }
    escmd("sudo insmod ./lib/hmod.ko");
//    escmd("sudo insmod hmod.ko");
    qh = nfq_create_queue(h, 0, &handle_pkg, NULL);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        endproxy();
        exit(1);
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    nf_fd = nfq_fd(h);
    init_socket();
    while ((rv = recv(nf_fd, buf, sizeof(buf), 0))) {
        if(rv>=0)
            nfq_handle_packet(h, buf, rv);
    }

}


void PROXY::endproxy(){
    if(qh)  nfq_destroy_queue(qh);
    if(h) nfq_close(h);
    if(sockfd_v4>0) Close(sockfd_v4);
    if(sockfd_v6>0) Close(sockfd_v6);
//    escmd("sudo rmmod hmod.ko");
    escmd("sudo rmmod ./lib/hmod.ko");
}


void init_socket(){
    sockfd_v4=Socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd_v4 < 0) {
        perror("socket_v4");
        exit(EXIT_FAILURE);
    }
    int one = 1;
    if (setsockopt(sockfd_v4, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
    }
    sockfd_v6=Socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
}

int getipv(const uint8_t *packet_data){
    uint verison=(packet_data[0]>>4);   //提取包前4位判断ip版本
    if(verison==4){
        return 4;
    }else if (verison==6) {
        return 6;
    }else{
        return -1;
    }
}



void log_redirect(log_s lgs, int flag){
    const char* o_str=lgs.o_protocol?"UDP":"TCP";
    if(flag==0){
        printf("[Received]:");
        printf(" (%s)[%s:%d -> %s:%d]\n",o_str,ConvertIP(lgs.o_srcaddr).c_str(),
               ntohs(lgs.o_srcport),ConvertIP(lgs.o_dstaddr).c_str(),ntohs(lgs.o_dstport));
    }else if(flag==1){
        const char* n_str=lgs.n_protocol?"UDP":"TCP";
        printf("[Redirect]:");
        printf(" (%s)[%s:%d -> %s:%d] ",o_str,ConvertIP(lgs.o_srcaddr).c_str(),
               ntohs(lgs.o_srcport),ConvertIP(lgs.o_dstaddr).c_str(),ntohs(lgs.o_dstport));
        printf("-> (%s)[%s:%d -> %s:%d]\n",n_str,ConvertIP(lgs.n_srcaddr).c_str(),
               ntohs(lgs.n_srcport),ConvertIP(lgs.n_dstaddr).c_str(),ntohs(lgs.n_dstport));
    }else if(flag==2){
        const char* n_str=lgs.n_protocol?"UDP":"TCP";
        printf("[Error]:");
        printf(" (%s)[%s:%d -> %s:%d] ",o_str,ConvertIP(lgs.o_srcaddr).c_str(),
               ntohs(lgs.o_srcport),ConvertIP(lgs.o_dstaddr).c_str(),ntohs(lgs.o_dstport));
        printf("-> (%s)[%s:%d -> %s:%d]\n",n_str,ConvertIP(lgs.n_srcaddr).c_str(),
               ntohs(lgs.n_srcport),ConvertIP(lgs.n_dstaddr).c_str(),ntohs(lgs.n_dstport));
    }
}


void handle_udp_tcp(iphdr* ip_header,udphdr* udp_header,tcphdr* tcp_header,log_s &lgs,uint8_t* packet_data){
    uint payloadlen = ntohs(udp_header->len) - udpl;
    uint8_t *payload = (uint8_t *) (udp_header + 1);
    proxy_ix px{
            udp_header->source,
            htons(5005),
            htonl(INADDR_ANY),
            handle_ipv4_domain("8.134.71.137"),
//            handle_ipv4_domain("121.40.171.33"),
            payloadlen
    };
    memmove((uint8_t *) (udp_header) + tcpl, payload, payloadlen);
    tcp_header = (struct tcphdr *) udp_header;
    memset(tcp_header, 0, sizeof(struct tcphdr));
    fake_tcp(*ip_header, *tcp_header, px, packet_data);
    lgs.n_protocol=0;
    lgs.n_srcaddr=ip_header->saddr;
    lgs.n_dstaddr=ip_header->daddr;
    lgs.n_srcport=tcp_header->source;
    lgs.n_dstport=tcp_header->dest;
    struct sockaddr_in ser_addr;
    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = tcp_header->dest;
    ser_addr.sin_addr.s_addr = ip_header->daddr;
    size_t sent_len = sendto(sockfd_v4, packet_data, ntohs(ip_header->tot_len), 0,
                             (struct sockaddr *) &ser_addr, sizeof(ser_addr));
    if (sent_len>0) {
        log_redirect(lgs,1);
    }else {
        log_redirect(lgs,2);
    }
}

void handle_udp_mtcphs(iphdr* ip_header,udphdr* udp_header,mtcphs* fake_tcphdr,log_s &lgs,uint8_t *packet_data){
    uint payloadlen = ntohs(udp_header->len) - udpl;
    uint8_t *payload = (uint8_t *) (udp_header + 1);
    proxy_ix px{
            udp_header->source,
            htons(5005),
            htonl(INADDR_ANY),
            handle_ipv4_domain("8.134.71.137"),
//            handle_ipv4_domain("121.40.171.33"),
            payloadlen
    };
    memmove((uint8_t *) (udp_header) + tcphl, payload, payloadlen);
    fake_tcphdr = (struct mtcphs *) udp_header;
    memset(fake_tcphdr, 0, tcphl);
    fake_mtcphs(*ip_header, *fake_tcphdr, px, packet_data);
    lgs.n_protocol=0;
    lgs.n_srcaddr=ip_header->saddr;
    lgs.n_dstaddr=ip_header->daddr;
    lgs.n_srcport=fake_tcphdr->src_port;
    lgs.n_dstport=fake_tcphdr->dst_port;
    struct sockaddr_in ser_addr;
    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_port = fake_tcphdr->dst_port;
    ser_addr.sin_addr.s_addr = ip_header->daddr;
    size_t sent_len = sendto(sockfd_v4, packet_data, ntohs(ip_header->tot_len), 0,
                             (struct sockaddr *) &ser_addr, sizeof(ser_addr));
    if (sent_len>0) {
        log_redirect(lgs,1);
    }else {
        log_redirect(lgs,2);
    }

}

void handle_mtcphs_udp(iphdr *ip_header,mtcphs *fake_tcphdr,udphdr *udp_header,log_s &lgs,uint8_t *packet_data){
    uint payloadlen= ntohs(ip_header->tot_len)-(ip_header->ihl<<2)-tcphl;
    uint8_t *payload = (uint8_t *) (fake_tcphdr + 1);
    proxy_ix px{
            fake_tcphdr->src_port,
            htons(5006),
            htonl(INADDR_ANY),
            handle_ipv4_domain("121.40.171.33"),
            payloadlen
    };
    memmove((uint8_t *) (fake_tcphdr) + udpl, payload, payloadlen);
    udp_header=(struct udphdr*)fake_tcphdr;
    memset(udp_header,0,udpl);
    parse_fakemtcphs(*ip_header,*udp_header,px,packet_data);
    lgs.n_protocol=1;
    lgs.n_srcaddr=ip_header->saddr;
    lgs.n_srcport=udp_header->source;
    lgs.n_dstaddr=ip_header->daddr;
    lgs.n_dstport=udp_header->dest;
    struct sockaddr_in ser_addr;
    ser_addr.sin_family=AF_INET;
    ser_addr.sin_addr.s_addr=ip_header->daddr;
    ser_addr.sin_port=udp_header->dest;
    size_t sent_len = sendto(sockfd_v4, packet_data, ntohs(ip_header->tot_len), 0,
                             (struct sockaddr *) &ser_addr, sizeof(ser_addr));
    if (sent_len>0) {
        log_redirect(lgs,1);
    }else {
        log_redirect(lgs,2);
    }
}


int handle_pkg(struct nfq_q_handle *qhd, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *packet_data;
    int id = 0, ret;
    struct iphdr *ip_header=nullptr;
    struct ip6_hdr *ip6_header= nullptr;
    struct tcphdr *tcp_header=nullptr;
    struct udphdr *udp_header=nullptr;
    struct mtcphs *fake_tcphdr= nullptr;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    ret = nfq_get_payload(nfa, &packet_data);
    uint8_t pkgd[ret];
    memcpy(pkgd,packet_data,ret);
    if (ret >= 0) {
        int version= getipv(packet_data);
        if(version==4){
            ip_header = (struct iphdr *)packet_data;
            log_s lgs;
            lgs.o_srcaddr=ip_header->saddr;
            lgs.o_dstaddr=ip_header->daddr;
            if(ip_header->protocol==IPPROTO_TCP){
                fake_tcphdr=(struct mtcphs*)(packet_data+(ip_header->ihl<<2));
                lgs.o_srcport=fake_tcphdr->src_port;
                lgs.o_dstport=fake_tcphdr->dst_port;
                lgs.o_protocol=0;
                uint64_t authid=fake_tcphdr->authid;
                if(authid==2144){
                    handle_mtcphs_udp(ip_header,fake_tcphdr,udp_header,lgs,packet_data);
                    return nfq_set_verdict(qhd, id, NF_STOLEN, ntohs(ip_header->tot_len), packet_data);
                }
                log_redirect(lgs, 0);
            }
            if(ip_header->protocol==IPPROTO_UDP) {
                udp_header = (struct udphdr *) (packet_data + (ip_header->ihl << 2));
                lgs.o_protocol=1;
                lgs.o_srcport=udp_header->source;
                lgs.o_dstport=udp_header->dest;
                if (ntohs(udp_header->dest) == 5005) {
                     handle_udp_mtcphs(ip_header,udp_header,fake_tcphdr,lgs,packet_data);
//                   handle_udp_tcp(ip_header,udp_header,tcp_header,lgs,packet_data);

                    return nfq_set_verdict(qhd, id, NF_STOLEN, ntohs(ip_header->tot_len), packet_data);
                }
                log_redirect(lgs, 0);
            }
        }else if(version==6){
            ip6_header=(struct ip6_hdr *)packet_data;
        }
    }
    return nfq_set_verdict(qhd, id, NF_ACCEPT, ret, packet_data);
}

#endif
