//
// Created by moon on 2024/8/2.
//

#ifndef _UDPPROXY_H
#define _UDPPROXY_H

#define BS 8192

#include <stdint.h>




//用于计算校验和的伪首部
struct pseudoh{
    uint32_t srcaddr;
    uint32_t destaddr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t length;
};

#ifdef _WIN32

#include <windows.h>
#include "tool.h"
#include "windivert.h"

#define uint unsigned int
#define ip4l sizeof(WINDIVERT_IPHDR)
#define ip6l sizeof(WINDIVERT_IPV6HDR)
#define tcpl sizeof(WINDIVERT_TCPHDR)
#define udpl sizeof(WINDIVERT_UDPHDR)
#define authl sizeof(authpkg)


struct proxy_ix{
    uint16_t srcport;
    uint16_t dstport;
    uint32_t dstaddr;   //目标IP
};

//认证信息包结构
struct authpkg{
    uint8_t id='#';     //特殊标识符
    uint64_t authid=0;    //认证标识
    uint32_t addr=0;      //游戏服务器地址
    uint16_t port=0;      //游戏服务器端口号
};


//伪装tcp
void fake_tcp(PWINDIVERT_IPHDR &iphdr, PWINDIVERT_TCPHDR &tcphdr,proxy_ix px);


//解包，解伪装
void parse_fake(PWINDIVERT_IPHDR &iphdr,PWINDIVERT_UDPHDR &udphdr,uint payloadlen,proxy_ix px);

#else
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include "tool.h"



#define ip4l sizeof(iphdr)
#define ip6l sizeof(ip6_hdr)
#define tcphl sizeof(mtcphs)
#define tcpl sizeof(tcphdr)
#define udpl sizeof(udphdr)
#define icmpl sizeof(icmp)
#define icmp6l sizeof(icmp6_hdr)

static int sockfd_v4=-1;
static int sockfd_v6=-1;

struct proxy_ix{
    uint16_t srcport;   //源端口
    uint16_t dstport;   //目标端口
    uint32_t srcaddr;   //源ip
    uint32_t dstaddr;  //目标ip地址
    uint payload_len;   //数据体长度
};

//自定义fake tcp头部
struct mtcphs{
    uint16_t src_port;    //源端口
    uint16_t dst_port;    //目的端口
    uint32_t seq;   //序列号
    uint32_t ack_num;   //确认号
    uint16_t reserved1:4; //保留位1
    uint16_t len:4; //数据偏移(tcp头部长度)
    uint8_t fin:1;    //fin标志，表示传输结束
    uint8_t syn:1;    //syn标志，表示发起一个连接
    uint8_t rst:1;    //rst标志，表示重置连接
    uint8_t psh:1;    //psh标志，提示接收端应尽快将数据交给应用程序
    uint8_t ack:1;    //ack标志，确认序号字段包含有效的确认号
    uint8_t urg:1;    //urg标志，表示紧急指针字段包含有效数据
    uint16_t reserved2:2; //保留位2
    uint16_t window;  //窗口大小
    uint16_t checksum;    //校验和
    uint16_t urgent_ptr;  //紧急指针
    uint64_t authid; //认证标识
    uint32_t daddr; //游戏服务器地址
    uint16_t port;  //游戏服务器端口号
};



//网络数据包结构体
struct netpacket{
    uint32_t hdrlen:17;     //数据包头部长度
    uint32_t fragoff:13;    //分片位移，表示数据包的分片位置
    uint32_t fragment:1;    //表示数据包是否被分片
    uint32_t mf:1;      //表示是否还有更多分片
    uint32_t Payloadlen:16;     //有效负载长度(不包括头部，也就是数据长度)
    uint32_t protocol:8;        //协议类型
    uint32_t truncated:1;       //表示数据包是否被截断
    uint32_t extended:1;    //表示数据包是否有扩展头
    uint32_t resv1:6;   //保留位
    iphdr *ipheader;     //ipv4头部
    ip6_hdr *ip6header;  //ipv6头部
    icmp *icmpheader;    //icmp头部
    icmp6_hdr *icmp6header;  //icmp6头部
    tcphdr *tcpheader;   //tcp头部
    udphdr *udpheader;   //udp头部
    uint8_t *Payload;   //指向数据包负载的指针
};






//通用计算校验和
uint16_t checksum(pseudoh *ph,uint16_t ph_len,void *data,uint len);

//计算ip头部校验和
uint16_t ip_checksum(iphdr *iph);

//计算tcp头部校验和
uint16_t tcp_checksum(iphdr *iph,void *data,uint len);

//计算udp头部校验和
uint16_t udp_checksum(iphdr *iph,void *data,uint len);

//伪装tcp
void fake_tcp(iphdr &iph, tcphdr &tcph, proxy_ix px, uint8_t *packet_data);

//伪装自定义tcp
void fake_mtcphs(iphdr &iph,mtcphs &tcph,proxy_ix px,uint8_t *packet_data);

//解包，解伪装
void parse_faketcp(iphdr &iph,udphdr &udph,proxy_ix px,uint8_t *packet_data);

//解包，解自建头伪装
void parse_fakemtcphs(iphdr &iph,udphdr &udph,proxy_ix px,uint8_t *packet_data);

//分析网络数据包，将受到的数据包进行解包分析
bool parsenetpkg(void *packet,uint len,netpacket *pkg);

#endif



#endif //_UDPPROXY_H
