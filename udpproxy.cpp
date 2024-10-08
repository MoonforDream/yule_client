#include "udpproxy.h"
#include <iostream>

#ifdef _WIN32

uint16_t checksum(pseudoh *ph,uint16_t ph_len, void *data, uint len){
    const uint16_t *data16=(const uint16_t*)ph;
    size_t len16=ph_len>>1;
    uint32_t sum=0;
    size_t i;
    for(i=0;i<len16;++i){
        sum+=(uint32_t)data16[i];
    }
    data16=(const uint16_t*)data;
    len16=len>>1;
    for(i=0;i<len16;++i){
        sum+=(uint32_t)data16[i];
    }
    if(len&0x1){
        const uint8_t *ndata=(const uint8_t*)data;
        sum+=(uint16_t)ndata[len-1];
    }
    sum=(sum & 0xFFFF)+(sum>>16);
    sum+=(sum>>16);
    sum=~sum;
    return (uint16_t)sum;
}



uint16_t ip_checksum(PWINDIVERT_IPHDR &iph){
    return checksum(nullptr, 0,iph, iph->HdrLength*4);
}

uint16_t tcp_checksum(PWINDIVERT_IPHDR &iph, void *data,uint len){
    pseudoh ph{
            iph->SrcAddr,
            iph->DstAddr,
            0,
            IPPROTO_TCP,
            htons((uint16_t)len)
    };
    return checksum(&ph,sizeof(pseudoh),data,len);
}

void fake_tcp(PWINDIVERT_IPHDR &iphdr, PWINDIVERT_TCPHDR &tcphdr,proxy_ix px){
    tcphdr->SrcPort=px.srcport;
    tcphdr->DstPort=px.dstport;
    tcphdr->SeqNum= htonl(1);
    tcphdr->AckNum= htonl(0);
    tcphdr->Window=htons(BS);
    tcphdr->Fin=0;
    tcphdr->Syn=1;
    tcphdr->Ack=0;
    tcphdr->Psh=0;
    tcphdr->Rst=0;
    tcphdr->Urg=0;
    tcphdr->UrgPtr=0;
    tcphdr->Reserved1=0;
    tcphdr->Reserved2=0;
    tcphdr->HdrLength= 5;
    tcphdr->Checksum=0;
    iphdr->Protocol=IPPROTO_TCP;
    iphdr->HdrLength=5;
    iphdr->Length=htons(ntohs(iphdr->Length)+tcpl-udpl+authl) ;
    iphdr->DstAddr=px.dstaddr;
    iphdr->Checksum=0;
}




void parse_fake(PWINDIVERT_IPHDR &iphdr,PWINDIVERT_UDPHDR &udphdr,uint payloadlen,proxy_ix px){
    iphdr->Protocol=IPPROTO_UDP;
    iphdr->SrcAddr=px.dstaddr;
    iphdr->HdrLength=5;
    iphdr->Length=htons(ntohs(iphdr->Length)-tcpl+udpl);
    iphdr->Checksum=0;
    udphdr->SrcPort=px.srcport;
    udphdr->DstPort=px.dstport;
    udphdr->Length= htons(udpl+payloadlen);
    udphdr->Checksum=0;
}

#else

uint16_t checksum(pseudoh *ph,uint16_t ph_len, void *data, uint len){
    const uint16_t *data16=(const uint16_t*)ph;
    size_t len16=ph_len>>1;
    uint32_t sum=0;
    size_t i;
    for(i=0;i<len16;++i){
        sum+=(uint32_t)data16[i];
    }
    data16=(const uint16_t*)data;
    len16=len>>1;
    for(i=0;i<len16;++i){
        sum+=(uint32_t)data16[i];
    }
    if(len&0x1){
        const uint8_t *ndata=(const uint8_t*)data;
        sum+=(uint16_t)ndata[len-1];
    }
    sum=(sum & 0xFFFF)+(sum>>16);
    sum+=(sum>>16);
    sum=~sum;
    return (uint16_t)sum;
}



uint16_t ip_checksum(iphdr *iph){
    return checksum(nullptr, 0,iph, iph->ihl*4);
}

uint16_t tcp_checksum(iphdr *iph, void *data,uint len){
    pseudoh ph{
        iph->saddr,
        iph->daddr,
        0,
        IPPROTO_TCP,
        htons((uint16_t)len)
    };
    return checksum(&ph,sizeof(pseudoh),data,len);
}


uint16_t udp_checksum(iphdr *iph, void *data,uint len){
    pseudoh ph{
        iph->saddr,
        iph->daddr,
        0,
        IPPROTO_UDP,
        htons((uint16_t)len)
    };
    return checksum(&ph,sizeof(pseudoh),data,len);
}

void fake_tcp(iphdr &iph, tcphdr &tcph, proxy_ix px, uint8_t *packet_data){
    tcph.source=px.srcport;
    tcph.dest=px.dstport;
    tcph.seq=htonl(1);
    tcph.ack_seq=0;
    tcph.window=htons(BS);
    tcph.fin=0;
    tcph.syn=0;
    tcph.ack=1;
    tcph.rst=0;
    tcph.psh=1;
    tcph.urg=0;
    tcph.res1=0;
    tcph.res2=0;
    tcph.doff=5;
    tcph.urg_ptr= 0;
    tcph.check=0;
    iph.protocol=IPPROTO_TCP;
    iph.ihl = 5;
    iph.tot_len=htons(ntohs(iph.tot_len) + tcpl- udpl);
    iph.saddr=px.srcaddr;
    iph.daddr=px.dstaddr;
    iph.check=0;
    iph.check=ip_checksum(&iph);
    uint blen= ntohs(iph.tot_len)-px.payload_len;
    uint data_len=ntohs(iph.tot_len)-(iph.ihl<<2);
    uint8_t buff[data_len];
    memcpy(buff,&tcph, tcpl);
    memcpy(buff+ tcpl,packet_data+blen,px.payload_len);
    tcph.check= tcp_checksum(&iph,buff,data_len);
}


void fake_mtcphs(iphdr &iph,mtcphs &tcph,proxy_ix px,uint8_t *packet_data){
    tcph.src_port=px.srcport;
    tcph.dst_port=px.dstport;
    tcph.seq=htonl(1);
    tcph.ack_num=0;
    tcph.window=htons(BS);
    tcph.fin=0;
    tcph.syn=0;
    tcph.ack=1;
    tcph.rst=0;
    tcph.psh=1;
    tcph.urg=0;
    tcph.reserved1=0;
    tcph.reserved2=0;
    tcph.len=8;
    tcph.urgent_ptr=0;
    snowflake* sf=snowflake::getsnowflake();
    tcph.authid=sf->nextid();
    tcph.daddr=px.dstaddr;
    tcph.port=px.dstport;
    tcph.checksum=0;
    iph.protocol=IPPROTO_TCP;
    iph.ihl = 5;
    iph.tot_len=htons(ntohs(iph.tot_len) + tcphl- udpl);
    iph.saddr=px.srcaddr;
    iph.daddr=px.dstaddr;
    iph.check=0;
    iph.check=ip_checksum(&iph);
    uint blen= ntohs(iph.tot_len)-px.payload_len;
    uint data_len=ntohs(iph.tot_len)-(iph.ihl<<2);
    uint8_t buff[data_len];
    memcpy(buff,&tcph, tcphl);
    memcpy(buff+ tcphl,packet_data+blen,px.payload_len);
    tcph.checksum= tcp_checksum(&iph,buff,data_len);
}



void parse_faketcp(iphdr &iph, udphdr &udph,proxy_ix px,uint8_t *packet_data){
    udph.source=px.srcport;
    udph.dest=px.dstport;
    udph.len=ntohs(udpl+px.payload_len);
    udph.check=0;
    iph.protocol=IPPROTO_UDP;
    iph.saddr=px.srcaddr;
    iph.daddr=px.dstaddr;
    iph.ihl=5;
    iph.tot_len= htons((ntohs(iph.tot_len)+ udpl- tcpl));
    iph.check=0;
    iph.check=ip_checksum(&iph);
    uint blen=ntohs(iph.tot_len)-px.payload_len;
    uint data_len= ntohs(iph.tot_len)-(iph.ihl<<2);
    uint8_t buff[data_len];
    memcpy(buff,&udph, udpl);
    memcpy(buff+udpl,packet_data+blen,px.payload_len);
    udph.check= udp_checksum(&iph,buff,data_len);
}

void parse_fakemtcphs(iphdr &iph, udphdr &udph, proxy_ix px, uint8_t *packet_data){
    udph.source=px.srcport;
    udph.dest=px.dstport;
    udph.len= ntohs(udpl+px.payload_len);
    udph.check=0;
    iph.protocol=IPPROTO_UDP;
    iph.saddr=px.srcaddr;
    iph.daddr=px.dstaddr;
    iph.ihl=5;
    iph.tot_len=htons(ntohs(iph.tot_len)+udpl-tcphl);
    iph.check=0;
    iph.check=ip_checksum(&iph);
    uint blen=ntohs(iph.tot_len)-px.payload_len;
    uint data_len=ntohs(iph.tot_len)-(iph.ihl<<2);
    uint8_t buff[data_len];
    memcpy(buff,&udph,udpl);
    memcpy(buff+udpl,packet_data+blen,px.payload_len);
    udph.check=udp_checksum(&iph,buff,data_len);
}

bool parsenetpkg(void *packet, uint len, netpacket *pkg){
    iphdr *iph=nullptr;
    ip6_hdr *iph6=nullptr;
    icmp *icmph=nullptr;
    icmp6_hdr *icmph6=nullptr;
    tcphdr *tcph=nullptr;
    udphdr *udph=nullptr;
    ip6_frag *frag_hdr=nullptr;
    uint8_t protocol=0;
    uint8_t *data=nullptr;
    uint pkg_len,tot_len,hdr_len,data_len=0,frag_off=0;
    bool mf=false,fragment=false,ext_hdr;
    if(packet==nullptr||len<sizeof(iphdr)) return false;
    data=static_cast<uint8_t *>(packet);
    data_len=len;
    iph=(iphdr*)data;
    switch (iph->version) {
        case 4:
            if(len<ip4l||iph->ihl<5) return false;
            tot_len=(uint)ntohs(iph->tot_len);
            protocol=iph->protocol;
            hdr_len=iph->ihl*sizeof(uint32_t);
            if(tot_len<hdr_len||len<hdr_len) return false;
            frag_off=ntohs((iph->frag_off)&0xFF1F);
            mf=(((iph->frag_off)&0x0020)!=0);
            fragment=(mf||frag_off!=0);
            pkg_len=(tot_len<len?tot_len:len);
            data+=hdr_len;
            data_len=pkg_len-hdr_len;
            break;
        case 6:
            iph=nullptr;
            iph6=(ip6_hdr*)data;
            if(len<ip6l) return false;
            protocol=iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
            tot_len=(uint)ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen)+ip6l;
            pkg_len=(tot_len<len?tot_len:len);
            data+=ip6l;
            data_len-=pkg_len-ip6l;
            while (frag_off==0&&data_len>=2) {
                hdr_len=(uint)data[1];
                ext_hdr=true;
                switch (protocol) {
                    case IPPROTO_FRAGMENT:
                        hdr_len=8;
                        if(fragment||data_len<hdr_len){
                            ext_hdr=false;
                            break;
                        }
                        frag_hdr=(ip6_frag*)data;
                        frag_off=ntohs((frag_hdr->ip6f_offlg)&0xF8FF);
                        mf=((frag_hdr->ip6f_offlg)&0x0100);
                        fragment=true;
                        break;
                    case IPPROTO_AH:
                        hdr_len+=2;
                        hdr_len*=4;
                        break;
                    case IPPROTO_HOPOPTS:
                    case IPPROTO_DSTOPTS:
                    case IPPROTO_ROUTING:
                    case IPPROTO_MH:
                        hdr_len++;
                        hdr_len*=8;
                        break;
                    default:
                        ext_hdr=false;
                        break;
                }
            }
            if(!ext_hdr||data_len<hdr_len) break;
            protocol=data[0];
            data+=hdr_len;
            data_len-=hdr_len;
            break;
        default:
            return false;
    }
    if(frag_off!=0) goto packetexit;
    switch (protocol) {
        case IPPROTO_TCP:
            tcph=(tcphdr*)data;
            if(data_len<tcpl||tcph->doff<5){
                tcph=nullptr;
                goto packetexit;
            }
            hdr_len=tcph->doff*sizeof(uint32_t);
            hdr_len=(hdr_len>data_len?data_len:hdr_len);
            break;
        case IPPROTO_UDP:
            if(data_len<udpl) goto packetexit;
            udph=(udphdr*)data;
            hdr_len=udpl;
            break;
        case IPPROTO_ICMP:
            if(!iph||data_len<icmpl) goto packetexit;
            icmph=(icmp *)data;
            hdr_len=icmpl;
            break;
        case IPPROTO_ICMPV6:
            if(!iph6||data_len<icmp6l) goto packetexit;
            icmph6=(icmp6_hdr *)data;
            hdr_len=icmp6l;
            break;
        default:
            goto packetexit;
    }
    data+=hdr_len;
    data_len-=hdr_len;

packetexit:
    if(!pkg) return true;
    data=(data_len==0?nullptr:data);
    pkg->protocol=static_cast<uint32_t>(protocol);
    pkg->fragment=(fragment?1:0);
    pkg->mf=(mf?1:0);
    pkg->fragoff=static_cast<uint32_t>(frag_off);
    pkg->truncated=(tot_len>len?1:0);
    pkg->extended=(tot_len<len?1:0);
    pkg->resv1=0;
    pkg->ipheader=iph;
    pkg->ip6header=iph6;
    pkg->icmpheader=icmph;
    pkg->icmp6header=icmph6;
    pkg->tcpheader=tcph;
    pkg->udpheader=udph;
    pkg->Payload=data;
    pkg->hdrlen=static_cast<uint32_t>(pkg_len-data_len);
    pkg->Payloadlen=static_cast<uint32_t>(data_len);
    return true;
}

#endif
