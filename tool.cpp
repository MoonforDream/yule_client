#include "tool.h"


snowflake* snowflake::sf= nullptr;
std::mutex snowflake::__mx;

bool isIPv4Address(const std::string &address) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, address.c_str(), &(sa.sin_addr)) != 0;
}

bool isIPv6Address(const std::string &address) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, address.c_str(), &(sa.sin6_addr)) != 0;
}

bool isDomainName(const std::string &address) {
    std::regex domain_regex("^[a-zA-Z0-9.-]+$");
    return std::regex_match(address, domain_regex);
}

char getAddressType(const std::string &address) {
    if (isIPv4Address(address)) {
        return IPV4;
    } else if (isIPv6Address(address)) {
        return IPV6;
    } else if (isDomainName(address)) {
        return DOMAIN;
    } else {
        printf("未知的地址类型!\n");
        exit(1);
    }
}

bool isValidAddress(const std::string &address) {
    struct addrinfo hints;
    struct addrinfo *res;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;

    int result = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (result == 0) {
        freeaddrinfo(res);
        return true;
    } else {
        return false;
    }
}

uint32_t handle_ipv4_domain(const char *ip) {
    int atyp = getAddressType(ip);
    if (atyp == IPV4) {
        return inet_addr(ip);
    } else if (atyp == DOMAIN) {
        struct hostent *h = gethostbyname(ip);
        if (h == nullptr) {
            perror("gethostbyname");
            return -1;
        }
        if (h->h_addrtype == AF_INET) {
            struct in_addr addr;
            memcpy(&addr, h->h_addr_list[0], sizeof(struct in_addr));
            return addr.s_addr;
        }
    }
    return -1;
}


void escmd(const char* cmd) {
    int result = std::system(cmd);
    if (result != 0) {
        std::cerr << "Command failed: " << cmd << std::endl;
    }
}

long long snowflake::nextid() {
    std::lock_guard<std::mutex> _lock(_mx);
    auto timestamp=timegen();
    if(timestamp<_lasttimestamp){
        throw std::runtime_error("Clock moved backwards. Refusing to generate id");
    }
    if(_lasttimestamp==timestamp){
        _sequence=(_sequence+1)&sequence_mask;
        if(_sequence==0){
            timestamp= nextmillis(_lasttimestamp);
        }
    }else{
        _sequence=0;
    }
    _lasttimestamp=timestamp;
    return ((timestamp-twepoch)<<timestamp_shift)|
           (_dataid<<dataid_shift)|(_workerid<<workerid_shift)|
           _sequence;
}


#ifdef _WIN32




// 转换 IP 地址为字符串
std::string ConvertIP(UINT32 addr) {
    in_addr in_addr;
    in_addr.S_un.S_addr = addr;
    return inet_ntoa(in_addr);
}



#endif
