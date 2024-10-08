#include <iostream>
#include <unistd.h>
#include "client.h"
// #include "Threadpool.h"
// #include <thread>



int main(int argc, char *argv[])
{
    int i;
    std::cin>>i;
    if(i!=1) return 0;
    std::cout<<"client start..."<<std::endl;
    sleep(1);
    std::string ip,user,pass,redirect_addr,redirect_port;
    int port=5005;
    //8.134.71.137
    //203.135.99.233
//    ip="121.40.171.33",user="admi",pass="admin21445",redirect_addr="yuul.cn",redirect_port="50055";
    ip="8.134.71.137",user="admi",pass="admin21445",redirect_addr="yuul.cn",redirect_port="50055";
    setbuf(stdout,NULL);
    SOCKS_CLI cli(ip.c_str(),port,user,pass);
    cli.handleconnect();
    return 0;
}

