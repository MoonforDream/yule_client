#include <iostream>
#include <unistd.h>
#include "client.h"
//#include "log.h"
#include <yaml-cpp/yaml.h>

// #include "Threadpool.h"
// #include <thread>



int main(int argc, char *argv[])
{

    int i;
    std::cin>>i;
    if(i!=1) return 0;
//    init_logging();
    int port;
    std::string ip,user,pass,redirect_addr,redirect_port;
    YAML::Node config;
    std::cout<<"read configuration file..."<<std::endl;
//    log("read configuration file...");
    sleep(1);
    try{
        config = YAML::LoadFile("config.yml");
    } catch(YAML::BadFile &e) {
//        error_handling("read error!");
        std::cout<<"read error!"<<std::endl;
        return -1;
    }
    ip=config["r_ip"].as<std::string>();
    port=config["r_port"].as<int>();
    numThreads=config["numThreads"].as<int>();
    cache_rep=config["cache_rep"].as<int>();
    for(auto const &it:config["proxy_pname"]){
        proxy_mmp[it.as<std::string>()]=1;
    }
    log_thread=config["log_thread"].as<int>();
    init_logging();
//    log("finish config");
//    log("client start...");
    std::cout<<"finish config"<<std::endl;
    std::cout<<"client start..."<<std::endl;
    sleep(1);
//    port=5005;
    //8.134.71.137
    //203.135.99.233
//    ip="121.40.171.33",user="admi",pass="admin21445",redirect_addr="yuul.cn",redirect_port="50055";
//    ip="8.134.71.137";
    user="admi",pass="admin21445",redirect_addr="yuul.cn",redirect_port="50055";
    setbuf(stdout,NULL);
    SOCKS_CLI cli(ip.c_str(),port,user,pass);
    cli.handleconnect();
    return 0;
}

