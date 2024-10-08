cmake_minimum_required(VERSION 3.27)
project(yule_accelerator)

set(CMAKE_CXX_STANDARD 11)

include_directories(./include)
link_directories("./lib")

add_executable(yule_accelerator main.cpp wrap.cpp client.cpp tool.cpp udpproxy.cpp proxy.cpp)

target_link_libraries(yule_accelerator ws2_32 WinDivert iphlpapi)

