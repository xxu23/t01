cmake_minimum_required(VERSION 2.6)
project(t01)

include_directories( "./" )
include_directories( "./ndpi/include/" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wformat=0")

add_executable(t01 main.c ndpi_util.c pktgen.c cJSON.c rule.c)
target_link_libraries(t01 m pthread)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/ndpi/lib/libndpi.a)
