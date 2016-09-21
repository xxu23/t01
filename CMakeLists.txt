cmake_minimum_required(VERSION 2.6)
project(t01)

option(USE_JEMALLOC "used jemalloc as replacement for libc malloc" ON) 

include_directories( "./" )
include_directories( "./ndpi/include/" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wformat=0")

if (USE_JEMALLOC)
add_definitions(-DUSE_JEMALLOC)
include_directories( "./jemalloc/include/" )
set(EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_SOURCE_DIR}/jemalloc/lib/libjemalloc.a  dl  pthread)
message("hello" ${EXTRA_LIBS})
endif (USE_JEMALLOC) 

add_executable(t01 main.c ndpi_util.c pktgen.c cJSON.c rule.c)
target_link_libraries(t01 m pthread)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/ndpi/lib/libndpi.a)
target_link_libraries(t01 ${EXTRA_LIBS})

