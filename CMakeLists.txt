cmake_minimum_required(VERSION 2.6)
project(t01)

option(USE_JEMALLOC "used jemalloc as replacement for libc malloc" ON)
option(USE_CXXQUEUE "used moodycamel::ConcurrentQueue" ON)

set(CMAKE_BUILD_TYPE Release)

include_directories( "./" )
include_directories( "./3rd/include/netmap/" )
include_directories( "./3rd/include/cJSON/" )
include_directories( "./3rd/include/ndpi/" )
include_directories( "./3rd/include/hiredis/" )
include_directories( "./3rd/include/rdkafka/" )
include_directories( "./3rd/include/http-parser/" )
include_directories( "./3rd/include/libevent/" )
include_directories( "./3rd/include/mysql/" )
include_directories( "./3rd/include/" )
include_directories( "./3rd/include/pcap/" )
include_directories( "./3rd/include/libhl/" )
include_directories( "./3rd/include/pfring/" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if (USE_JEMALLOC)
add_definitions(-DUSE_JEMALLOC)
include_directories( "./3rd/include/jemalloc/" )
set(EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_SOURCE_DIR}/3rd/lib/libjemalloc.a dl pthread)
endif (USE_JEMALLOC)
if (USE_CXXQUEUE)
    add_definitions(-DUSE_CXXQUEUE)
endif(USE_CXXQUEUE)

SET(THIRD_SRC_DIR 3rd/src/)
SET(CJSON_SRC_DIR ${THIRD_SRC_DIR}/cJSON)
SET(THIRD_SRC ${CJSON_SRC_DIR}/cJSON.c)
SET(MAIN_SRC t01.c myqueue.cpp logger.c config.c zmalloc.c ndpi_util.c pktgen.c rule.c crc32.c crc64.c util.c anet.c http-server.c ioengines.c engines/redis.c engines/kafka.c ${THIRD_SRC})
SET(MAIN_LINK_LIB m pthread
        ${PROJECT_SOURCE_DIR}/3rd/lib/libndpi.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libhiredis.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/librdkafka.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libevent.a
        z
        ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/pfring/libpfring.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libhl.a)

SET(T01_PFRING_LINK_LIB ${MAIN_LINK_LIB}
        ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/pfring/libpcap.a)
add_executable(t01-pfring ${MAIN_SRC})
target_link_libraries(t01-pfring ${T01_PFRING_LINK_LIB} ${EXTRA_LIBS})

SET(T01_LINK_LIB ${MAIN_LINK_LIB}
        ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/libpcap.a)
add_executable(t01 ${MAIN_SRC} crc32.h crc32.c)
target_link_libraries(t01 ${T01_LINK_LIB} ${EXTRA_LIBS})

add_executable(tests_rule tests/tests_rule.c logger.c zmalloc.c rule.c crc64.c util.c ${THIRD_SRC})
target_link_libraries(tests_rule m pthread)
target_link_libraries(tests_rule ${PROJECT_SOURCE_DIR}/3rd/lib/libevent.a)
target_link_libraries(tests_rule z)
target_link_libraries(tests_rule ${EXTRA_LIBS})

add_executable(t01log t01log.c anet.c logger.c util.c zmalloc.c)
target_link_libraries(t01log ${PROJECT_SOURCE_DIR}/3rd/lib/libevent.a)
target_link_libraries(t01log m pthread)
target_link_libraries(t01log ${EXTRA_LIBS})
target_link_libraries(t01log ${PROJECT_SOURCE_DIR}/3rd/lib/libmysqlclient.a)
target_link_libraries(t01log ${PROJECT_SOURCE_DIR}/3rd/lib/libhl.a)
target_link_libraries(t01log z m)

