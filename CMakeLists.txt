cmake_minimum_required(VERSION 2.6)
project(t01)

option(USE_JEMALLOC "used jemalloc as replacement for libc malloc" ON)
option(LIBPCAP_PFRING "used libpcap ported for pfring" OFF)

message(${LIBPCAP_PFRING}, ${USE_JEMALLOC})

set(CMAKE_BUILD_TYPE Release)

include_directories( "./" )
include_directories( "./3rd/include/netmap/" )
include_directories( "./3rd/include/cJSON/" )
include_directories( "./3rd/include/ndpi/" )
include_directories( "./3rd/include/hiredis/" )
include_directories( "./3rd/include/rdkafka/" )
include_directories( "./3rd/include/msgpack/" )
include_directories( "./3rd/include/http-parser/" )
include_directories( "./3rd/include/libevent/" )
include_directories( "./3rd/include/mysql/" )
include_directories( "./3rd/include/" )
include_directories( "./3rd/include/pcap/" )
include_directories( "./3rd/include/libhl/" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=0")

if (USE_JEMALLOC)
add_definitions(-DUSE_JEMALLOC)
include_directories( "./3rd/include/jemalloc/" )
set(EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_SOURCE_DIR}/3rd/lib/libjemalloc.a dl pthread)
endif (USE_JEMALLOC)

SET(THIRD_SRC_DIR 3rd/src/)
SET(CJSON_SRC_DIR ${THIRD_SRC_DIR}/cJSON)
SET(THIRD_SRC ${CJSON_SRC_DIR}/cJSON.c)
SET(MAIN_SRC logger.c t01.c zmalloc.c ndpi_util.c pktgen.c rule.c crc64.c util.c anet.c http-server.c ioengines.c engines/redis.c engines/kafka.c ${THIRD_SRC})
SET(MAIN_LINK_LIB m pthread
        ${PROJECT_SOURCE_DIR}/3rd/lib/libndpi.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libhiredis.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/librdkafka.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libevent.a
        z
        ${PROJECT_SOURCE_DIR}/3rd/lib/libmsgpackc.a
        ${PROJECT_SOURCE_DIR}/3rd/lib/libhl.a)

if (LIBPCAP_PFRING)
    SET(MAIN_LINK_LIB ${MAIN_LINK_LIB}
            ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/pfring/libpfring.a
            ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/pfring/libpcap.a)
    add_executable(t01-pfring ${MAIN_SRC})
    target_link_libraries(t01-pfring ${MAIN_LINK_LIB} ${EXTRA_LIBS})
else()
    SET(MAIN_LINK_LIB ${MAIN_LINK_LIB}
            ${PROJECT_SOURCE_DIR}/3rd/lib/libpcap/libpcap.a)
    add_executable(t01 ${MAIN_SRC})
    target_link_libraries(t01 ${MAIN_LINK_LIB} ${EXTRA_LIBS})
endif(LIBPCAP_PFRING)

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

