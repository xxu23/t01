cmake_minimum_required(VERSION 2.6)
project(t01)

option(USE_JEMALLOC "used jemalloc as replacement for libc malloc" ON) 

include_directories( "./3rd/include/netmap/" )
include_directories( "./3rd/include/ndpi/" )
include_directories( "./3rd/include/hiredis/" )
include_directories( "./3rd/include/rdkafka/" )
include_directories( "./3rd/include/msgpack/" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wformat=0")

if (USE_JEMALLOC)
add_definitions(-DUSE_JEMALLOC)
include_directories( "./3rd/include/jemalloc/" )
set(EXTRA_LIBS ${EXTRA_LIBS} ${PROJECT_SOURCE_DIR}/3rd/lib/libjemalloc.a dl pthread)
endif (USE_JEMALLOC) 

add_executable(t01 logger.c main.c ndpi_util.c pktgen.c cJSON.c rule.c anet.c ae.c networking.c ioengines.c engines/redis.c engines/kafka.c)
target_link_libraries(t01 m pthread)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/3rd/lib/libndpi.a)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/3rd/lib/libhiredis.a)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/3rd/lib/librdkafka.a)
target_link_libraries(t01 z)
target_link_libraries(t01 ${PROJECT_SOURCE_DIR}/3rd/lib/libmsgpackc.a)
target_link_libraries(t01 ${EXTRA_LIBS})

