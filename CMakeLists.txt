CMAKE_MINIMUM_REQUIRED (VERSION 2.8)

SET(CMAKE_LEGACY_CYGWIN_WIN32 0)
SET(CMAKE_MACOSX_RPATH ON)

PROJECT(sd C)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

SET(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${PROJECT_SOURCE_DIR}/cmake/)

FIND_PACKAGE(PkgConfig REQUIRED)
FIND_PACKAGE(cmocka REQUIRED)
FIND_PACKAGE(ProtobufC REQUIRED)
FIND_PACKAGE(Threads REQUIRED)

PKG_CHECK_MODULES(SODIUM REQUIRED libsodium)
PKG_CHECK_MODULES(X11 x11 xtst xi)

INCLUDE(CheckFunctionExists)

CHECK_FUNCTION_EXISTS(sched_setaffinity HAVE_SCHED)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

INCLUDE_DIRECTORIES(SYSTEM
    ${PROTOBUFC_INCLUDE_DIRS}
    ${CMOCKA_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS})
LINK_DIRECTORIES(${SODIUM_LIBRARY_DIRS})

ADD_DEFINITIONS(-DVERSION="0.0.1")
ADD_DEFINITIONS(-D_POSIX_C_SOURCE=200809L)
ADD_DEFINITIONS(-D_DEFAULT_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic -std=c89")

PROTOBUF_GENERATE_C(PROTO_SOURCES PROTO_HEADERS
    proto/capabilities.proto
    proto/connect.proto
    proto/discovery.proto
    proto/encryption.proto
    proto/test.proto)

ADD_LIBRARY(sd SHARED
    lib/bench.c
    lib/caps.c
    lib/cfg.c
    lib/channel.c
    lib/common.c
    lib/keys.c
    lib/log.c
    lib/parameter.c
    lib/proto.c
    lib/proto-enc.c
    lib/server.c
    lib/session.c
    lib/service.c
    service/capabilities.c
    service/exec.c
    service/invoke.c
    service/synergy.c
    service/test.c
    service/xpra.c
    ${PROTO_SOURCES})
TARGET_LINK_LIBRARIES(sd
    ${SODIUM_LIBRARIES}
    ${PROTOBUFC_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT})

ADD_EXECUTABLE(sd-connect sd-connect.c)
TARGET_LINK_LIBRARIES(sd-connect sd)

ADD_EXECUTABLE(sd-discover sd-discover.c)
TARGET_LINK_LIBRARIES(sd-discover sd)

ADD_EXECUTABLE(sd-discover-responder sd-discover-responder.c)
TARGET_LINK_LIBRARIES(sd-discover-responder sd)

ADD_EXECUTABLE(sd-genkey sd-genkey.c)
TARGET_LINK_LIBRARIES(sd-genkey sd)

ADD_EXECUTABLE(sd-server sd-server.c)
TARGET_LINK_LIBRARIES(sd-server sd)

ADD_EXECUTABLE(sd-test sd-test.c
    test/cfg.c
    test/channel.c
    test/common.c
    test/keys.c
    test/parameter.c
    test/proto.c
    test/server.c
    test/service.c
    test/session.c)
TARGET_LINK_LIBRARIES(sd-test sd cmocka)

ADD_EXECUTABLE(sd-bench-throughput sd-bench-throughput.c)
TARGET_LINK_LIBRARIES(sd-bench-throughput sd)

ADD_EXECUTABLE(sd-bench-latency sd-bench-latency.c)
TARGET_LINK_LIBRARIES(sd-bench-latency sd)

IF(X11_FOUND)
    ADD_EXECUTABLE(sd-bench-input sd-bench-input.c)
    TARGET_LINK_LIBRARIES(sd-bench-input sd ${X11_LIBRARIES})
ENDIF(X11_FOUND)
