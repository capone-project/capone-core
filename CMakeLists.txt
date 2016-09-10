CMAKE_MINIMUM_REQUIRED (VERSION 2.8)

SET(CMAKE_LEGACY_CYGWIN_WIN32 0)
SET(CMAKE_MACOSX_RPATH ON)

PROJECT(capone C)

SET(CMAKE_INCLUDE_CURRENT_DIR ON)

SET(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${PROJECT_SOURCE_DIR}/cmake/)

FIND_PACKAGE(PkgConfig REQUIRED)
FIND_PACKAGE(ProtobufC REQUIRED)
FIND_PACKAGE(Threads REQUIRED)

PKG_CHECK_MODULES(SODIUM REQUIRED libsodium)

INCLUDE(CheckFunctionExists)

CHECK_FUNCTION_EXISTS(sched_setaffinity HAVE_SCHED)
CHECK_FUNCTION_EXISTS(clock_gettime HAVE_CLOCK_GETTIME)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h)

INCLUDE_DIRECTORIES("${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_BINARY_DIR}/include")
INCLUDE_DIRECTORIES(SYSTEM
    ${PROTOBUFC_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS})
LINK_DIRECTORIES(${SODIUM_LIBRARY_DIRS})

ADD_DEFINITIONS(-DVERSION="0.0.1")
ADD_DEFINITIONS(-D_POSIX_C_SOURCE=200809L)
ADD_DEFINITIONS(-D_DEFAULT_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic -std=c89")

PROTOBUF_GENERATE_C(PROTO_SOURCES PROTO_HEADERS
    include/capone/proto/capabilities.proto
    include/capone/proto/connect.proto
    include/capone/proto/discovery.proto
    include/capone/proto/encryption.proto
    include/capone/proto/exec.proto
    include/capone/proto/invoke.proto)

ADD_LIBRARY(capone SHARED
    lib/acl.c
    lib/buf.c
    lib/caps.c
    lib/cfg.c
    lib/channel.c
    lib/client.c
    lib/common.c
    lib/global.c
    lib/keys.c
    lib/list.c
    lib/log.c
    lib/opts.c
    lib/proto-enc.c
    lib/protobuf.c
    lib/server.c
    lib/service.c
    lib/session.c
    lib/socket.c
    lib/services/capabilities.c
    lib/services/exec.c
    lib/services/invoke.c
    lib/services/synergy.c
    lib/services/xpra.c
    ${PROTO_SOURCES})
TARGET_LINK_LIBRARIES(capone
    ${SODIUM_LIBRARIES}
    ${PROTOBUFC_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT})

ADD_EXECUTABLE(cpn-client cpn-client.c)
TARGET_LINK_LIBRARIES(cpn-client capone)

ADD_EXECUTABLE(cpn-derive cpn-derive.c)
TARGET_LINK_LIBRARIES(cpn-derive capone)

ADD_EXECUTABLE(cpn-discover cpn-discover.c)
TARGET_LINK_LIBRARIES(cpn-discover capone)

ADD_EXECUTABLE(cpn-discover-responder cpn-discover-responder.c)
TARGET_LINK_LIBRARIES(cpn-discover-responder capone)

ADD_EXECUTABLE(cpn-genkey cpn-genkey.c)
TARGET_LINK_LIBRARIES(cpn-genkey capone)

ADD_EXECUTABLE(cpn-server cpn-server.c)
TARGET_LINK_LIBRARIES(cpn-server capone)

ADD_SUBDIRECTORY(test)
