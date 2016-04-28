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

INCLUDE_DIRECTORIES(SYSTEM
    ${PROTOBUFC_INCLUDE_DIRS}
    ${CMOCKA_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS})
LINK_DIRECTORIES(${SODIUM_LIBRARY_DIRS})

ADD_DEFINITIONS(-DVERSION="0.0.1")
ADD_DEFINITIONS(-D_POSIX_C_SOURCE=200809L)
ADD_DEFINITIONS(-D_DEFAULT_SOURCE)

SET(CMAKE_C_FLAGS "-Wall -Wextra -Werror -pedantic -std=c89")

PROTOBUF_GENERATE_C(PROTO_SOURCES PROTO_HEADERS
    proto/capabilities.proto
    proto/connect.proto
    proto/discovery.proto
    proto/encryption.proto
    proto/test.proto)

ADD_LIBRARY(sd SHARED
    lib/cfg.c
    lib/channel.c
    lib/common.c
    lib/keys.c
    lib/log.c
    lib/proto.c
    lib/proto-enc.c
    lib/server.c
    lib/service.c
    lib/service/capabilities.c
    lib/service/exec.c
    lib/service/invoke.c
    lib/service/synergy.c
    lib/service/test.c
    lib/service/xpra.c
    lib/session.c
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
    test/proto.c
    test/server.c
    test/service.c
    test/session.c)
TARGET_LINK_LIBRARIES(sd-test sd cmocka)
