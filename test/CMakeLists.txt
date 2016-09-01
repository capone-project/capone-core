FIND_PACKAGE(CMOCKA)

IF(CMOCKA_FOUND)
    MESSAGE(STATUS "Found cmocka: TRUE")
    MESSAGE(STATUS "  Building tests")

    PROTOBUF_GENERATE_C(TEST_PROTO_SOURCES TEST_PROTO_HEADERS lib/test.proto)

    INCLUDE_DIRECTORIES(SYSTEM
        ${CMOCKA_INCLUDE_DIR}
        ${PROJECT_BINARY_DIR})

    ADD_EXECUTABLE(test-helper test-helper.c)

    SET(TEST_HELPER_EXECUTABLE
        ${CMAKE_CURRENT_BINARY_DIR}/test-helper${CMAKE_EXECUTABLE_SUFFIX})

    CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/config.h)

    ADD_LIBRARY(capone-test SHARED bench.c test.c)
    TARGET_LINK_LIBRARIES(capone-test capone cmocka)

    ADD_EXECUTABLE(cpn-test cpn-test.c
        lib/acl.c
        lib/caps.c
        lib/cfg.c
        lib/channel.c
        lib/common.c
        lib/keys.c
        lib/list.c
        lib/opts.c
        lib/proto.c
        lib/server.c
        lib/service.c
        lib/session.c
        lib/test-service.c
        lib/service/exec.c
        ${TEST_PROTO_SOURCES})
    TARGET_LINK_LIBRARIES(cpn-test capone-test)

    ADD_EXECUTABLE(cpn-bench-throughput cpn-bench-throughput.c)
    TARGET_LINK_LIBRARIES(cpn-bench-throughput capone-test)

    ADD_EXECUTABLE(cpn-bench-latency cpn-bench-latency.c)
    TARGET_LINK_LIBRARIES(cpn-bench-latency capone-test)

    PKG_CHECK_MODULES(X11 x11 xtst xi)

    IF(X11_FOUND)
        ADD_EXECUTABLE(cpn-bench-input cpn-bench-input.c)
        TARGET_LINK_LIBRARIES(cpn-bench-input capone-test ${X11_LIBRARIES})
    ENDIF(X11_FOUND)

ELSE()
    MESSAGE(STATUS "Found cmocka: FALSE")
    MESSAGE(STATUS "  Not building tests")
ENDIF(CMOCKA_FOUND)
