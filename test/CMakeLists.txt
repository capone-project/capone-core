PROTOBUF_GENERATE_C(TEST_PROTO_SOURCES TEST_PROTO_HEADERS test.proto)

FIND_PACKAGE(CMOCKA)

IF(CMOCKA_FOUND)
    MESSAGE(STATUS "Found cmocka: TRUE")
    MESSAGE(STATUS "  Building tests")

    INCLUDE_DIRECTORIES(SYSTEM ${CMOCKA_INCLUDE_DIR})

    ADD_LIBRARY(capone-test SHARED test.c)
    TARGET_LINK_LIBRARIES(capone-test capone cmocka)

    ADD_EXECUTABLE(cpn-test cpn-test.c
        acl.c
        caps.c
        cfg.c
        channel.c
        common.c
        keys.c
        list.c
        opts.c
        proto.c
        server.c
        service.c
        session.c
        test-service.c
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
