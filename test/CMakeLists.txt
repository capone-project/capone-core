INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

PROTOBUF_GENERATE_C(TEST_PROTO_SOURCES TEST_PROTO_HEADERS test.proto)

ADD_EXECUTABLE(cpn-test cpn-test.c
    acl.c
    caps.c
    cfg.c
    channel.c
    common.c
    keys.c
    parameter.c
    proto.c
    server.c
    service.c
    session.c
    ${TEST_PROTO_SOURCES})
TARGET_LINK_LIBRARIES(cpn-test cpn cmocka)

ADD_EXECUTABLE(cpn-bench-throughput cpn-bench-throughput.c)
TARGET_LINK_LIBRARIES(cpn-bench-throughput cpn)

ADD_EXECUTABLE(cpn-bench-latency cpn-bench-latency.c)
TARGET_LINK_LIBRARIES(cpn-bench-latency cpn)

IF(X11_FOUND)
    ADD_EXECUTABLE(cpn-bench-input cpn-bench-input.c)
    TARGET_LINK_LIBRARIES(cpn-bench-input cpn ${X11_LIBRARIES})
ENDIF(X11_FOUND)
