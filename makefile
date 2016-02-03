CC=gcc
CFLAGS=-g -ggdb -O0 -Wall -Wextra -pedantic -std=c99 -D_POSIX_SOURCE -D_DEFAULT_SOURCE
LDFLAGS=-g -ggdb
CPPFLAGS=-DVERSION=\"0.0.1\"

PROTOBUF=proto/discovery.proto
PROTOBUF_SOURCES=$(patsubst %.proto,%.pb-c.c,${PROTOBUF})
PROTOBUF_HEADERS=$(patsubst %.proto,%.pb-c.h,${PROTOBUF})
PROTOBUF_OBJECTS=$(patsubst %.proto,%.pb-c.o,${PROTOBUF})

LIBRARY_SOURCES=lib/cfg.c \
				lib/common.c \
				lib/channel.c \
				lib/log.c \
				lib/service.c
LIBRARY_HEADERS=$(patsubst %.c,%.h,${LIBRARY_SOURCES})
LIBRARY_OBJECTS=$(patsubst %.c,%.o,${LIBRARY_SOURCES})

EXECUTABLES=sd-discover \
			sd-discover-responder \
			sd-genkey \
			sd-query \
			sd-query-responder \
			sd-connect \
			sd-connect-responder
EXECUTABLES_LIBS=libsodium libprotobuf-c
EXECUTABLES_CFLAGS=${CFLAGS} -I. $(shell pkg-config --cflags ${EXECUTABLES_LIBS})
EXECUTABLES_LDFLAGS=${LDFLAGS} $(shell pkg-config --libs ${EXECUTABLES_LIBS})

TEST_SOURCES=test/test.c \
			 test/cfg.c \
			 test/channel.c
TEST_OBJECTS=$(patsubst %.c,%.o,${TEST_SOURCES})
TEST_LIBS=cmocka ${EXECUTABLES_LIBS}
TEST_CFLAGS=${CFLAGS} -I. $(shell pkg-config --cflags ${TEST_LIBS})
TEST_LDFLAGS=${LDFLAGS} $(shell pkg-config --libs ${TEST_LIBS})

.SUFFIXES: .proto .pb-c.c .pb-c.h .pb-c.o
.PRECIOUS: %.pb-c.c %.pb-c.h

.PHONY: all clean test

all: ${EXECUTABLES}

clean:
	@echo "Cleaning protobufs..."
	@rm ${PROTOBUF_HEADERS} 2>/dev/null || true
	@rm ${PROTOBUF_SOURCES} 2>/dev/null || true
	@echo "Cleaning objects..."
	@rm ${LIBRARY_OBJECTS} 2>/dev/null || true
	@rm ${PROTOBUF_OBJECTS} 2>/dev/null || true
	@rm ${TEST_OBJECTS} 2>/dev/null || true
	@echo "Cleaning executables..."
	@rm ${EXECUTABLES} 2>/dev/null || true
	@rm sd-test 2>/dev/null || true

$(EXECUTABLES): _CFLAGS=${EXECUTABLES_CFLAGS}
$(EXECUTABLES): _LDFLAGS=${EXECUTABLES_LDFLAGS}
$(EXECUTABLES): %: ${PROTOBUF_OBJECTS} ${LIBRARY_OBJECTS} %.o
	@echo "LD $@"
	@$(CC) ${_LDFLAGS} -o "$@" $^

test: sd-test
	./sd-test
sd-test: _CFLAGS=${TEST_CFLAGS}
sd-test: _LDFLAGS=${TEST_LDFLAGS}
sd-test: ${TEST_OBJECTS} ${LIBRARY_OBJECTS}
	@echo "LD $@"
	@$(CC) ${_LDFLAGS} -o "$@" $^

%.o: %.c %.h
	@echo "CC $@"
	@$(CC) ${_CFLAGS} ${CPPFLAGS} -c -o "$@" "$<"
%.o: %.c
	@echo "CC $@"
	@$(CC) ${_CFLAGS} ${CPPFLAGS} -c -o "$@" "$<"
%.pb-c.c: %.proto
	@echo "PB $@"
	@protoc-c --c_out . $^
