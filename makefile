LIBS=libsodium libprotobuf-c
CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_SOURCE $(shell pkg-config --cflags ${LIBS})
LDFLAGS=$(shell pkg-config --libs ${LIBS})

PROTOBUF=announce.proto \
		 discover.proto
PROTOBUF_SOURCES=$(patsubst %.proto,%.pb-c.c,${PROTOBUF})
PROTOBUF_HEADERS=$(patsubst %.proto,%.pb-c.h,${PROTOBUF})
PROTOBUF_OBJECTS=$(patsubst %.proto,%.pb-c.o,${PROTOBUF})

CLIENT_SOURCES=client.c \
			   common.c \
			   log.c
CLIENT_HEADERS=common.h \
			   log.h
CLIENT_OBJECTS=$(patsubst %.c,%.o,${CLIENT_SOURCES})

SERVICE_SOURCES=common.c \
				log.c \
				service.c
SERVICE_HEADERS=common.h \
				log.h
SERVICE_OBJECTS=$(patsubst %.c,%.o,${SERVICE_SOURCES})

EXECUTABLES=client service

.PHONY: all clean
.SUFFIXES: .proto .pb-c.c .pb-c.h
.PRECIOUS: %.pb-c.c %.pb-c.h

all: ${EXECUTABLES}

clean:
	@echo "Cleaning protobufs..."
	@rm ${PROTOBUF_HEADERS} 2>/dev/null || true
	@rm ${PROTOBUF_SOURCES} 2>/dev/null || true
	@rm ${PROTOBUF_OBJECTS} 2>/dev/null || true
	@echo "Cleaning objects..."
	@rm ${CLIENT_OBJECTS} 2>/dev/null || true
	@rm ${SERVICE_OBJECTS} 2>/dev/null || true
	@echo "Cleaning executables..."
	@rm ${EXECUTABLES} 2>/dev/null || true

client: ${PROTOBUF_OBJECTS} ${CLIENT_OBJECTS}
	@echo "LD $@"
	@gcc -o "$@" $^ ${LDFLAGS}

service: ${PROTOBUF_OBJECTS} ${SERVICE_OBJECTS}
	@echo "LD $@"
	@gcc -o "$@" $^ ${LDFLAGS}

%.pb-c.c: %.proto
	@echo "PB $@"
	@protoc-c --c_out . $^
%.o: %.c ${CLIENT_HEADERS} ${SERVICE_HEADERS}
	@echo "CC $@"
	@gcc ${CFLAGS} -c -o "$@" "$<"
