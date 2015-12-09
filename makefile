LIBS=libsodium libprotobuf-c
CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_SOURCE $(shell pkg-config --cflags ${LIBS})
LDFLAGS=$(shell pkg-config --libs ${LIBS})

CLIENT_SOURCES=client.c \
			   common.c \
			   log.c \
			   announce.pb-c.c \
			   probe.pb-c.c
CLIENT_HEADERS=common.h \
			   log.h
CLIENT_OBJECTS=$(patsubst %.c,%.o,${CLIENT_SOURCES})

SERVICE_SOURCES=common.c \
				log.c \
				service.c \
				announce.pb-c.c \
				probe.pb-c.c
SERVICE_HEADERS=common.h \
				log.h
SERVICE_OBJECTS=$(patsubst %.c,%.o,${SERVICE_SOURCES})

EXECUTABLES=client service

.PHONY: all clean

all: ${EXECUTABLES}

clean:
	@echo "Cleaning objects..."
	@rm ${CLIENT_OBJECTS} 2>/dev/null || true
	@rm ${SERVICE_OBJECTS} 2>/dev/null || true
	@echo "Cleaning executables..."
	@rm ${EXECUTABLES} 2>/dev/null || true

client: ${CLIENT_OBJECTS}
	@echo "LD $@"
	@gcc -o "$@" $^ ${LDFLAGS}

service: ${SERVICE_OBJECTS}
	@echo "LD $@"
	@gcc -o "$@" $^ ${LDFLAGS}

%.pb-c.c: %.proto
	@echo "PB $@"
	@protoc-c --c_out . $^

%.o: %.c ${CLIENT_HEADERS} ${SERVICE_HEADERS}
	@echo "CC $@"
	@gcc ${CFLAGS} -c -o "$@" "$<"
