LIBS=libsodium libprotobuf-c
CFLAGS=-I. -Iproto -Ilib -Wall -Wextra -pedantic -std=c99 -D_POSIX_SOURCE $(shell pkg-config --cflags ${LIBS})
CPPFLAGS=-DVERSION=\"0.0.1\"
LDFLAGS=$(shell pkg-config --libs ${LIBS})

PROTOBUF=proto/announce.proto \
		 proto/discover.proto
PROTOBUF_SOURCES=$(patsubst %.proto,%.pb-c.c,${PROTOBUF})
PROTOBUF_HEADERS=$(patsubst %.proto,%.pb-c.h,${PROTOBUF})
PROTOBUF_OBJECTS=$(patsubst %.proto,%.pb-c.o,${PROTOBUF})

LIBRARY_SOURCES=lib/common.c \
				lib/log.c \
				lib/schannel.c
LIBRARY_HEADERS=$(patsubst %.c,%.h,${LIBRARY_SOURCES})
LIBRARY_OBJECTS=$(patsubst %.c,%.o,${LIBRARY_SOURCES})

EXECUTABLES=sd-discover sd-discover-responder sd-query sd-query-responder sd-connect sd-connect-responder

.SUFFIXES: .proto .pb-c.c .pb-c.h .pb-c.o
.PRECIOUS: %.pb-c.c %.pb-c.h

.PHONY: all clean

all: ${EXECUTABLES}

clean:
	@echo "Cleaning protobufs..."
	@rm ${PROTOBUF_HEADERS} 2>/dev/null || true
	@rm ${PROTOBUF_SOURCES} 2>/dev/null || true
	@echo "Cleaning objects..."
	@rm ${LIBRARY_OBJECTS} 2>/dev/null || true
	@rm ${PROTOBUF_OBJECTS} 2>/dev/null || true
	@echo "Cleaning executables..."
	@rm ${EXECUTABLES} 2>/dev/null || true

$(EXECUTABLES): %: ${PROTOBUF_OBJECTS} ${LIBRARY_OBJECTS} %.o
	@echo "LD $@"
	@gcc -o "$@" $^ ${LDFLAGS}

%.o: %.c %.h
	@echo "CC $@"
	@gcc ${CFLAGS} ${CPPFLAGS} -c -o "$@" "$<"
%.o: %.c
	@echo "CC $@"
	@gcc ${CFLAGS} ${CPPFLAGS} -c -o "$@" "$<"
%.pb-c.c: %.proto
	@echo "PB $@"
	@protoc-c --c_out . $^
