CFLAGS=-Wall -Wextra -pedantic -std=c99

CLIENT_SRC=common.c \
		   client.c
CLIENT_OBJ=$(patsubst %.c,%.o,${CLIENT_SRC})

SERVICE_SRC=common.c \
			service.c
SERVICE_OBJ=$(patsubst %.c,%.o,${SERVICE_SRC})

EXECUTABLES=client service

.PHONY: all clean

all: ${EXECUTABLES}

clean:
	@echo "Cleaning objects..."
	@rm ${CLIENT_OBJ} 2>/dev/null || true
	@rm ${SERVICE_OBJ} 2>/dev/null || true
	@echo "Cleaning executables..."
	@rm ${EXECUTABLES} 2>/dev/null || true

client: ${CLIENT_OBJ}
	@echo "LD $@"
	@gcc -o "$@" $^

service: ${SERVICE_OBJ}
	@echo "LD $@"
	@gcc -o "$@" $^

%.o: %.c common.h 
	@echo "CC $@"
	@gcc ${CFLAGS} -c -o "$@" "$<"
