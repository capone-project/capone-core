CC=clang
CFLAGS=-g -ggdb -O0 -Werror -Wall -Wextra -pedantic -std=c89 -D_POSIX_SOURCE -D_DEFAULT_SOURCE -fsanitize=address
LDFLAGS=-g -ggdb
CPPFLAGS=-DVERSION=\"0.0.1\"
