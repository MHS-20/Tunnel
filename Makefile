CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CPPFLAGS += -D_GNU_SOURCE -Isrc
LDLIBS  += -lsodium -lutil

LIB_SRC := $(filter-out src/client_main.c src/server_main.c,$(wildcard src/*.c))
LIB_OBJ := $(LIB_SRC:.c=.o)
TESTS   := $(patsubst %.c,%,$(wildcard tests/test_*.c))

.PHONY: all test unit e2e clean
all: tunnel tunneld

libtunnel.a: $(LIB_OBJ)
	$(AR) rcs $@ $^

tunnel: src/client_main.o libtunnel.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tunneld: src/server_main.o libtunnel.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tests/test_%: tests/test_%.c tests/check.h libtunnel.a
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< libtunnel.a $(LDLIBS)

unit: $(TESTS)
	@set -e; for t in $(TESTS); do ./$$t; done

e2e: all
	./tests/e2e.sh

test: unit e2e

src/%.o: src/%.c $(wildcard src/*.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o libtunnel.a tunnel tunneld $(TESTS)
