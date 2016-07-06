SRCS=nacl.c \
	yajl.c \
	ev.c \
	nrc.c

BINS=pack unpack main
.PHONY: main

OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -g -D__MAIN__ -DDEBUG
CLIBS=-lm

unpack: unpack.o $(OBJS)
	cc $^ $(CLIBS) -o $@
pack: pack.o $(OBJS)
	cc $^ $(CLIBS) -o $@
main: main.o $(OBJS) key.h
	cc $^ $(CLIBS) -o $@

key.h: key.def.h
	cp $< $@

run: main
	./main

v: main
	valgrind --leak-check=full --show-reachable=yes ./main

%.o: %.c Makefile
	cc $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) main pack
