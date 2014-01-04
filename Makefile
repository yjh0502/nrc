SRCS:=nacl.c \
	yajl.c \
	ev.c \
	nrc.c \
	main.c

.PHONY: main

OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -g -D__NRC_MAIN__
CLIBS=-lm -lrt

run: main
	./main

v: main
	valgrind --leak-check=full --show-reachable=yes ./main

main: $(OBJS) $(SRCS)
	cc $(OBJS) $(CLIBS) -o main

%.o: %.c
	cc $(CFLAGS) -c $< -o $@

clean:
	rm -r $(OBJS) main
