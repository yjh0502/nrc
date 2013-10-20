SRCS:=nacl.c \
	yajl.c \
	ev.c \
	nrc.c \
	main.c

.PHONY: main

OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -O2 -g
CLIBS=-lm

v: main
	valgrind --leak-check=full --show-reachable=yes ./main

run: main
	./main

main: $(OBJS) $(SRCS)
	gcc $(OBJS) $(CLIBS) -o main

%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -r $(OBJS) main
