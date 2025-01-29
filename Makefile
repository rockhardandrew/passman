OS:=$(shell uname)
CC=cc
PREFIX=/usr/local
CFLAGS=-static -Os -march=native
FILES=passman.c third-party/monocypher.c
# passman only supports Linux and BSD, arc4random is native on BSD, and on Linux there's a port included in the source tree
ifeq ($(OS), Linux)
	FILES += third-party/arc4random.c third-party/arc4random_uniform.c
endif
all:
	$(CC) $(CFLAGS) $(FILES) -o passman
clean:
	rm passman
install:
	cp passman $(PREFIX)/bin/
