OS:=$(shell uname)
CC=cc
PREFIX=/usr/local
FILES=passman.c third-party/monocypher.c
# passman only supports Linux and BSD, arc4random is native on BSD, and on Linux there's a port included in the source tree
ifeq ($(OS), Linux)
	FILES += third-party/arc4random.c third-party/arc4random_uniform.c
endif
all:
	$(CC) -O2 -march=native $(FILES) -o passman

debug:
	clang -fsanitize=address -O1 -fno-omit-frame-pointer -g $(FILES) -o passman

clean:
	rm passman

install:
	cp passman $(PREFIX)/bin/
