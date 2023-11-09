# This is a simple Makefile example with a 'clean' target

all: read logger preload

read:
	gcc read.c -o read

logger:
	gcc -Wall -fPIC -shared -o logger.so logger.c -ldl -lcrypto

preload:
	LD_PRELOAD=./logger.so ./read

clean:
	rm -f read logger.so
