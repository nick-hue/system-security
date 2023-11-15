# This is a simple Makefile example with a 'clean' target

all: read logger preload

read:
	gcc -Wall -o read  read.c

logger:
	gcc -Wall -fPIC -shared -o logger.so logger.c -ldl -lcrypto

preload:
	LD_PRELOAD=./logger.so ./read

preload_w:
	LD_PRELOAD=./logger.so ./write

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor
	./acmonitor

clean:
	rm -f read logger.so symlink/** file_logging.log write.txt write2.txt
