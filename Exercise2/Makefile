all: logger acmonitor test_aclog

logger:
	gcc -Wall -fPIC -shared -o logger.so logger.c -ldl -lcrypto

preload:
	LD_PRELOAD=./logger.so ./

acmonitor: 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so symlink/** file_logging.log *.txt test_aclog acmonitor
