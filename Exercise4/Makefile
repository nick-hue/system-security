all: net_monitor run

net_monitor: net_monitor.c 
	gcc net_monitor.c -o net_monitor

run: net_monitor
	./net_monitor

clean:
	rm -rf net_monitor
