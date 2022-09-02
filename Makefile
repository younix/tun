.PHONY: all run

all: tun
run: tun
	./tun /dev/tun0 /dev/tun1
