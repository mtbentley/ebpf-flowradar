CFLAGS:=-g -O2 -Wall -Wextra -target bpf
.PHONY: all load unload clean setup

all: xdp-example.o

xdp-example.o: xdp-example.c bpf_helpers.h
	clang $(CFLAGS) -c xdp-example.c -o xdp-example.o

load: xdp-example.o unload
	sudo ip netns exec h1 ip l set dev h1-eth0 xdp obj xdp-example.o verbose

unload:
	sudo ip netns exec h1 ip l set dev h1-eth0 xdp off || true

clean: unload
	sudo rm /var/run/netns/h1

setup:
	sudo ln -s /proc/$(shell pgrep -f h1)/ns/net /var/run/netns/h1

dump: xdp-example.o
	llvm-objdump -S xdp-example.o
