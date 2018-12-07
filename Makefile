LINUX_SOURCE=../linux
# ^^ is there a better way to do this??
IFLAGS:=-I$(LINUX_SOURCE)/tools/lib -I$(LINUX_SOURCE)/tools/perf -I$(LINUX_SOURCE)/tools/include

CFLAGS:=-g -O2 -Wall -Wextra
.PHONY: all load unload clean setup

all: xdp-flowradar.o

xdp-flowradar.o: xdp-flowradar.c bpf_helpers.h
	clang $(CFLAGS) -target bpf -c xdp-flowradar.c -o xdp-flowradar.o

bpf_load.o: bpf_load.c bpf_load.h
	clang $(CFLAGS) $(IFLAGS) -c bpf_load.c -o bpf_load.o

test-hash: test-hash.c xdp-flowradar.c
	clang $(CFLAGS) test-hash.c -o test-hash

load: xdp-flowradar.o unload
	sudo ip netns exec h1 ip l set dev h1-eth0 xdp obj xdp-flowradar.o verbose

unload:
	sudo ip netns exec h1 ip l set dev h1-eth0 xdp off || true

clean: unload
	sudo rm /var/run/netns/h1 || true
	rm xdp-flowradar.o || true
	rm test-hash || true

setup: clean
	sudo ln -s /proc/$(shell pgrep -f h1)/ns/net /var/run/netns/h1

dump: xdp-flowradar.o
	llvm-objdump -S xdp-flowradar.o
