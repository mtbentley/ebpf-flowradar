xdp bpf flowradar
===
This is mostly not implemented, just some code around parsing packets.

The code has comments on what stuff does.

Testing
---
1. Run mininet: `sudo mn --topo tree,2,2`
2. Setup the network namespace for h1: `make setup`
3. Compile: `make`
4. Load the program: `make load`. This is where you migth get verifier errors
5. Monitor the output (from `bpf_debug()`): `sudo cat /sys/kernel/debug/tracing/trace_pipe`

Requirements
---
kernel: You will need a modern kernel.  I'm developing with `4.18.0-11-generic`

apt:
```
sudo apt install -y build-essential libelf-dev binutils-dev make gcc \
libssl-dev bc libelf-dev libcap-dev clang gcc-multilib llvm libncurses5-dev \
git pkg-config libmnl0 bison flex graphviz mininet
```

bpftool is nice:
1. Get kernel source
2. `cd <source>/tools/bpf/bpftool/`
3. `make`
4. copy `bpftool` to whereever you put binaries
