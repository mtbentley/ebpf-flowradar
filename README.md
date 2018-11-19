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

Programming
---
Writing for the bpf target is not like normal programming.  Some things to keep
in mind:

1. The verifier might yell at you.  The error messages are often anoying, but
they often mean you need to add explicit bounds checks and make sure variables
are initialized.  Even if you know the code is correct, you need to "prove it"
2. No loops.  If you have a "loop" with a constant size, you can add `#pragma
unroll` on the line before it.  Keep in mind that this will tell the compiler
to unroll it, so it may take up a lot of space
3. No function calls.  We have "function calls" by adding `static
__always_inline` before every function.  Instead of function calls, it just
copies the whole function body to the call location

Debugging
---
You can get the compiled bytecode by running `make dump`.  This calls
`llvm-objdump` on the object file, and includes the source lines above assembly
lines (as long as you leave `-g` in the CFLAGS)

You can list the maps with `bpftool map`, and dump the contents of a map with
`bpftool map dump id <id>`.  
TODO: make a tool to pin maps and read them more easily

hash function
---
`test-hash.c` exists to test the hash function.  `analyze.py` takes the output
of that and produces an histogram.

Usage:
1. `make test-hash`
2. `./test-hash saddr-start saddr-end daddr-start daddr-end sport-start sport-end dport-start dport-end proto-start proto-end hostnonce-start hostnonce-end k-start k-end`
 for example: `./test-hash 0x20000000 0x2000ffff 0x10000000 0x10000005 1230 1231 80 81 0 1 0 1 0 1 > ../hashes`
3. `python3 -m venv venv; source venv/bin/activate; pip install -r requirements.txt`
4. `./analyze.py ../hashes ../hashes.svg`

TODO
---
- Figure out a better way to export maps to userspace
- Implement flowradar - how to store the data we need to store?
- Investigate using `bpf_xdp_adjust_head` rather than l3/l4 offset (see 
https://patchwork.ozlabs.org/patch/702198/ )
- IPv6 support

FlowRadar
---
The paper: https://www.usenix.org/system/files/conference/nsdi16/nsdi16-paper-li-yuliang.pdf

XDP BPF side:
- Bloom filter with m bits
- Each packet (5-tuple) hashed to k (/m) bits in filter
- Count Table: stores 5-tuple (13 bytes), flow count (2 bytes?), packet count
(4 bytes?)
- Each packet: for each of k hash results, increments packet count in count
table
- If Bloom filter indicates New Flow, store (table 5-tuple)xor(packet 5-tuple)
in table 5-tuple and increment flow count for each of k hash results, and set
all bits in bloom filter

Bloom filter size: `m bits = (m/8) bytes`
Count table size: `((13 + 2 + 4)*m) bytes`
Hash result = `hash(packet, host-nonce, k) % m`

host-nonce: per host magic number that's mixed into hash to provide different
hashes per host (important for decoding flow counts)

Random math
---
From wikipedia (https://en.wikipedia.org/wiki/Bloom\_filter):

Optimal number of hash functions: `k=(m/n)ln(2)`  
m: filter bits  
n: number of flows  
`ln(2) ~= 0.69 ~= 0.5` 

minimum k: 1  
given ^^, minimum m/n ratio: 2/1

Reasonable memory maximum: 16MB  
memory required ~= `m*20B` (B=bytes)  
`16777216 = m*20`  
`m = 838912`  
Bloom filter bytes: 104864, `uint64_t`s: 13108 :o  

max flows: 8192?  
`k = (838912/8192)*0.69 ~= 71`  
^^ is that too much? (Note that the current code does compile and load w/ k=71)

Actual reasonable bloom filter size: `2**16 = UINT16_MAX+1` ==> ~1.25MB  
`m = 65536`  
Bloom filter bytes: 65536, `uint64_t`s: 1024

max flows: 8192?  
`k = (65536/8192)*ln(2) ~= 6`  
^^ Much better, but maybe too few?

Given 10Gb interface, 64byte minimum packet: max pps = 20971520 ~= 21,000,000  
Time to process one packet: 1s/20971520 ~= 47ns :o  
Modern CPU: 2Ghz = 2,000,000,000 inst/sec => ~95 instructions / packet :o

Reasonable MTU: 1500 bytes  ==> pps = 894785 ~= 900,000  
Time to process one packet: 1s/894785 ~= 1.1 microseconds  
2Ghz CPU => ~2200 instructions / packet

TODO: figure out the mapping from BPF instructions to CPU instructions?
