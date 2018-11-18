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
