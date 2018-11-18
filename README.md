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
