#define _GNU_SOURCE
#include "bpf_load.h"

#include <linux/bpf.h>

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <sched.h>


/* Note: these need to be kept up to date (including the correct order) with
 * the maps in _kern.c
 * TODO: make a macro that does this automagically?
 */
#define NUM_MAP_PINS 6
static const char *map_pins[NUM_MAP_PINS] = {
    "/sys/fs/bpf/eth_proto_count",
    "/sys/fs/bpf/ip_proto_count",
    "/sys/fs/bpf/sport_count",
    "/sys/fs/bpf/dport_count",
    "/sys/fs/bpf/sip_count",
    "/sys/fs/bpf/dip_count",
};


int main(int argc, char *argv[]) {
    char filename[256];
    int ifindex;
    char *ifname;
    char *nspath;
    int nsfd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <ns-path>\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    nspath = argv[2];

    snprintf(filename, sizeof(filename), "%s.o", argv[0]);

    // Load the bpf file.  The fd will end up in prog_fd[0]
    if (load_bpf_file(filename)) {
        fprintf(
            stderr,
            "ERR: failed to load file %s: %s\n",
            filename, bpf_log_buf
        );
        return 1;
    }

    if (!prog_fd[0]) {
        fprintf(
            stderr,
            "ERR: load_bpf_file(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    for (int i=0; i<NUM_MAP_PINS; i++) {
        if (map_fd[i] <= 0) {
            fprintf(
                stderr,
                "ERR: map %d(%s) failed to load: %d\n",
                i, map_pins[i], map_fd[i]
            );
            return 1;
        }
        // Try to pin the i-th map_fd to the filesystem
        if (bpf_obj_pin(map_fd[i], map_pins[i])) {
            fprintf(
                stderr,
                "ERR: Cannot pin map: err(%d):%s\n",
                errno, strerror(errno)
            );
            return 1;
        }
    }

    nsfd = open(nspath, O_RDONLY);
    if (nsfd < 0) {
        fprintf(
            stderr,
            "ERR: failed to open nspath(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    // Set the namespace
    if (setns(nsfd, 0)) {
        fprintf(
            stderr,
            "ERR: failed to join ns(%d): %s\n",
            errno, strerror(errno)
        );
        return 1;
    }

    // Lookup the interface index
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERR: unknown ifname(%d): %s", errno, strerror(errno));
        return 1;
    }

    // Add the xdp program to the interface
    if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
        fprintf(stderr, "ERR: failed to set prog\n");
        return 1;
    }

    return 0;
}
