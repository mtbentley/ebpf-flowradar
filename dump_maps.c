#define _GNU_SOURCE
#include "bpf_load.h"
#include "common.h"

#include <linux/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int map_pin_fds[NUM_MAP_PINS];

void dump_hash(int map_fd) {
    uint32_t key = 0, next_key;
    uint64_t value;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        key = next_key;
        if ((bpf_map_lookup_elem(map_fd, &key, &value)) != 0) {
            fprintf(
                stderr,
                "ERR: failed to read key %x from map(%d): %s\n",
                key, errno, strerror(errno)
            );
        }
        if (value)
            printf("%x: %lu\n", key, value);
    }
}


int main(int argc, char *argv[]) {
    int fd, i;
    for (i=0; i<NUM_MAP_PINS; i++) {
        fd = bpf_obj_get(map_pins[i]);
        if (fd <= 0) {
            fprintf(stderr,
                "ERR: Failed to load map pin %s(%d): %s\n",
                map_pins[i], errno, strerror(errno)
            );
            return 1;
        }
        map_pin_fds[i] = fd;
    }

    for (i=0; i<NUM_MAP_PINS; i++) {
        printf("Dumping stats from %s\n", map_pins[i]);
        dump_hash(map_pin_fds[i]);
        printf("\n");
    }

    return 0;
}
