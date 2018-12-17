#define _GNU_SOURCE
#include "bpf_load.h"
#include "common.h"
#include "cjson/cJSON.h"
#include "bpf_util.h"

#include <linux/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    int fd, i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host-num> <save-prefix>\n", argv[0]);
        return 1;
    }

    uint16_t host_num = atoi(argv[1]);
    uint8_t save_prefix = atoi(argv[2]);

    if (format_map_paths(host_num, save_prefix))
        return 1;

    for (i=0; i<NUM_MAP_PINS; i++) {
        fd = bpf_obj_get(map_pins[i].path_formatted);
        if (fd <= 0) {
            fprintf(stderr,
                "ERR: Failed to load map pin %s(%d): %s\n",
                map_pins[i].path_formatted, errno, strerror(errno)
            );
            return 1;
        }
        map_pin_fds[i] = fd;
    }

    char *string = NULL;
    cJSON *data = cJSON_CreateObject();

    for (i=0; i<NUM_MAP_PINS; i++) {
        cJSON *map_data = cJSON_AddObjectToObject(data, map_pins[i].name);
        (map_pins[i].dump)(map_pin_fds[i], map_data, i);
    }

    string = cJSON_Print(data);
    printf("%s\n", string);

    cJSON_Delete(data);

    return 0;
}
