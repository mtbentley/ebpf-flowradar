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

int map_pin_fds[NUM_MAP_PINS];
#define KEY_NAME_MAX 32
#define NUM_VALUE_MAX 128
char key_name[KEY_NAME_MAX];
char num_value[NUM_VALUE_MAX];
char num_str[8];

void dump_hash(int map_fd, cJSON *map_data, int index) {
    uint32_t key = -1, next_key;
    unsigned int nr_cpus = bpf_num_possible_cpus();
    unsigned int i;
    uint64_t values[nr_cpus];
    cJSON *cpu_objects[nr_cpus];

    for (i=0; i<nr_cpus; i++)
        cpu_objects[i] = cJSON_CreateObject();


    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        key = next_key;
        if ((bpf_map_lookup_elem(map_fd, &key, &values)) != 0) {
            fprintf(
                stderr,
                "ERR: failed to read key %x from map(%d): %s\n",
                key, errno, strerror(errno)
            );
        }
        for (i=0; i<nr_cpus; i++) {
            if (values[i]) {
                if ((map_pins[index].format_key)(&key, key_name, KEY_NAME_MAX) <= 0)
                    continue;
                if ((map_pins[index].format_value)(
                        &values[i], num_value, NUM_VALUE_MAX
                    ) <= 0)
                    continue;

                if (cJSON_AddStringToObject(cpu_objects[i], key_name, num_value) == NULL)
                    fprintf(
                        stderr,
                        "ERR: Failed to add key(value) %x(%lu) to json\n",
                        key, values[i]
                    );
            }
        }
    }

    for (i=0; i<nr_cpus; i++) {
        snprintf(num_str, 8, "%d", i);
        cJSON_AddItemToObject(map_data, num_str, cpu_objects[i]);
     }
}


int main(int argc, char *argv[]) {
    int fd, i;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host-num>\n", argv[0]);
        return 1;
    }

    uint16_t host_num = atoi(argv[1]);

    format_map_paths(host_num);

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
        dump_hash(map_pin_fds[i], map_data, i);
    }

    string = cJSON_Print(data);
    printf("%s\n", string);

    cJSON_Delete(data);

    return 0;
}
