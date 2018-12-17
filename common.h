#include <stdint.h>
#include <linux/types.h>
#include <stdio.h>
#include "cjson/cJSON.h"
#include "bpf_util.h"
#include "bpf_load.h"
#include "data.h"

#include <linux/bpf.h>

#define NUM_MAP_PINS 9
#define MAX_PATH_FORMATTED 128

char bpf_pin_folder[MAX_PATH_FORMATTED];

#define KEY_NAME_MAX 32
#define NUM_VALUE_MAX 128
char key_name[KEY_NAME_MAX];
char num_value[NUM_VALUE_MAX];
char num_str[8];
int map_pin_fds[NUM_MAP_PINS];

struct map_pin_info {
    char *name;
    int (*format_value)(void *, char *, int);
    int (*format_key)(void *, char *, int);
    void (*dump)(int map_fd, cJSON *, int index);
    char path_formatted[MAX_PATH_FORMATTED];
};

struct map_pin_info map_pins[NUM_MAP_PINS];

int format_long_hex(void *data, char *buf, int len) {
    uint64_t *d = data;
    return snprintf(buf, len, "0x%lx", (unsigned long)*d);
}

int format_int_hex(void *data, char *buf, int len) {
    uint32_t *d = data;
    return snprintf(buf, len, "0x%x", (unsigned int)*d);
}

int format_short_hex(void *data, char *buf, int len) {
    uint16_t *d = data;
    return snprintf(buf, len, "0x%04hx", (unsigned short)*d);
}

int format_host_info(void *data, char *buf, int len) {
    struct host_info *hi = data;
    return snprintf(buf, len, "host=0x%lx", (unsigned long)hi->host);
}

int format_flow_info(void *data, char *buf, int len) {
    int c;
    char *curr = buf;
    struct flow_info *fi = data;
    struct five_tuple *ft = &(fi->ft);
    c = snprintf(
        curr, len,
        "saddr=0x%x,daddr=0x%x,",
        ft->saddr, ft->daddr
    );
    curr = buf + c;
    c += snprintf(
        curr, len-c,
        "sport=0x%x,dport=0x%x,",
        ft->sport, ft->dport
    );
    curr = buf + c;
    c += snprintf(
        curr, len-c,
        "proto=0x%x,",
        ft->proto
    );
    curr = buf + c;
    c += snprintf(
        curr, len-c,
        "flow_count=0x%x,packet_count=0x%x",
        fi->flow_count, fi->packet_count
    );
    return c;
}

void dump_hash64(int map_fd, cJSON *map_data, int index) {
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

void dump_hash_flowinfo(int map_fd, cJSON *map_data, int index) {
    uint32_t key = -1, next_key;
    unsigned int nr_cpus = bpf_num_possible_cpus();
    unsigned int i;
    struct flow_info values[nr_cpus];
    cJSON *cpu_objects[nr_cpus];

    memset(values, 0, sizeof(values));

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
            if (values[i].flow_count) {
                if ((map_pins[index].format_key)(&key, key_name, KEY_NAME_MAX) <= 0) {
                    fprintf(stderr, "ERR: Failed to format key %d\n", i);
                    continue;
                }
                if ((map_pins[index].format_value)(
                        &values[i], num_value, NUM_VALUE_MAX
                    ) <= 0) {
                    fprintf(stderr, "ERR: failed to format value for %d\n", i);
                    continue;
                }

                if (cJSON_AddStringToObject(cpu_objects[i], key_name, num_value) == NULL)
                    fprintf(
                        stderr,
                        "ERR: Failed to add key %x to json\n",
                        key
                    );
            }
        }
    }

    for (i=0; i<nr_cpus; i++) {
        snprintf(num_str, 8, "%d", i);
        cJSON_AddItemToObject(map_data, num_str, cpu_objects[i]);
     }
}

struct map_pin_info map_pins[NUM_MAP_PINS] = {
    {
        .name = "bloomfilter",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
        .dump = dump_hash64,
    },
    {
        .name = "flow_info",
        .format_value = format_flow_info,
        .format_key = format_int_hex,
        .dump = dump_hash_flowinfo,
    },
    {
        .name = "eth_proto_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
        .dump = dump_hash64,
    },
    {
        .name = "ip_proto_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
        .dump = dump_hash64,
    },
    {
        .name = "sport_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
        .dump = dump_hash64,
    },
    {
        .name = "dport_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
        .dump = dump_hash64,
    },
    {
        .name = "sip_count",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
        .dump = dump_hash64,
    },
    {
        .name = "dip_count",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
        .dump = dump_hash64,
    },
    {
        .name = "host_info",
        .format_value = format_host_info,
        .format_key = format_int_hex,
        .dump = dump_hash64,
    },
};

int format_map_paths(uint16_t host_num, uint8_t prefix_num) {
    char prefix_str[MAX_PATH_FORMATTED];
    for (int i=0; i<NUM_MAP_PINS; i++) {
        if (snprintf(
            prefix_str, MAX_PATH_FORMATTED,
            "/sys/fs/bpf/%hhu/%u/", prefix_num, host_num
        ) <= 0) {
            fprintf(stderr, "WARN: failed to format map path\n");
            return -1;
        }
        if (snprintf(
            map_pins[i].path_formatted, MAX_PATH_FORMATTED,
            "%s%s", prefix_str, map_pins[i].name
        ) <= 0) {
            fprintf(stderr, "WARN: falied to format map path\n");
            return -1;
        }
    }
    snprintf(
        bpf_pin_folder, MAX_PATH_FORMATTED, "/sys/fs/bpf/%hhu/%u",
        prefix_num, host_num);

    return 0;
}
