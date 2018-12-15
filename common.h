#include <stdint.h>
#include <linux/types.h>
#include <stdio.h>

#define NUM_MAP_PINS 9
#define MAX_PATH_FORMATTED 128

char bpf_pin_folder[MAX_PATH_FORMATTED];

struct __attribute__((__packed__)) host_info {
    uint64_t host;
};

struct map_pin_info {
    char *name;
    int (*format_value)(void *, char *, int);
    int (*format_key)(void *, char *, int);
    char path_formatted[MAX_PATH_FORMATTED];
};

/* Information on the "five tuple" used to identify flows */
struct __attribute__((__packed__)) five_tuple {
    __be32 saddr;
    __be32 daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

struct __attribute__((__packed__)) flow_info {
    struct five_tuple ft;
    uint16_t flow_count;
    uint32_t packet_count;
};

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

struct map_pin_info map_pins[NUM_MAP_PINS] = {
    {
        .name = "bloomfilter",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
    },
    {
        .name = "flow_info",
        .format_value = format_flow_info,
        .format_key = format_int_hex,
    },
    {
        .name = "eth_proto_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
    },
    {
        .name = "ip_proto_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
    },
    {
        .name = "sport_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
    },
    {
        .name = "dport_count",
        .format_value = format_long_hex,
        .format_key = format_short_hex,
    },
    {
        .name = "sip_count",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
    },
    {
        .name = "dip_count",
        .format_value = format_long_hex,
        .format_key = format_int_hex,
    },
    {
        .name = "host_info",
        .format_value = format_host_info,
        .format_key = format_int_hex,
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
