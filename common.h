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
