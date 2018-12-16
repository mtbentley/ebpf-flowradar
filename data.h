#include <stdint.h>
#include <linux/types.h>

#if defined(__clang__)
#define PACKED __attribute__((__packed__))
#elif defined(__GNUC__) || defined(__GNUG__)
#define PACKED __attribute__((packed))
#endif

struct PACKED host_info {
    uint64_t host;
};

/* Information on the "five tuple" used to identify flows */
struct PACKED five_tuple {
    __be32 saddr;
    __be32 daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t proto;
};

struct PACKED flow_info {
    struct five_tuple ft;
    uint16_t flow_count;
    uint32_t packet_count;
    char pad[5];
};

