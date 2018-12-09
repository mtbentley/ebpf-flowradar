#include "xdp-flowradar_kern.c"
#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include <stdlib.h>

uint16_t do_hash(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto, uint16_t host, uint8_t k) {
    struct five_tuple ft = {
        .saddr = saddr,
        .daddr = daddr,
        .sport = sport,
        .dport = dport,
        .proto = proto,
    };

    uint16_t h = hash(host, k, &ft);
    return h;
}


int main(int argc, char *argv[]) {
    if (argc < 15) {
        printf("Usage: %s saddr-start saddr-end daddr-start daddr-end sport-start sport-end dport-start dport-end proto-start proto-end hostnonce-start hostnonce-end k-start k-end\n", argv[0]);
        return 1;
    }

    uint32_t inputs[14];
    for (int i=0; i<14; i++) {
        inputs[i] = strtol(argv[i+1], NULL, 0);
    }
    uint16_t h;

    for (uint32_t saddr=inputs[0]; saddr<=inputs[1]; saddr++) {
        for (uint32_t daddr=inputs[2]; daddr<=inputs[3]; daddr++) {
            for (uint16_t sport=inputs[4]; sport<=inputs[5]; sport++) {
                for (uint16_t dport=inputs[6]; dport<=inputs[7]; dport++) {
                    for (uint8_t proto=inputs[8]; proto<=inputs[9]; proto++) {
                        for (uint16_t host=inputs[10]; host<=inputs[11]; host++) {
                            for (int8_t k=inputs[12]; k<=inputs[13]; k++) {
                                h = do_hash(saddr, daddr, sport, dport, proto, host, k);
                                printf("0x%x\n", h);
                            }
                        }
                    }
                }
            }
        }
    }
                        
    return 0;
}
