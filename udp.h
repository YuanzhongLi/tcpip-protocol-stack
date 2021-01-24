#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

struct udp_endpoint {
    ip_addr_t addr;
    uint16_t port;
};

extern ssize_t
udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, uint8_t *buf, size_t len);
extern int
udp_init(void);

extern int
udp_open(void);
extern int
udp_bind(int index, struct udp_endpoint *local);
extern ssize_t
udp_sendto(int id, uint8_t *buf, size_t len, struct udp_endpoint *peer);
extern ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct udp_endpoint *peer);
extern int
udp_close(int id);

#endif
