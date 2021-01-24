#ifndef ETHER_H
#define ETHER_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "net.h"

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif
#define ETHER_ADDR_STR_LEN 18 /* "xx:xx:xx:xx:xx:xx\0" */

#define ETHER_HDR_SIZE 14
#define ETHER_TRL_SIZE  4
#define ETHER_FRAME_SIZE_MIN   64 /* with FCS */
#define ETHER_FRAME_SIZE_MAX 1518 /* with FCS */
#define ETHER_PAYLOAD_SIZE_MIN (ETHER_FRAME_SIZE_MIN - (ETHER_HDR_SIZE + ETHER_TRL_SIZE))
#define ETHER_PAYLOAD_SIZE_MAX (ETHER_FRAME_SIZE_MAX - (ETHER_HDR_SIZE + ETHER_TRL_SIZE))

#define ETHER_TYPE_IP   0x0800
#define ETHER_TYPE_ARP  0x0806
#define ETHER_TYPE_IPV6 0x86dd

struct ether_device;

struct ether_device_ops {
    int (*open)(struct ether_device *raw);
    int (*close)(struct ether_device *raw);
    int (*write)(struct ether_device *raw, const uint8_t *frame, size_t flen);
    int (*read)(struct ether_device *raw, uint8_t *buf, size_t size);
};

struct ether_device {
    struct net_device *net_device;
    struct ether_device_ops *ops;
    void *priv;
};

extern const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN];
extern const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN];

extern int
ether_addr_pton (const char *p, uint8_t *n);
extern char *
ether_addr_ntop (const uint8_t *n, char *p, size_t size);

extern int
ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *payload, size_t plen, const void *dst, ssize_t (*callback)(struct net_device *dev, const uint8_t *buf, size_t len));
extern int
ether_poll_helper(struct net_device *dev, ssize_t (*callback)(struct net_device *dev, uint8_t *buf, size_t size));
extern void
ether_setup_helper(struct net_device *net_device);

extern struct net_device *
ether_init(const char *name);

#endif
