#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_PCB_ARRAY_SIZE 128

#define TCP_PCB_STATE_CLOSED 0
#define TCP_PCB_STATE_LISTEN 1
#define TCP_PCB_STATE_SYN_SENT 2
#define TCP_PCB_STATE_SYN_RCVD 3
#define TCP_PCB_STATE_ESTABLISHED 4
#define TCP_PCB_STATE_FIN_WAIT1 5
#define TCP_PCB_STATE_FIN_WAIT2 6
#define TCP_PCB_STATE_CLOSING 7
#define TCP_PCB_STATE_TIME_WAIT 8
#define TCP_PCB_STATE_CLOSE_WAIT 9
#define TCP_PCB_STATE_LAST_ACK 10

#define TCP_CTL_FIN 0x01
#define TCP_CTL_SYN 0x02
#define TCP_CTL_RST 0x04
#define TCP_CTL_PSH 0x08
#define TCP_CTL_ACK 0x10
#define TCP_CTL_URG 0x20

#define TCP_CTL_ISSET(x, y) ((x&0x3f) & y)

#define TCP_HDR_LEN(hdr) (((hdr)->offset >> 4) << 2)
#define TCP_DATA_LEN(hdr, len) ((len)-TCP_HDR_LEN(hdr))

#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

struct tcp_pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint64_t ack;
    uint8_t offset;
    uint8_t ctrls;
    uint16_t win;
    uint16_t sum;
    uint16_t urg;
};
