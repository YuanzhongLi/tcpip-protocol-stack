#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"

static uint8_t data[] = {0x00, 0x00, 0x35, 0x4d,
                         0x00, 0x00, 0x00, 0x00,
                         0x74, 0x65, 0x73, 0x74,
                         0x20, 0x64, 0x61, 0x74,
                         0x61};

struct {
    unsigned int type;
    size_t len;
    uint8_t *data;
} test = {0x01, sizeof(data), data};

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int
main(void)
{
    struct net_device *dev;
    struct ip_iface *iface;
    ip_addr_t dst;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc("127.0.0.1", "255.0.0.0");
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    dst = iface->unicast;
    while (!terminate) {
        if (ip_output(test.type, test.data, test.len, iface->unicast, dst) == -1) {
            errorf("ip_output() failure, dev=%s, type=0x%04x, len=%zu", dev->name, test.type, test.len);
            break;
        }
        sleep(1);
    }
    net_shutdown();
    return 0;
}
