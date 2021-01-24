#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"

static char data[] = "test data";

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
        if (icmp_output(ICMP_TYPE_ECHO, 0, 0, (uint8_t *)data, strlen(data), iface->unicast, dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        sleep(1);
    }
    net_shutdown();
    return 0;
}
