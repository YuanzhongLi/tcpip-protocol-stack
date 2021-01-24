#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/ether_tap.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = ether_tap_init("tap0", "00:00:5e:00:53:01");
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc("172.16.10.2", "255.255.255.0");
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, "172.16.10.1") == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

int
main(void)
{
    struct udp_endpoint src, dst;
    char data[] = "test data\n";

    if (setup() == -1) {
        return -1;
    }
    ip_addr_pton("172.16.10.2", &src.addr);
    src.port = hton16(7);
    ip_addr_pton("172.16.10.1", &dst.addr);
    dst.port = hton16(10007);
    while (!terminate) {
        // udp_output(&src, &dst, (uint8_t *)data, strlen(data));
        sleep(1);
    }
    net_shutdown();
    return 0;
}
