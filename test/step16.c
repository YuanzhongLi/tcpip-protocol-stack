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

static void
on_signal(int s)
{
    (void)s;
    net_interrupt = 1;
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
    int soc;
    struct udp_endpoint local, foreign;
    ssize_t ret;
    uint8_t buf[1024];
    char addr[IP_ADDR_STR_LEN];

    if (setup() == -1) {
        return -1;
    }
    /*
     * exercise: step16
     *   UDPのエコーサーバを作成
     *     - 0.0.0.0 の 7 番ポートを使用する
     */
    soc = udp_open(); // socket descripter id
    local.addr = IP_ADDR_ANY;
    local.port = ntoh16(7);
    udp_bind(soc, &local);
    while (1) {
        ret = udp_recvfrom(soc, buf, 1024, &foreign);
        if (ret <= 0) {
            break;
        }
        hexdump(stderr, buf, ret);
        udp_sendto(soc, buf, ret, &foreign); // エコーサーバなのでもらったものをそのまま返す
    }
    udp_close(soc);
    net_shutdown();
    return 0;
}
