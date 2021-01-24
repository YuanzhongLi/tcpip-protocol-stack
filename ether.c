#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

int
ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return 0;
}

static const char *
ether_type_ntoa(uint16_t type)
{
    switch (ntoh16(type)) {
    case ETHER_TYPE_IP:
        return "IP";
    case ETHER_TYPE_ARP:
        return "ARP";
    case ETHER_TYPE_IPV6:
        return "IPv6";
    }
    return "UNKNOWN";
}

char *
ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p) {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

static void
ether_dump(const uint8_t *frame, size_t flen)
{
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    flockfile(stderr);
    fprintf(stderr, "   src: %s\n", ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "   dst: %s\n", ether_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "  type: 0x%04x (%s)\n", ntoh16(hdr->type), ether_type_ntoa(hdr->type));
#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

int
ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ssize_t (*callback)(struct net_device *dev, const uint8_t *data, size_t len))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    struct ether_hdr *hdr;
    size_t flen;

    if (!data || len > ETHER_PAYLOAD_SIZE_MAX || !dst) {
        return -1;
    }

    hdr = (struct ether_hdr *)frame;
    /*
     * exercise: step10
     *   Ethernetフレームの生成
     *   (1) ヘッダの各フィールドに値を設定する
     *   (2) ヘッダの後ろにデータをコピーする
     *   (3) データが最小サイズに満たない場合はパディングを挿入してデータサイズを調整する
     */
    flen = sizeof(*hdr) + len;
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    memcpy(hdr->dst, (uint8_t *)dst, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    memset(hdr+1, 0, ETHER_PAYLOAD_SIZE_MIN);
    memcpy(hdr+1, data, len);
    flen = MAX(flen, sizeof(*hdr) + ETHER_PAYLOAD_SIZE_MIN);

    debugf("%zd bytes data to <%s>", flen, dev->name);
    ether_dump(frame, flen);
    /*
     * exercise: step10
     *   引数として渡されたコールバック関数を呼び出す
     *     - コールバック関数の戻り値が送信フレームサイズと一致する場合は 0, そうでない場合は -1 を戻り値として返す
     */
    if (callback(dev, frame, flen) != (ssize_t)flen) {
        return -1;
    }
    return 0;
}

int
ether_poll_helper(struct net_device *dev, ssize_t (*callback)(struct net_device *dev, uint8_t *buf, size_t size))
{
    uint8_t frame[2048];
    ssize_t flen;
    struct ether_hdr *hdr;

    flen = callback(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(*hdr)) {
        errorf("input data is too short");
        return -1;
    }
    hdr = (struct ether_hdr *)frame;
    /*
     * exercise: step10
     *   フィルタリング処理
     *     - 以下条件のいずれにも合致しない場合は他のホスト宛とみなしてエラーを返す（ログの出力は不要）
     *       a. 宛先MACアドレスがデバイスのMACアドレスと一致する
     *       b. 宛先MACアドレスがブロードキャストMACアドレスと一致する
     */
    if (memcmp(hdr->dst,  dev->addr, ETHER_ADDR_LEN) != 0) {
        if (memcmp(hdr->dst, dev->broadcast, ETHER_ADDR_LEN) != 0) {
          return -1;
        }
    }

    debugf("%zd bytes data from <%s>", flen, dev->name);
    ether_dump(frame, flen);
    /*
     * exercise: step10
     *   プロトコルスタック本体の入力ハンドラを呼び出す
     *     - 入力ハンドラの戻り値をこの関数の戻り値としてそのまま返す
     */
    return net_input_handler(ntoh16(hdr->type),  (uint8_t *)(hdr+1), flen - sizeof(*hdr), dev);
}

void
ether_setup_helper(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEVICE_FLAG_BROADCAST | NET_DEVICE_FLAG_NEED_ARP);
    dev->hlen = ETHER_HDR_SIZE;
    dev->alen = ETHER_ADDR_LEN;
    memcpy(dev->broadcast, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
}
