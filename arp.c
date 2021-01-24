#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "util.h"
#include "ether.h"
#include "net.h"
#include "arp.h"
#include "ip.h"

#define ARP_HRD_ETHER 0x0001

#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_TABLE_SIZE 32
#define ARP_TABLE_TIMEOUT 30 /* seconds */

#define ARP_ENTRY_STATE_FREE       0
#define ARP_ENTRY_STATE_INCOMPLETE 1
#define ARP_ENTRY_STATE_RESOLVED   2
#define ARP_ENTRY_STATE_STATIC     3

struct arp_hdr {
    uint16_t hrd;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

struct arp_ether {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];
    uint8_t spa[IP_ADDR_LEN];
    uint8_t tha[ETHER_ADDR_LEN];
    uint8_t tpa[IP_ADDR_LEN];
};

struct arp_entry {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct arp_entry arp_table[ARP_TABLE_SIZE];

static char *
arp_opcode_ntop(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "REQUEST";
    case ARP_OP_REPLY:
        return "REPLY";
    }
    return "UNKNOWN";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether *)data;
    flockfile(stderr);
    fprintf(stderr, "  hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "  pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "  hln: %u\n", message->hdr.hln);
    fprintf(stderr, "  pln: %u\n", message->hdr.pln);
    fprintf(stderr, "   op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntop(message->hdr.op));
    fprintf(stderr, "  sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "  spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "  tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "  tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * ARP Table
 *
 * NOTE: ARP Table functions must be called after mutex locked
 */

static struct arp_entry *
arp_table_freespace(void)
{
    struct arp_entry *entry, *oldest = NULL;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (entry->state == ARP_ENTRY_STATE_FREE) {
            return entry;
        }
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    return oldest;
}

static struct arp_entry *
arp_table_select(ip_addr_t pa)
{
    struct arp_entry *entry;

    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (entry->state != ARP_ENTRY_STATE_FREE && entry->pa == pa) {
            return entry;
        }
    }
    return NULL;
}

static struct arp_entry *
arp_table_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_entry *entry;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];

    entry = arp_table_select(pa);
    if (!entry) {
        return NULL;
    }
    entry->state = ARP_ENTRY_STATE_RESOLVED;
    memcpy(entry->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&entry->timestamp, NULL);
    debugf("UPDATE pa=%s ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return entry;
}

static struct arp_entry *
arp_table_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_entry *entry;
    char addr1[IP_ADDR_STR_LEN], addr2[ETHER_ADDR_STR_LEN];

    entry = arp_table_freespace();
    if (!entry) {
        return NULL;
    }
    entry->state = ARP_ENTRY_STATE_RESOLVED;
    entry->pa = pa;
    memcpy(entry->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&entry->timestamp, NULL);
    debugf("INSERT pa=%s ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return entry;
}

static void
arp_table_delete(struct arp_entry *entry)
{
    char addr1[IP_ADDR_STR_LEN], addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE pa=%s ha=%s", ip_addr_ntop(entry->pa, addr1, sizeof(addr1)), ether_addr_ntop(entry->ha, addr2, sizeof(addr2)));
    entry->state = ARP_ENTRY_STATE_FREE;
    entry->pa = 0;
    memset(entry->ha, 0, ETHER_ADDR_LEN);
    timerclear(&entry->timestamp);
}

static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether request;

    /*
     * exercise: step12
     *   ARP要求メッセージの生成
     */
    /* header作成 */
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    /* ip, hdaddrの作成 */
    struct ip_iface *ip_iface;
    ip_iface = (struct ip_iface *)iface;
    memcpy(request.sha, iface->dev->addr, sizeof(request.sha));
    memcpy(request.spa, (uint8_t *)(&(ip_iface->unicast)), sizeof(request.spa));
    /* tha do not care (0) */
    memset(request.tha, 0, sizeof(request.tha));
    memcpy(request.tpa, (uint8_t *)&tpa, sizeof(request.tpa));


    debugf("%zd bytes data to <%s>", sizeof(request), iface->dev->name);
    arp_dump((uint8_t *)&request, sizeof(request));

    /*
     * exercise: step12
     *   デバイスから送信
     *     - 呼び出した関数の戻り値をこの関数の戻り値としてそのまま返す
     */
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_ARP, (uint8_t *)(&request), sizeof(request), ETHER_ADDR_BROADCAST);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether reply;
    /*
     * exercise: step11
     *   ARP応答メッセージの生成
     */
    /* header作成 */
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    /* ip, hdaddrの作成 */
    struct ip_iface *ip_iface;
    ip_iface = (struct ip_iface *)iface;
    memcpy(reply.sha, iface->dev->addr, sizeof(reply.sha));
    memcpy(reply.spa, (uint8_t *)(&(ip_iface->unicast)), sizeof(reply.spa));
    memcpy(reply.tha, tha, sizeof(reply.tha));
    memcpy(reply.tpa, (uint8_t *)&tpa, sizeof(reply.tpa));


    debugf("%zd bytes data to <%s>", sizeof(reply), iface->dev->name);
    arp_dump((uint8_t *)&reply, sizeof(reply));
    /*
     * exercise: step11
     *   デバイスから送信
     *     - 呼び出した関数の戻り値をこの関数の戻り値としてそのまま返す
     */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)(&reply), sizeof(reply), dst);
}

int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_entry *entry;

    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IPV4) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    pthread_mutex_lock(&mutex);
    entry = arp_table_select(pa);
    if (entry) {
        if (entry->state == ARP_ENTRY_STATE_INCOMPLETE) {
            arp_request(iface, pa); /* just in case packet loss */
            pthread_mutex_unlock(&mutex);
            return ARP_RESOLVE_QUERY;
        }

        memcpy(ha, entry->ha, ETHER_ADDR_LEN);
        pthread_mutex_unlock(&mutex);
        return ARP_RESOLVE_FOUND;
    }
    /*
     * exercise: step12
     *   未解決のアドレスを解決するためにARP要求を送信する
     *   (1) ARPテーブルから未使用のエントリを取得
     *   (2) エントリの状態を ARP_ENTRY_STATE_INCOMPLETE に設定
     *   (3) エントリのプロトコルアドレスに pa を設定
     *   (4) エントリのタイムスタンプに現在時刻を設定
     *   (5) ARPリクエストの送信関数を呼び出す
     */
    entry = arp_table_freespace(); // (1)
    entry->state = ARP_ENTRY_STATE_INCOMPLETE; // (2)
    entry->pa = pa; // (3)
    gettimeofday(&entry->timestamp, NULL); // (4)
    pthread_mutex_unlock(&mutex);
    arp_request(iface, pa); // (5)

    return ARP_RESOLVE_QUERY;
}

static void
arp_timer(void)
{
    struct arp_entry *entry;
    struct timeval now, diff;

    pthread_mutex_lock(&mutex);

    /*
     *   ARPテーブルを巡回してタイムアウトしているエントリを削除する
     *    - ARPエントリのうち state が ARP_ENTRY_STATE_FREE または ARP_ENTRY_STATE_STATIC のものはチェックをスキップする
     *    - struct timeval 型で保持している時刻情報は timersub() で差分を取得する
     *    - タイムアウトの判定は「現在時刻」と「エントリのタイムスタンプ」の差分が ARP_TABLE_TIMEOUT（秒）以上であるかどうか
     */
    for (entry = arp_table; entry < array_tailof(arp_table); entry++) {
        if (entry->state == ARP_ENTRY_STATE_FREE || entry->state == ARP_ENTRY_STATE_STATIC) {
          continue;
        }
        gettimeofday(&now, NULL);
        timersub(&now, &(entry->timestamp), &diff);
        if (ARP_TABLE_TIMEOUT <= diff.tv_sec) { /* secondで30秒以上判定 */
            arp_table_delete(entry);
        }
    }

    pthread_mutex_unlock(&mutex);
}



static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether *msg;
    ip_addr_t spa, tpa;
    int merge = 0;
    struct net_iface *iface;

    if (len < sizeof(struct arp_ether)) {
        debugf("input data is too short");
        return;
    }
    debugf("%zd bytes message from <%s>", len, dev->name);
    arp_dump(data, len);
    msg = (struct arp_ether *)data;
    /*
     * exercise: step11
     *   RFC記載の手順で受信処理（RFC826 - Section: Packet Reception）
     */
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER) {
        debugf("ha is not ether");
        return;
    }
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP) {
        debugf("protocol is not IPV4");
        return;
    }

    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    // If the pair <proto type, spa> in table
    struct arp_entry *entry;
    pthread_mutex_lock(&mutex);
    entry = arp_table_update(spa, msg->sha);
    pthread_mutex_unlock(&mutex);
    if (entry) {
        merge = 1;
    }

    // Am I the target proto
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IPV4);
    if (iface) {
        if (!merge) {
            pthread_mutex_lock(&mutex);
            arp_table_insert(spa, msg->sha);
            pthread_mutex_unlock(&mutex);
        }
    }

    if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
        arp_reply(iface, msg->sha, spa, msg->sha);
    }
}

int
arp_init(void)
{
    struct timeval interval = {1, 0};

    if (net_protocol_register("ARP", NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        return -1;
    }
    /*
     * exercise: step13
     *   プロトコルスタック本体にARPタイマーを登録する
     */
    net_timer_register("ARP_TIMER", interval, arp_timer);
    return 0;
}
