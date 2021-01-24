#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_ARRAY_SIZE 16

#define UDP_PCB_STATE_CLOSED  0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

struct udp_pcb {
    int state;
    struct udp_endpoint local;
    struct queue_head queue; /* receive queue */
    int wait;
    pthread_cond_t cond;
};

struct udp_queue_entry {
    struct udp_endpoint foreign;
    uint16_t len;
    uint8_t data[0];
};

static pthread_mutex_t m_pcbs = PTHREAD_MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_ARRAY_SIZE];

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP PROTOCOL CONTROL BLOCK
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */
static struct udp_pcb *
udp_pcb_new(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_CLOSED) {
            pcb->state = UDP_PCB_STATE_OPEN;
            pthread_cond_init(&pcb->cond, NULL);
            return pcb;
        }
    }
    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    if (pcb->state == UDP_PCB_STATE_OPEN) {
      pcb->state = UDP_PCB_STATE_CLOSING;
    }
    if (pcb->wait) {
        pthread_cond_broadcast(&pcb->cond);
        return;
    }
    pcb->state = UDP_PCB_STATE_CLOSED;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
      free(entry);
    }
    pthread_cond_destroy(&pcb->cond);
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < array_tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port) {
              return pcb;
            }
        }
    }
    return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (!array_index_isvalid(pcbs, id)) {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        return NULL;
    }
    return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
    return array_offset(pcbs, pcb);
}

/*
 * UDP CORE
 */

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0, sum;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN], addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    /*
     * exercise: step15
     *   UDPデータグラムの検証
     *   (1) サイズの検証
     *   (2) チェックサムの検証（疑似ヘッダの存在を忘れずに）
     */
    /* サイズの検証 (1) */
    hdr = (struct udp_hdr *)data;
    if (len > IP_PAYLOAD_SIZE_MAX) {
        errorf("udp size is too long");
        return;
    }
    if (len < sizeof(*hdr)) {
        errorf("udp size is too short");
        return;
    }

    /* pseudo headerの作成 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~(cksum16((uint16_t *)(&pseudo), sizeof(pseudo), 0)); // 途中までのsumなので反転させる

    if (cksum16((uint16_t *)data, len, psum) != 0) {
        errorf("checksome error");
        return;
    }

    debugf("%s:%d => %s:%d (%zu bytes payload)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len - sizeof(*hdr));
    udp_dump(data, len);

    pthread_mutex_lock(&m_pcbs);
    /*
     * exercise: step16
     *   (1) あて先のアドレスとポートに対応するPCBを検索（見つからなければエラーを返す）
     *   (2) PCBの受信キューにエントリをプッシュ
     *   (3) PCBの条件変数（cond）を用いて休止しているスレッドを起床させる（pthread_cond_broadcastで通知を送信）
     */
    /* (1) */
    pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb) {
        pthread_mutex_unlock(&m_pcbs);
        errorf("pcb not found");
        return;
    }
    /* (2) */
    entry = calloc(1, sizeof(*entry) + (len-sizeof(*hdr))); // udp headerを除くサイズ
    entry->len = (len-sizeof(*hdr));
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    memcpy(entry->data, (uint8_t *)(hdr+1), (len-sizeof(*hdr)));
    queue_push(&pcb->queue, entry);
    /* (3) */
    pthread_cond_broadcast(&pcb->cond);
    pthread_mutex_unlock(&m_pcbs);
}

ssize_t
udp_output(struct udp_endpoint *src, struct udp_endpoint *dst, uint8_t *data, size_t len)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /*
     * exercise: step15
     *   UDPデータグラムを生成
     *     - チェックサム生成時に疑似ヘッダの存在を忘れずに
     */
    /* pseudo headerを作成 */
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(sizeof(*hdr) + len);

    psum = ~(cksum16((uint16_t *)(&pseudo), sizeof(pseudo), 0)); //途中までのsumなので反転させる

    /* UDP headerを作成 */
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = hton16(sizeof(*hdr) + len);
    hdr->sum = 0;
    memcpy(hdr+1, data, len);
    hdr->sum = cksum16((uint16_t *)hdr, sizeof(*hdr) + len, psum);

    debugf("%s:%d => %s:%d (%zu bytes payload)",
        ip_addr_ntop(src->addr, addr1, sizeof(addr1)), ntoh16(src->port),
        ip_addr_ntop(dst->addr, addr2, sizeof(addr2)), ntoh16(dst->port),
        len);
    udp_dump((uint8_t *)hdr, sizeof(*hdr) + len);
    /*
     * exercise: step15
     *   IPの送信関数を呼び出してUDPデータグラムを送信
     */
    return ip_output(IP_PROTOCOL_UDP, buf, sizeof(*hdr) + len, src->addr, dst->addr);
}

int
udp_init(void)
{
    if (ip_protocol_register("UDP", IP_PROTOCOL_UDP, udp_input) == -1) {
        return -1;
    }
    return 0;
}

/*
 * UDP USER COMMAND
 */

int
udp_open(void)
{
    struct udp_pcb *pcb;
    int id;

    pthread_mutex_unlock(&m_pcbs);
    pcb = udp_pcb_new();
    if (!pcb) {
        errorf("no resource");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    id = udp_pcb_id(pcb);
    pthread_mutex_unlock(&m_pcbs);
    return id;
}

int udp_close(int index)
{
    struct udp_pcb *pcb;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(index);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    udp_pcb_release(pcb);
    pthread_mutex_unlock(&m_pcbs);
    return 0;
}

int udp_bind(int id, struct udp_endpoint *local)
{
    struct udp_pcb *pcb;
    char addr[IP_ADDR_STR_LEN];

    pthread_mutex_lock(&m_pcbs);
    /*
     * exercise: step16
     *   PCBにエンドポイントを紐づける
     *   (1) idで指定されたPCBを取得（取得できなかったらエラーを返す）
     *   (2) 指定されたエンドポイントに紐づく既存のPCBを検索（PCBが見つかった場合はbindできないのでエラーを返す）
     *   (3) (1) で取得したPCBにエンドポイントを設定する
     */
    /* (1) */
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    /* (2) */
    if (udp_pcb_select(local->addr, local->port)) {
        errorf("upd endpoint already binded");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    /* (3) */
    pcb->local = *local;

    debugf("success: addr=%s, port=%u", ip_addr_ntop(pcb->local.addr, addr, sizeof(addr)), ntoh16(pcb->local.port));
    pthread_mutex_unlock(&m_pcbs);
    return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct udp_endpoint *peer)
{
    struct udp_pcb *pcb;
    struct udp_endpoint src;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    src.addr = pcb->local.addr;
    if (src.addr == IP_ADDR_ANY) {
        iface = ip_iface_by_peer(peer->addr);
        if (!iface) {
            pthread_mutex_unlock(&m_pcbs);
            return -1;
        }
        debugf("select source address: %s", ip_addr_ntop(iface->unicast, addr, sizeof(addr)));
        src.addr = iface->unicast;
    }
    if (!pcb->local.port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp_pcb_select(src.addr, hton16(p))) {
                debugf("dinamic assign srouce port: %d", p);
                pcb->local.port = hton16(p);
                break;
            }
        }
        if (!pcb->local.port) {
            debugf("failed to dinamic assign srouce port");
            pthread_mutex_unlock(&m_pcbs);
            return -1;
        }
    }
    src.port = pcb->local.port;
    pthread_mutex_unlock(&m_pcbs);
    return udp_output(&src, peer, data, len);
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct udp_endpoint *peer)
{
    struct udp_pcb *pcb;
    struct timespec timeout;
    struct udp_queue_entry *entry;
    ssize_t len;

    pthread_mutex_lock(&m_pcbs);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    while ((entry = (struct udp_queue_entry *)queue_pop(&pcb->queue)) == NULL && !net_interrupt) {
        clock_gettime(CLOCK_REALTIME, &timeout);
        timespec_add_nsec(&timeout, 10000000); /* 100ms */
        pcb->wait++;
        pthread_cond_timedwait(&pcb->cond, &m_pcbs, &timeout);
        pcb->wait--;
    }
    if (pcb->state == UDP_PCB_STATE_CLOSING) {
        udp_pcb_release(pcb);
        free(entry);
        pthread_mutex_unlock(&m_pcbs);
        return 0;
    }
    if (!entry) {
        pthread_mutex_unlock(&m_pcbs);
        return -1;
    }
    if (peer) {
        *peer = entry->foreign;
    }
    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry->data, len);
    free(entry);
    pthread_mutex_unlock(&m_pcbs);
    return len;
}
