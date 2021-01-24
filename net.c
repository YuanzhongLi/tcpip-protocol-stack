#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>

#include "util.h"
#include "net.h"

#define NET_THREAD_SLEEP_TIME 1000 /* micro seconds */

struct net_protocol {
    struct net_protocol *next;
    char name[16];
    uint16_t type;
    pthread_mutex_t mutex; /* mutex for input queue */
    struct queue_head queue; /* input queue */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
    uint8_t data[0];
};

struct net_timer {
    struct net_timer *next;
    char name[16];
    struct timeval interval;
    struct timeval last;
    void (*handler)(void);
};

volatile sig_atomic_t net_interrupt;

static pthread_t thread;
static volatile sig_atomic_t terminate;

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;
static struct net_timer *timers;

struct net_device *
net_device_alloc(void (*setup)(struct net_device *dev))
{
    struct net_device *dev;

    dev = calloc(1, sizeof(*dev));
    if (!dev) {
        errorf("calloc() failure");
        return NULL;
    }
    if (setup) {
        setup(dev);
    }
    return dev;
}

int
net_timer_register(const char *name, struct timeval interval, void (*handler)(void))
{
    struct net_timer *timer;
    struct timeval now;

    /*
     * exercise: step13
     *   新しいタイマー用のメモリを確保してパラメータを設定し、タイマーのリストに追加する
     */
    timer = calloc(1, sizeof(*timer));
    if (!timer) {
        errorf("calloc() failure");
        return -1;
    }

    strncpy(timer->name, name, MIN(strlen(name), sizeof(timer->name)-1));
    timer->handler = handler;
    timer->interval = interval;
    gettimeofday(&now, NULL);
    timer->last = now; /* initial timer last is timer created timestamp */

    /* listの先頭についか */
    timer->next = timers;
    timers = timer;

    infof("registerd: %s interval={%d, %d}", timer->name, interval.tv_sec, interval.tv_usec);
    return 0;
};

/* NOTE: must not be call after net_run() */
int
net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    /*
     * exercise: step1
     *   ネットワークデバイスのリストの先頭に挿入する
     */
    dev->next = devices; // dev->next = 先頭
    devices = dev; // 先頭を更新
    infof("registerd, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int
net_device_open(struct net_device *dev)
{
    /*
     * exercise: step1
     *   ネットワークデバイスのオープン処理
     *   (1) デバイスの状態を確認
     *   (2) デバイス固有のオープン関数が登録されていたら呼び出す
     *   (3) デバイスのフラグに NET_DEVICE_FLAG_UP をセットする
     */
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/* NOTE: must not be call after net_run() */
int
net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == iface->family) {
            errorf("already exists, dev=%s, family=0x%02x", dev->name, entry->family);
            return -1;
        }
    }
    iface->next = dev->ifaces;
    iface->dev = dev;
    dev->ifaces = iface;
    return 0;
}

struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == family) {
            break;
        }
    }
    return entry;
}

int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu) {
        errorf("too long");
        return -1;
    }
    debugf("dev=%s, proto=%s(0x%04x), len=%zu", dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    /*
     * exercise: step1
     *   ネットワークデバイス固有の送信関数を呼び出す
     */
    return dev->ops->transmit(dev, type, data, len, dst);
}

int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            entry = calloc(1, sizeof(*entry) + len);
            if (!entry) {
                errorf("calloc() failure");
                return -1;
            }
            /*
             * exercise: step3
             *   プロトコルの受信キューに entry を push する
             *   (1) entry の全てのメンバに値を格納する
             *   (2) queue_push() を使用してキューに entry を push する
             *     - キューの操作は mutex をロックして実施すること（アンロック忘れに注意）
             */
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);
            pthread_mutex_lock(&proto->mutex);
            queue_push(&proto->queue, entry);
            pthread_mutex_unlock(&proto->mutex);
            debugf("queue pushed, dev=%s, proto=%s(0x%04x) len=%zd", dev->name, proto->name, type, len);
            debugdump(data, len);
            return 0;
        }
    }
    /* unsupported protocol */
    return 0;
}

/* NOTE: must not be call after net_run() */
int
net_protocol_register(const char *name, uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    /*
     * exercise: step3
     *   重複チェック
     */
    for (proto=protocols; proto; proto=proto->next) {
        if (proto->type == type) {
            errorf("protocol already registerd");
            return -1;
        }
    }
    proto = calloc(1, sizeof(*proto));
    if (!proto) {
        errorf("calloc() failure");
        return -1;
    }
    strncpy(proto->name, name, MIN(strlen(name), sizeof(proto->name)-1));
    proto->type = type;
    pthread_mutex_init(&proto->mutex, NULL);
    proto->handler = handler;
    /*
     * exercise: step3
     *   プロトコルのリストの先頭に挿入する
     */
    proto->next = protocols;
    protocols = proto;
    infof("registerd, %s (0x%04x)", proto->name, type);
    return 0;
}

char *
net_protocol_name(uint16_t type)
{
    struct net_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            return entry->name;
        }
    }
    return "UNKNOWN";
}

static void *
net_thread(void *arg)
{
    unsigned int count;
    struct net_device *dev;
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;
    struct net_timer *timer;
    struct timeval now, diff;

    while (!terminate) {
        count = 0;
        for (dev = devices; dev; dev = dev->next) {
            /*
             * exercise: step4
             *   デバイスにパケットの受信を促す
             *   (1) デバイスの状態を確認
             *     - デバイスがUP状態でなければ (2) の処理はスキップ
             *   (2) デバイス固有の poll 関数を呼び出す
             *     - エラーが返されなかった場合のみ count をインクリメントする
             */
             if (NET_DEVICE_IS_UP(dev)) {
                if (dev->ops->poll) {
                  if (dev->ops->poll(dev) != -1) {
                      count++;
                  }
                }
             }
        }
        for (proto = protocols; proto; proto = proto->next) {
            /*
             * exercise: step4
             *   プロトコルの受信キューから entry を pop してプロトコルの受信ハンドラに渡す
             *   (1) queue_pol() を使用してキューから entry を pop する
             *     - キューの操作は mutex をロックして実施すること（アンロック忘れに注意）
             *     - entry が NULL（つまりキューが空）の場合は (2) 以降の処理はスキップ
             *   (2) プロトコルの受信ハンドラを呼び出す
             *   (3) entry は net_input_handler() 内で動的に確保されたものなのでメモリを開放する
             *   (4) count をインクリメントする
             */
             pthread_mutex_lock(&proto->mutex);
             entry = queue_pop(&proto->queue);
             pthread_mutex_unlock(&proto->mutex);
             if (entry) {
                  proto->handler(entry->data, entry->len, entry->dev);
                  free(entry);
                  count++;
             }
        }
        for (timer = timers; timer; timer = timer->next) {
            gettimeofday(&now, NULL);
            timersub(&now, &timer->last, &diff);
            if (timercmp(&timer->interval, &diff, <) != 0) { /* true (!0) or false (0) */
                timer->handler();
                timer->last = now;
                count++;
            }
        }

        /*
         * exercise: step4
         *   count が 0 のままだったら NET_THREAD_SLEEP_TIME の時間だけスレッドを休止する
         */
        if (!count) {
            usleep(NET_THREAD_SLEEP_TIME);
        }
    }
    return NULL;
}

int
net_run(void)
{
    struct net_device *dev;

    debugf("open all devices...");
    /*
     * exercise: step1
     *   登録されている全てのネットワークデバイスをオープン
     */
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("done");
    debugf("create background thread...");
    /*
     * exercise: step4
     *   pthread_create() でスレッドを起動する
     *     - スレッド識別子はグローバル変数 thread として定義してあるものを使用する
     *     - スレッドのエントリポイントは net_thread()
     *     - エラーが返されたらこの関数もエラーを返す
     */
    if (pthread_create(&thread, NULL, net_thread, NULL) != 0) {
        errorf("can not create thread");
        return -1;
    }
    debugf("done");
    return 0;
}

void
net_shutdown(void)
{
    struct net_device *dev;

    debugf("terminate background thread...");
    /*
     * exercise: step4
     *   スレッドを終了させて回収する
     *   (1) グローバル変数 terminate に 1 を代入する
     *     - スレッドがループから脱して終了する
     *   (2) pthread_join() でスレッドの終了を待ち回収する
     *     - スレッドの終了ステータスを取得する必要はない
     */
    terminate = 1;
    pthread_join(thread, NULL);
    debugf("done");

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    debugf("done");
}

#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

int
net_init(void)
{
    if (arp_init() == -1) {
        return -1;
    }
    if (ip_init() == -1) {
        return -1;
    }
    if (icmp_init() == -1) {
        return -1;
    }
    if (udp_init() == -1) {
        return -1;
    }
    return 0;
}
