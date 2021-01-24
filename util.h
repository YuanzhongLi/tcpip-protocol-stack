#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define timespec_add_nsec(x, y)          \
    do {                                 \
        (x)->tv_nsec += y;               \
        if ((x)->tv_nsec > 1000000000) { \
            (x)->tv_sec += 1;            \
            (x)->tv_nsec -= 1000000000;  \
        }                                \
    } while(0);

#define sizeof_member(s, m) sizeof(((s *)NULL)->m)
#define array_size(x) ((sizeof(x) / sizeof(*x)))
#define array_tailof(x) (x + array_size(x))
#define array_offset(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))
#define array_index_isvalid(x, y) ((y) >=0 && (unsigned int)(y) < array_size(x))

#define errorf(...) lprintf('E', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define warnf(...) lprintf('W', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define infof(...) lprintf('I', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define debugf(...) lprintf('D', __FILE__, __LINE__, __func__, __VA_ARGS__)

#ifdef HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

extern int
lprintf(int level, const char *file, int line, const char *func, const char *fmt, ...);

extern void
hexdump(FILE *fp, const void *data, size_t size);

struct queue_entry {
    struct queue_entry *next;
    void *data;
};

struct queue_head {
    struct queue_entry *head;
    struct queue_entry *tail;
    unsigned int num;
};

extern void
queue_init(struct queue_head *queue);
extern void *
queue_push(struct queue_head *queue, void *data);
extern void *
queue_pop(struct queue_head *queue);
extern void *
queue_peek(struct queue_head *queue);

extern uint16_t
hton16(uint16_t h);
extern uint16_t
ntoh16(uint16_t n);
extern uint32_t
hton32(uint32_t h);
extern uint32_t
ntoh32(uint32_t n);

extern uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif
