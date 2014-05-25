#pragma once

#include <stdint.h>
#include <sys/socket.h>

#define NET_BLOCK 0
#define NET_KILL  (1<<0)
#define NET_LOG   (1<<1)
#define NET_ALLOW (1<<2)

struct netmap {
    struct sockaddr *addr;
    struct netmap *next;
    int val;
};

struct netmap* alloc_netmap(void);
void add_addr_to_netmap(struct netmap **map, struct sockaddr *addr, int val);
struct netmap* get_net_from_netmap(struct netmap *map, struct sockaddr *addr);
