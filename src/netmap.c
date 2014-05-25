#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include "netmap.h"

struct netmap* alloc_netmap(void)
{
    /* nothing to do */
    return NULL;
}

void add_addr_to_netmap(struct netmap **map, struct sockaddr *addr, int val)
{
    struct netmap* s = malloc(sizeof(struct netmap));
    s->addr = addr;
    s->val = val;
    s->next = NULL;
    if (!*map) {
        *map = s;
    } else {
        struct netmap* m = *map;
        while (m->next)
            m = m->next;
        m->next = s;
    }
}

static
int get_addr_score_in(struct sockaddr_in *netrule, struct sockaddr_in *addr)
{
    int port_score = 0;
    if (netrule->sin_port != 0) {
        if (netrule->sin_port == addr->sin_port)
            port_score = 1;
        else
            return 0;
    }
    uint32_t a = ntohl(addr->sin_addr.s_addr);
    uint32_t b = ntohl(netrule->sin_addr.s_addr);
    if (a == b)
        return 9 + port_score;
    if ((b & 0x000000ff))
        return 0;
    if ((a | 0x000000ff) == (b | 0x000000ff))
        return 7 + port_score;
    if ((b & 0x0000ffff))
        return 0;
    if ((a | 0x0000ffff) == (b | 0x0000ffff))
        return 5 + port_score;
    if ((b & 0x00ffffff))
        return 0;
    if ((a | 0x00ffffff) == (b | 0x00ffffff))
        return 3 + port_score;
    if ((b & 0xffffffff))
        return 0;
    return 1 + port_score;
}

static
int get_addr_score(struct sockaddr *netrule, struct sockaddr *addr)
{
    if (netrule->sa_family != addr->sa_family)
        return 0;
    if (addr->sa_family == AF_INET) {
        return get_addr_score_in((struct sockaddr_in *)netrule,
                (struct sockaddr_in *)addr);
    } else {
        // AF_INET6 not yet supported
        return 0;
    }
}

struct netmap* get_net_from_netmap(struct netmap *map, struct sockaddr *addr)
{
    struct netmap *res = NULL;
    int score = 0;
    int s;
    while (map) {
        s = get_addr_score(map->addr, addr);
        if (s > score) {
            score = s;
            res = map;
        }
        map = map->next;
    }
    return res;
}
