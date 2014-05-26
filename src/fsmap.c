#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include "fsmap.h"
#include "dbg.h"

struct fsmap* alloc_fsmap(void)
{
    /* nothing to do */
    return NULL;
}

void add_path_to_fsmap(struct fsmap **map, char *key, int val)
{
    struct fsmap* s = (struct fsmap*)malloc(sizeof(struct fsmap));
    strncpy(s->key, key, sizeof(s->key));
    s->val = val;
    HASH_ADD_STR(*map, key, s);

    dbg(fsmap, "deleted %s (flag:%d)", key, val);
}

struct fsmap* get_path_from_fsmap(struct fsmap *map, char *key)
{
    struct fsmap *s;
    HASH_FIND_STR(map, key, s);
    return s;
}

void free_fsmap(struct fsmap *map)
{
    struct fsmap *s;
    struct fsmap *tmp;

    HASH_ITER(hh, map, s, tmp) {
        HASH_DEL(map, s);
        free(s);
    }
}

int path_status(struct fsmap *map, char *path)
{
    if (!map) {
        return 0;
    }
    
    char buf[PATH_MAX];
    strncpy(buf, path, sizeof(buf));
    
    struct fsmap *s;
    char *end = buf + strlen(buf);
    do {
        dbg(fsmapv, "path: %s", buf);
        s = get_path_from_fsmap(map, buf);
        if (s)
            return s->val;

        while (end != buf && *end != '/') {
            end --;
        }
        *end = '\0';
    } while (end != buf);

    s = get_path_from_fsmap(map, "/");
    return s ? s->val : 0;
}
