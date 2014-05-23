#pragma once

#include "uthash.h"

#define PATH_DELETED (1<<0)
#define PATH_ALLOWED (1<<1)
#define PATH_DIRECT  (1<<2)

struct fsmap {
    char key[PATH_MAX];
    int val;
    UT_hash_handle hh;
};

struct fsmap* alloc_fsmap(void);
void add_path_to_fsmap(struct fsmap **map, char *key, int val);
struct fsmap* get_path_from_fsmap(struct fsmap *map, char *key);
int is_in_fsmap(struct fsmap *map, char *key);
void free_fsmap(struct fsmap *map);
int path_status(struct fsmap *map, char *path);
