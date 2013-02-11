#pragma once

#include "uthash.h"
#include "dbg.h"

#include <openssl/md5.h>

struct md5map {
    char key[PATH_MAX];
    unsigned char val[MD5_DIGEST_LENGTH];
    UT_hash_handle hh;
};

static
void add_md5_to_map(struct md5map **map, char *key, unsigned char *val)
{
    struct md5map* s = (struct md5map*)malloc(sizeof(struct md5map));
    strncpy(s->key, key, sizeof(s->key));
    memcpy(s->val, val, sizeof(s->val));

    HASH_ADD_STR(*map, key, s);

    ifdbg(md5map, {
        int i;
        dbg(md5map, "add md5: %s", key);
        for (i = 0; i < MD5_DIGEST_LENGTH; i ++) {
            fprintf(stderr, "%02x", val[i]);
        }
    });
}

static
struct md5map* get_md5_from_map(struct md5map *map, char *key)
{
    struct md5map *s;
    HASH_FIND_STR(map, key, s);
    return s;
}

static
void free_md5map(struct md5map *map)
{
    struct md5map *s;
    struct md5map *tmp;

    HASH_ITER(hh, map, s, tmp) {
        HASH_DEL(map, s);
        free(s);
    }
}
