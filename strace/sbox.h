#pragma once

#define READWRITE_READ    0
#define READWRITE_WRITE   1
#define READWRITE_FORCE   2

static inline
int path_exists(char *path)
{
    return access(path, F_OK) == 0;
}

extern void sbox_remote_write(struct tcb *tcp, long ptr, char *buf, int len);
extern void sbox_rewrite_arg(struct tcb *tcp, int arg, long val);
extern void sbox_hijack_str(struct tcb *tcp, int arg, char *new);
extern void sbox_restore_hijack(struct tcb *tcp);
extern void sbox_cleanup(void);

#define is_in_sboxfs(pn) (strncmp(pn, opt_root, opt_root_len) == 0)