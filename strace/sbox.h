#pragma once

#define RW_NONE    0
#define RW_WRITING 1
#define RW_FORCE   2

static inline
int path_exists(char *path)
{
    return access(path, F_OK) == 0;
}

extern void get_hpn_from_arg(struct tcb *tcp, int arg, char *path, int len);
extern void get_spn_from_hpn(char *hpn, char *spn, int len);
extern void set_regs_with_arg(struct user_regs_struct *regs, int arg, long val);
extern void sbox_remote_write(struct tcb *tcp, long ptr, char *buf, int len);
extern void sbox_rewrite_arg(struct tcb *tcp, int arg, long val);
extern void sbox_hijack_str(struct tcb *tcp, int arg, char *new);
extern void sbox_restore_hijack(struct tcb *tcp);

#define is_in_sboxfs(pn) (strncmp(pn, opt_root, opt_root_len) == 0)