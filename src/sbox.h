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
extern void sbox_hijack_mem(struct tcb *tcp, int arg, void *new, int len);
extern void sbox_hijack_str(struct tcb *tcp, int arg, char *new);
extern void sbox_restore_hijack(struct tcb *tcp);
extern void sbox_check_test_cond(const char *pn, const char *key);
extern void sbox_init(void);
extern void sbox_cleanup(FILE *outf);
extern int sbox_interactive(void);
extern void sbox_stop(struct tcb *tcp, const char *fmt, ...);
extern void sbox_get_readonly_ptr(struct tcb *tcp);
extern void sbox_add_log(struct tcb *tcp, const char *fmt, ...);
extern void sbox_load_profile(char *profile);

#define is_in_sboxfs(pn) (strncmp(pn, opt_root, opt_root_len) == 0)

static inline
void *safe_malloc(size_t size)
{
    void *ptr = (void *) malloc(size);
    if (!ptr) {
        die_out_of_memory();
    }
    return ptr;
}

// define a syscall to interpose, if syscall gets a just path arg
#define DEF_SBOX_SC_PATH(sc, arg, opt)                              \
    int sbox_##sc(struct tcb *tcp)                                  \
    {                                                               \
        if (entering(tcp)) {                                        \
            sbox_rewrite_path(tcp, AT_FDCWD, arg, READWRITE_##opt); \
        }                                                           \
        return 0;                                                   \
    }

#define DEF_SBOX_SC_PATH_AT(sc, fd, arg, opt)                       \
    int sbox_##sc(struct tcb *tcp)                                  \
    {                                                               \
        if (entering(tcp)) {                                        \
            sbox_rewrite_path(tcp, tcp->u_arg[fd], arg,             \
                              READWRITE_##opt);                     \
        }                                                           \
        return 0;                                                   \
    }
