#include "defs.h"
#include "sbox.h"
#include "dbg.h"

#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/stat.h>

void get_hpn_from_arg(struct tcb *tcp, int arg, char *path, int len)
{
    char pn[PATH_MAX];
    const long ptr = tcp->u_arg[arg];
    if (umovestr(tcp, ptr, PATH_MAX, pn) <= 0) {
        pn[0] = '\0';
    }
    realpath(pn, path);
}

void get_spn_from_hpn(char *hpn, char *spn, int len)
{
    snprintf(spn, len, "%s%s", opt_root, hpn);
}

void set_regs_with_arg(struct user_regs_struct *regs, int arg, long val)
{
    switch (arg) {
    case 0: regs->rdi = val; break;
    case 1: regs->rsi = val; break;
    case 2: regs->rdx = val; break;
    case 3: regs->r10 = val; break;
    case 4: regs->r8  = val; break;
    case 5: regs->r9  = val; break;
    }
}

void sbox_remote_write(struct tcb *tcp, long ptr, char *buf, int len)
{
    struct iovec local[1], remote[1];

    local[0].iov_base = (void*)buf;
    local[0].iov_len = len;
    remote[0].iov_base = (void*)ptr;
    remote[0].iov_len = len;

    if (process_vm_writev(tcp->pid, local, 1, remote, 1, 0) < 0) {
        err(1, "writev failed: pid=%d", tcp->pid);
    }
}

void sbox_rewrite_arg(struct tcb *tcp, int arg, long val)
{
    struct user_regs_struct regs = tcp->regs;
    set_regs_with_arg(&regs, arg, val);
    ptrace(PTRACE_SETREGS, tcp->pid, 0, &regs);
}

void sbox_hijack_str(struct tcb *tcp, int arg, char *new)
{
    struct user_regs_struct regs = tcp->regs;

    tcp->hijacked = 1;
    tcp->hijacked_old_arg = arg;
    tcp->hijacked_old_val = tcp->u_arg[arg];

    /* XXX. need to find the readonly memory */
    long new_ptr = regs.rsp - PATH_MAX * (arg+1);
    sbox_remote_write(tcp, new_ptr, new, strlen(new)+1);
    sbox_rewrite_arg(tcp, arg, new_ptr);
}

void sbox_restore_hijack(struct tcb *tcp)
{
    sbox_rewrite_arg(tcp, tcp->hijacked_old_arg, tcp->hijacked_old_val);
    tcp->hijacked = 0;
}

void sbox_sync_parent_dirs(char *hpn, char *spn)
{
    // already synced
    if (exists_parent_dir(spn)) {
        return;
    }

    // don't have to sync
    if (!exists_parent_dir(hpn)) {
        return;
    }

    dbg(path, "sync path '%s'", hpn);
    
    // find the last / and split for a while
    char *last = spn + strlen(spn);
    for (; *last != '/' && last >= spn; last --);
    if (*last != '/') {
        return;
    }

    // split spn to iterate
    *last = '\0';

    int done = 0;
    int ret = 0;
    char *iter = spn + opt_root_len;

    while (!done && *(++iter) != '\0') {
        // find next '/' or '\0'
        for (; *iter != '\0' && *iter != '/'; iter ++);
        // done
        if (*iter == '\0') {
            done = 1;
        }
        // make a dir
        *iter = '\0';
        // fetch the mode
        struct stat hpn_stat;
        if (stat(spn + opt_root_len, &hpn_stat) < 0) {
            break;
        }
        ret = mkdir(spn, hpn_stat.st_mode);
        if (done) {
            break;
        }
        // continue
        *iter = '/';
    }

    // restore
    *last = '/';
}

void sbox_open_enter(struct tcb *tcp, int arg, mode_t mode)
{
    mode_t accmode;
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    get_hpn_from_arg(tcp, arg, hpn, PATH_MAX);
    get_spn_from_hpn(hpn, spn, PATH_MAX);

    // NOTE. ignore /dev and /proc
    //   /proc: need to emulate /proc/pid/fd/*
    //   /dev : need to verify what is correct to do
    if (strncmp(hpn, "/dev/", 5) == 0 || strncmp(hpn, "/proc/", 6) == 0) {
        return;
    }

    /* XXX */
    /*
    if (strstr(hpn, "testme")) {
        printf("hpn: %s\nspn: %s\n", hpn, spn);
        sbox_hijack_str(tcp, arg, "/tmp/x");
    }
    */

    // TODO. deleted (or masked) file/dir

    // whenever path exists in the sandbox, go to there
    if (path_exists(spn)) {
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // readonly, just use hostfs
    accmode = mode & O_ACCMODE;
    if (accmode == O_RDONLY) {
        return;
    }

    // trunc
    if (mode & O_TRUNC) {
        sbox_sync_parent_dirs(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // write or read/write
    if (accmode == O_RDWR || accmode == O_RDWR) {
        sbox_sync_parent_dirs(hpn, spn);
        copyfile(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
    }
}
