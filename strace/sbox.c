#include "defs.h"
#include "sbox.h"
#include "dbg.h"

#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/stat.h>

static
void sbox_setenv(void)
{
    char spwd[PATH_MAX];
    char hpwd[PATH_MAX];

    getcwd(hpwd, sizeof(hpwd));
    
    // setenvs for test scripts
    if (!getenv("SPWD")) {
        snprintf(spwd, sizeof(spwd), "%s/%s", opt_root, hpwd);
        setenv("SPWD", spwd, 1);
    }
    if (!getenv("HPWD")) {
        setenv("HPWD", hpwd, 1);
    }
}

void sbox_check_test_cond(char *pn, char *key)
{
    sbox_setenv();

    FILE *fp = fopen(pn , "r");
    if (!fp) {
        err(1, "fopen");
    }

    char m1[128];
    char m2[128];
    snprintf(m1, sizeof(m1), "# %s:", key);
    snprintf(m2, sizeof(m2), "#%s:", key);

    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, fp) != -1) {
        if (strncmp(line, m1, strlen(m1)) == 0 ||
            strncmp(line, m2, strlen(m2)) == 0) {
            char *cmd = strchr(line, ':');
            cmd ++;
            if (system(cmd) != 0) {
                dbg(info, "Failed to check %s condition: %s", key, cmd);
                exit(1);
            }
        }
    }

    fclose(fp);
}

//
// return a path relative to fd from a syscall
//
void get_hpn_from_fd_and_arg(struct tcb *tcp, int fd, int arg, char *path, int len)
{
    // ugly realpath requirement
    assert(len == PATH_MAX);

    char pn[PATH_MAX];
    const long ptr = tcp->u_arg[arg];
    if (umovestr(tcp, ptr, PATH_MAX, pn) <= 0) {
        pn[0] = '\0';
    }

    if (fd == AT_FDCWD) {
        realpath(pn, path);
    } else {
        char root[PATH_MAX];
        char proc[PATH_MAX];
        char fdpath[PATH_MAX];

        snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", tcp->pid, fd);
        if (readlink(proc, root, sizeof(root)) < 0) {
            /* fd doesn't exist*/
            root[0] = '\0';
        }
        snprintf(fdpath, sizeof(fdpath), "%s/%s", root, pn);
        realpath(fdpath, path);
        dbg(test, "XXX %d/%s -> %s", fd, pn, fdpath);
    }
}

void get_spn_from_hpn(char *hpn, char *spn, int len)
{
    snprintf(spn, len, "%s%s", opt_root, hpn);
}

void set_regs_with_arg(struct user_regs_struct *regs, int arg, long val)
{
    switch (arg) {
    case  0: regs->rdi = val; break;
    case  1: regs->rsi = val; break;
    case  2: regs->rdx = val; break;
    case  3: regs->r10 = val; break;
    case  4: regs->r8  = val; break;
    case  5: regs->r9  = val; break;
    case -1: regs->rax = val; break;
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

    int n = tcp->hijacked;
    tcp->hijacked_args[n] = arg;
    tcp->hijacked_vals[n] = tcp->u_arg[arg];
    tcp->hijacked ++;

    /* XXX. need to find the readonly memory */
    long new_ptr = regs.rsp - PATH_MAX * (arg+1);
    sbox_remote_write(tcp, new_ptr, new, strlen(new)+1);
    sbox_rewrite_arg(tcp, arg, new_ptr);
}

void sbox_hijack_arg(struct tcb *tcp, int arg, long new)
{
    int n = tcp->hijacked;
    tcp->hijacked_args[n] = arg;
    tcp->hijacked_vals[n] = tcp->u_arg[arg];
    tcp->hijacked ++;

    sbox_rewrite_arg(tcp, arg, new);
}

void sbox_restore_hijack(struct tcb *tcp)
{
    int i;
    for (i = 0; i < tcp->hijacked; i ++) {
        // ignore restoring rax
        if (tcp->hijacked_args[i] == ARG_RET) {
            continue;
        }
        sbox_rewrite_arg(tcp, tcp->hijacked_args[i], tcp->hijacked_vals[i]);
    }
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

static
void sbox_open_enter(struct tcb *tcp, int fd, int arg, int oflag)
{
    int accmode;
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
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
    accmode = oflag & O_ACCMODE;
    if (accmode == O_RDONLY) {
        return;
    }

    // trunc
    if (oflag & O_TRUNC) {
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

int sbox_open(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_open_enter(tcp, AT_FDCWD, 0, tcp->u_arg[1]);
    }
    return 0;
}

int sbox_openat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_open_enter(tcp, tcp->u_arg[0], 1, tcp->u_arg[2]);
    }
    return 0;
}

int sbox_rewrite_path(struct tcb *tcp, int fd, int arg, int flag)
{
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
    get_spn_from_hpn(hpn, spn, PATH_MAX);

    // XXX. or hpn is deleted
    if (flag != RW_NONE || path_exists(spn)) {
        // to be written to spn, so sync parent paths
        if (flag != RW_NONE) {
            sbox_sync_parent_dirs(hpn, spn);
        }

        // writing intent (not force)
        if (flag == RW_WRITING) {
            copyfile(hpn, spn);
        }

        // finally hijack path (arg)
        sbox_hijack_str(tcp, arg, spn);

        dbg(path, "> rewrite to %s", spn);
    }

    return 0;
}

int sbox_stat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, RW_NONE);
    }
    return 0;
}

int sbox_newfstatat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, RW_NONE);
    }
    return 0;
}

int sbox_mkdir(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, RW_FORCE);
    }
    return 0;
}

int sbox_mkdirat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, RW_FORCE);
    }
    return 0;
}

int sbox_rmdir(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, RW_FORCE);
    } else {
        /* XXX */
    }
    return 0;
}

int sbox_unlink_general(struct tcb *tcp, int fd, int arg)
{
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    if (entering(tcp)) {
        sbox_rewrite_path(tcp, fd, arg, RW_FORCE);
    } else {
        // failed on sandbox
        if (tcp->regs.rax < 0) {
            // get hpn/spn
            get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
            get_spn_from_hpn(hpn, spn, PATH_MAX);

            // emulate successful deletion
            if (path_exists(hpn)) {
                sbox_hijack_arg(tcp, ARG_RET, 0);
            }
        }
    }
    return 0;
}

int sbox_unlink(struct tcb *tcp)
{
    return sbox_unlink_general(tcp, AT_FDCWD, 0);
}

int sbox_unlinkat(struct tcb *tcp)
{
    return sbox_unlink_general(tcp, tcp->u_arg[0], 1);
}

int sbox_access_general(struct tcb *tcp, int fd, int arg) 
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, fd, arg, RW_NONE);
    }
    return 0;
}

int sbox_access(struct tcb *tcp)
{
    return sbox_access_general(tcp, AT_FDCWD, 0);
}

int sbox_faccessat(struct tcb *tcp) 
{
    return sbox_unlink_general(tcp, tcp->u_arg[0], 1);
}