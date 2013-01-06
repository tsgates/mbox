#include "defs.h"
#include "sbox.h"

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

void sbox_sync_sbox_path(char *hpn, char *spn) 
{
    if (path_exists(hpn) && !path_exists(spn)) {
        /* XXX. make it same as hostfs's mode */
        mkdirp(spn, 0755);
    }
}

void sbox_copy_to_sbox(char *hpn, char *spn) 
{
    
}

void sbox_open_enter(struct tcb *tcp, int arg, mode_t mode)
{
    mode_t accmode;
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    get_hpn_from_arg(tcp, arg, hpn, PATH_MAX);
    get_spn_from_hpn(hpn, spn, PATH_MAX);

    /* XXX */
    /*
    if (strstr(hpn, "testme")) {
        printf("hpn: %s\nspn: %s\n", hpn, spn);
        sbox_hijack_str(tcp, arg, "/tmp/x");
    }
    */
    
    // deleted (or masked) file/dir
    
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
        sbox_sync_sbox_path(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // write or read/write
    if (accmode == O_RDWR || accmode == O_RDWR) {
        sbox_sync_sbox_path(hpn, spn);
        sbox_copy_to_sbox(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
    }
}
