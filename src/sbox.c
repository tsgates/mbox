#include "defs.h"
#include "sbox.h"
#include "dbg.h"
#include "fsmap.h"
#include "netmap.h"
#include "md5map.h"

#include <err.h>
#include <dirent.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/seccomp.h>

struct linux_dirent {
    long           d_ino;
    off_t          d_off;
    unsigned short d_reclen;
    char           d_name[];
};

#define min(a, b) ((a) < (b)? (a): (b))

/* os global structure */
static struct fsmap* os_fsmap = NULL; /* deleted fs map */
static struct md5map* os_md5map    = NULL; /* keep md5sums of original files */
static struct netmap* os_netmap = NULL;

int sbox_is_deleted(char *path)
{
    int s = path_status(os_fsmap, path);
    return s & PATH_DELETED;
}

int sbox_is_direct(char *path)
{
    int s = path_status(os_fsmap, path);
    return s & PATH_DIRECT;
}

static inline
int __sbox_delete_file(char *path)
{
    add_path_to_fsmap(&os_fsmap, path, PATH_DELETED);
    return 1;
}

static
int __sbox_delete_dir(char *path)
{
    const int path_len = strlen(path);
    struct fsmap *s;
    struct fsmap *tmp;

    HASH_ITER(hh, os_fsmap, s, tmp) {
        if (strncmp(s->key, path, path_len) == 0) {
            dbg(fsmap, "merging deleted file: %s", s->key);
            HASH_DEL(os_fsmap, s);
            free(s);
        }
    }

    add_path_to_fsmap(&os_fsmap, path, PATH_DELETED);
    return 1;
}

static
int __sbox_allow_path(char *path)
{
    add_path_to_fsmap(&os_fsmap, path, PATH_ALLOWED);
    return 1;
}

static
int __sbox_direct_path(char *path)
{
    add_path_to_fsmap(&os_fsmap, path, PATH_DIRECT);
    return 1;
}

static
char *__sbox_meta_file(void)
{
    static char *path = NULL;
    if (!path) {
        path = (char *)safe_malloc(PATH_MAX);
        snprintf(path, PATH_MAX, "%s.meta", opt_root);
    }
    return path;
}


static
void _sbox_flush_deleted_files(void)
{
    // only if we have something to flush
    if (!os_fsmap) {
        return;
    }

    FILE *fp = fopen(__sbox_meta_file(), "w+");
    if (!fp) {
        err(1, "fopen");
    }

    struct fsmap *s;
    struct fsmap *tmp;

    fprintf(stderr, "Deleted Files:\n");
    HASH_ITER(hh, os_fsmap, s, tmp) {
        if (s->val == PATH_DELETED) {
            fprintf(stderr, " > %s (%x)\n", s->key, s->val);
            fprintf(fp, "D:%s:%d\n", s->key, s->val);
        }
    }

    fclose(fp);
}

static
void _sbox_flush_md5sums(void)
{
    // only if we have something to flush
    if (!os_md5map || !opt_md5) {
        return;
    }

    FILE *fp = fopen(__sbox_meta_file(), "a+");
    if (!fp) {
        err(1, "fopen");
    }

    struct md5map *s;
    struct md5map *tmp;

    fprintf(stderr, "MD5 Sums of original files:\n");
    HASH_ITER(hh, os_md5map, s, tmp) {
        int i;
        char md5str[MD5_DIGEST_LENGTH*2+1];
        for (i = 0; i < MD5_DIGEST_LENGTH; i ++) {
            snprintf(md5str+i*2, 3, "%02x", (unsigned int)s->val[i]);
        }

        fprintf(stderr, " > %s (%s)\n", s->key, md5str);
        fprintf(fp, "M:%s:%s\n", s->key, md5str);
    }

    fclose(fp);
}

void sbox_flush_meta(void)
{
    _sbox_flush_deleted_files();
    _sbox_flush_md5sums();
}

void sbox_load_meta(void)
{
    FILE *fp = fopen(__sbox_meta_file() , "r");
    if (!fp) {
        /* okay */
        return;
    }

    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, fp) != -1) {
        if (len < 2 || line[1] != ':') {
            errx(1, "Malformed %s file", __sbox_meta_file());
        }

        char *key = line+2;
        char *val = strstr(key, ":");
        if (!val) {
            errx(1, "Malformed %s file", __sbox_meta_file());
        }

        *val = '\0';
        val ++;

        switch (line[0]) {
        case 'D': {
            int flag;
            sscanf(val, "%d", &flag);
            add_path_to_fsmap(&os_fsmap, key, flag);
            break;
        }
        case 'M': {
            int i;
            byte md5sum[MD5_DIGEST_LENGTH];
            for (i = 0; i < MD5_DIGEST_LENGTH; i ++) {
                unsigned int hex;
                sscanf(val+i*2, "%02x", &hex);
                md5sum[i] = (unsigned int) hex;
            }
            add_md5_to_map(&os_md5map, key, md5sum);
            break;
        }
        default:
            errx(1, "Unknown meta data: %c (%s)", line[0], line);
        }
    }

    fclose(fp);
}

void sbox_init(void)
{
    sbox_load_meta();
}

void sbox_cleanup(FILE *outf)
{
    // dump system-wide logs
    if (systemlog) {
        fprintf(outf, "Network Summary:\n");
        // per each process
        struct systemlog *logs;
        for (logs = systemlog; logs != NULL; logs = logs->next) {
            struct auditlog *iter;
            for (iter = logs->logs; iter != NULL; iter = iter->prev) {
                fprintf(outf, " > [%d] %s\n", logs->pid, iter->log);
            }
        }
    }

    // dump into a permanent place
    sbox_flush_meta();

    // NOTE. we are going to die anyway.
    // free_fsmap(os_fsmap);
    // free_systemlog(systemlog);
}

static
void sbox_setenv(void)
{
    // setenvs for test scripts
    //  - $HOME
    //  - $SHOME
    //  - $SPWD
    //  - $HPWD
    char home[PATH_MAX];
    char spwd[PATH_MAX];
    char hpwd[PATH_MAX];

    getcwd(hpwd, sizeof(hpwd));

    if (!getenv("SPWD")) {
        snprintf(spwd, sizeof(spwd), "%s%s", opt_root, hpwd);
        setenv("SPWD", spwd, 1);
        dbg(testcond, "setenv $SPWD=%s", spwd);
    }

    if (!getenv("HPWD")) {
        setenv("HPWD", hpwd, 1);
        dbg(testcond, "setenv $HPWD=%s", hpwd);
    }

    if (!getenv("SHOME") && getenv("HOME")) {
        snprintf(home, sizeof(home), "%s%s", opt_root, getenv("HOME"));
        setenv("SHOME", home, 1);
        dbg(testcond, "setenv $SHOME=%s", home);
    }
}

void sbox_check_test_cond(const char *pn, const char *key)
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
            cmd[strlen(cmd)-1] = '\0';
            dbg(info, "Check %s: %s", key, cmd);
            if (system(cmd) != 0) {
                dbg(info, "Failed to check %s condition: %s", key, cmd);
                exit(1);
            }
        }
    }

    fclose(fp);
}

static
int get_fd_path(int pid, int fd, char *path, int len)
{
    ssize_t read;
    char proc[PATH_MAX];

    snprintf(proc, sizeof(proc), "/proc/%d/fd/%d", pid, fd);
    if ((read = readlink(proc, path, len - 1)) < 0) {
        /* fd doesn't exist*/
        path[0] = '\0';
        return 0;
    }
    path[read] = '\0';
    dbg(test, "> %s", path);

    return 1;
}

static
int get_fd_hpn(int pid, int fd, char *path, int len)
{
    int fd_in_sbox = 0;

    // XXX. ugly
    if (!get_fd_path(pid, fd, path, len)) {
        return 0;
    }

    // check if cwd is under sboxfs
    if (is_in_sboxfs(path)) {
        char *iter;
        for (iter = path; *(iter + opt_root_len) != '\0'; iter ++) {
            *iter = *(iter + opt_root_len);
        }
        *iter = '\0';
        fd_in_sbox = 1;
    }

    return fd_in_sbox;
}

static
int get_cwd_hpn(int pid, char *path, int len)
{
    int cwd_in_sbox = 0;
    ssize_t read;
    char proc[PATH_MAX];

    snprintf(proc, sizeof(proc), "/proc/%d/cwd", pid);
    if ((read = readlink(proc, path, len - 1)) < 0) {
        err(1, "proc/cwd");
    }
    path[read] = '\0';

    // check if cwd is under sboxfs
    if (is_in_sboxfs(path)) {
        char *iter;
        for (iter = path; *(iter + opt_root_len) != '\0'; iter ++) {
            *iter = *(iter + opt_root_len);
        }
        *iter = '\0';
        dbg(test, "cwd in sboxfs: %s", path);
        cwd_in_sbox = 1;
    }

    return cwd_in_sbox;
}

//
// get a path relative to fd from a syscall
// return 1 if cwd is on the sboxfs
//
static
int get_hpn_from_fd_and_arg(struct tcb *tcp, int fd, int arg, char *path, int len)
{
    // ugly realpath requirement
    assert(len == PATH_MAX);

    char pn[PATH_MAX];
    const long ptr = tcp->u_arg[arg];
    // fprintf(stderr, "XXX: read %x (pid=%d)\n", ptr, tcp->pid);
    if (ptr == 0 || umovestr(tcp, ptr, PATH_MAX, pn) <= 0) {
        pn[0] = '\0';
        return -1;
    }
    if (pn[0] == '\0') {
        return -1;
    }
    // fprintf(stderr, "XXX: %s\n", pn);

    // abspath
    if (pn[0] == '/') {
        strncpy(path, pn, len);
        normalize_path(path);
        return 0;
    }

    // relpath, so resolve it
    int cwd_in_sbox = 0;
    char root[PATH_MAX];
    if (fd == AT_FDCWD) {
        // read /proc/pid/cwd
        cwd_in_sbox = get_cwd_hpn(tcp->pid, root, sizeof(root));
    } else {
        // read /proc/pid/fd/#
        cwd_in_sbox = get_fd_hpn(tcp->pid, fd, root, sizeof(root));
    }

    snprintf(path, len, "%s/%s", root, pn);
    normalize_path(path);

    return cwd_in_sbox;
}

static
void get_spn_from_hpn(char *hpn, char *spn, int len)
{
    snprintf(spn, len, "%s%s", opt_root, hpn);
}

static
void set_regs_with_arg(struct user_regs_struct *regs, int arg, long val)
{
    switch (arg) {
    case 0: regs->rdi = val; break;
    case 1: regs->rsi = val; break;
    case 2: regs->rdx = val; break;
    case 3: regs->r10 = val; break;
    case 4: regs->r8  = val; break;
    case 5: regs->r9  = val; break;
    case 6: regs->rax = val; break;
    default:
        dbg(fatal, "Unknown argument: %d\n", arg);
        exit(1);
    }
}

#ifdef SBOX_USE_WRITEV
void sbox_remote_write(struct tcb *tcp, long ptr, char *buf, int len)
{
    struct iovec local[1], remote[1];

    local[0].iov_base  = (void*)buf;
    local[0].iov_len   = len;
    remote[0].iov_base = (void*)ptr;
    remote[0].iov_len  = len;

    if (process_vm_writev(tcp->pid, local, 1, remote, 1, 0) < 0) {
        err(1, "writev failed: pid=%d", tcp->pid);
    }
}
#else
void sbox_remote_write(struct tcb *tcp, long ptr, char *buf, int len)
{
    // off
    // [..bb]...[ee..]
    //    ^        ^
    //    +-- ptr  |
    // [byte]      |
    //             rear
    //

    long off = ptr % 8;
    if (off) {
        int i;
        long read = ptrace(PTRACE_PEEKDATA, tcp->pid, ptr - off, 0, 0);
        for (i = off; i < 8 - off; i ++) {
            *((char *)&read + i) = buf[i - off];
        }
        if (ptrace(PTRACE_POKEDATA, tcp->pid, ptr - off, read, 0) < 0)
            sbox_stop(tcp, "Error writting to %ld", ptr);

        len -= 8 - off;
        ptr += 8 - off;
        buf += 8 - off;
    }

    for (; len > 0; len -= 8, buf += 8, ptr += 8) {
        if (ptrace(PTRACE_POKEDATA, tcp->pid, ptr, *(long *)(buf), 0) < 0)
            sbox_stop(tcp, "Error writting to %ld", ptr);
    }

    if (len > 0) {
        int i;
        long read = ptrace(PTRACE_PEEKDATA, tcp->pid, ptr, 0, 0);
        for (i = 0; i < len; i ++) {
            *((char *)&read + i) = buf[i];
        }
        if (ptrace(PTRACE_POKEDATA, tcp->pid, ptr, read, 0) < 0)
            sbox_stop(tcp, "Error writting to %ld", ptr);
    }
}
#endif

void sbox_rewrite_arg(struct tcb *tcp, int arg, long val)
{
    struct user_regs_struct *regs = &tcp->regs;
    set_regs_with_arg(regs, arg, val);
    ptrace(PTRACE_SETREGS, tcp->pid, 0, regs);
}

void sbox_rewrite_ret(struct tcb *tcp, long long ret)
{
    if (ret == 0) {
        tcp->u_error = 0;
    }

    tcp->u_rval = ret;
    sbox_rewrite_arg(tcp, ARG_RET, ret);
}

void sbox_hijack_mem(struct tcb *tcp, int arg, void *new, int len)
{
    struct user_regs_struct *regs = &tcp->regs;

    int n = tcp->hijacked;
    tcp->hijacked_args[n] = arg;
    tcp->hijacked_vals[n] = tcp->u_arg[arg];
    tcp->hijacked ++;

    /* write to the readonly memory to avoid race */
    long new_ptr;
    if (tcp->readonly_ptr == -1) {
        new_ptr = regs->rsp - PATH_MAX * (arg+1);
    } else {
        //
        // FIXME. PATH_MAX is the correct value, but it is
        // big enough to overwrite important things in the
        // elf header. so use 256 for now, in fact, there
        // are just few syscalls hijacking multiple args.
        //
        new_ptr = tcp->readonly_ptr + 256 * arg;
    }

    sbox_remote_write(tcp, new_ptr, new, len);
    sbox_rewrite_arg(tcp, arg, new_ptr);
}

void sbox_hijack_str(struct tcb *tcp, int arg, char *new)
{
    sbox_hijack_mem(tcp, arg, new, strlen(new)+1);
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
        mkdir(spn, hpn_stat.st_mode);
        if (done) {
            break;
        }
        // continue
        *iter = '/';
    }

    // restore
    *last = '/';
}

int sbox_rewrite_path(struct tcb *tcp, int fd, int arg, int flag)
{
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    if (get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX) == -1) {
        return -1;
    }
    get_spn_from_hpn(hpn, spn, PATH_MAX);

    if (sbox_is_direct(hpn)) {
        sbox_hijack_str(tcp, arg, hpn);
        return 1;
    }

    // satisfying one of rewrite conditions
    if (flag != READWRITE_READ  \
        || sbox_is_deleted(hpn) \
        || path_exists(spn)) {

        // to be written to spn, so sync parent paths
        if (flag != READWRITE_READ) {
            sbox_sync_parent_dirs(hpn, spn);
        }

        // writing intent (not force)
        if (flag == READWRITE_WRITE) {
            byte md5[MD5_DIGEST_LENGTH];
            if (copyfile(hpn, spn, md5)) {
                add_md5_to_map(&os_md5map, hpn, md5);
            }
        }

        // finally hijack path (arg)
        sbox_hijack_str(tcp, arg, spn);

        dbg(path, "rewrite to %s", spn);
    }

    return 1;
}

static
void sbox_open_enter(struct tcb *tcp, int fd, int arg, int oflag)
{
    int cwd_in_sboxfs;
    int accmode;
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    cwd_in_sboxfs = get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
    get_spn_from_hpn(hpn, spn, PATH_MAX);

    // NOTE. ignore /dev and /proc
    //   /proc: need to emulate /proc/pid/fd/*
    //   /dev : need to verify what is correct to do
    if (strncmp(hpn, "/dev/", 5) == 0 || strncmp(hpn, "/proc/", 6) == 0) {
        sbox_hijack_str(tcp, arg, hpn);
        return;
    }

    if (sbox_is_direct(hpn)) {
        sbox_hijack_str(tcp, arg, hpn);
        return;
    }

    // if the path is deleted
    if (sbox_is_deleted(hpn)) {
        dbg(open, "open deleted file: %s", hpn);
        sbox_sync_parent_dirs(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // whenever path exists in the sandbox, go to there
    if (path_exists(spn)) {
        dbg(open, "exists in sbox: %s", spn);
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // readonly, just use hostfs
    accmode = oflag & O_ACCMODE;
    if (accmode == O_RDONLY) {
        // complicated situation arises if cwd in sboxfs
        if (cwd_in_sboxfs) {
            // rewrite abspath to open hpn (ignoring cwd effect)
            dbg(open, "writing back to hpn: %s", hpn);
            sbox_hijack_str(tcp, arg, hpn);
        }
        return;
    }

    // trunc or write only
    if (oflag & O_TRUNC || accmode == O_WRONLY) {
        dbg(open, "open(%s, TRUNC)", spn);
        sbox_sync_parent_dirs(hpn, spn);
        sbox_hijack_str(tcp, arg, spn);
        return;
    }

    // write or read/write
    if (accmode == O_RDWR || accmode == O_RDWR) {
        byte md5[MD5_DIGEST_LENGTH];
        dbg(open, "open(%s, RW)", spn);
        sbox_sync_parent_dirs(hpn, spn);
        if (copyfile(hpn, spn, md5)) {
            add_md5_to_map(&os_md5map, hpn, md5);
        }
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

int sbox_creat(struct tcb *tcp)
{
    // creat(path, mode) == open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_FORCE);
    }
    return 0;
}

int sbox_stat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_READ);
    }
    return 0;
}

int sbox_newfstatat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, READWRITE_READ);
    }
    return 0;
}

int sbox_mkdir(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_FORCE);
    }
    return 0;
}

int sbox_mkdirat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, READWRITE_FORCE);
    }
    return 0;
}

int sbox_rmdir(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_FORCE);
    } else {
        // successfully delete a directory
        if (tcp->regs.rax == 0) {
            char hpn[PATH_MAX];
            get_hpn_from_fd_and_arg(tcp, AT_FDCWD, 0, hpn, PATH_MAX);

            // clean up all files in the directory
            // NOTE. can be optimized if need
            __sbox_delete_dir(hpn);
        }
    }
    return 0;
}

int sbox_unlink_general(struct tcb *tcp, int fd, int arg, int flag)
{
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    if (entering(tcp)) {
        sbox_rewrite_path(tcp, fd, arg, READWRITE_FORCE);
    } else {
        // get hpn/spn
        get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
        get_spn_from_hpn(hpn, spn, PATH_MAX);

        if (sbox_is_direct(hpn))
            return 0;

        // failed on sandbox
        if ((long)tcp->regs.rax < 0) {
            // emulate successful deletion
            if (!sbox_is_deleted(hpn) && path_exists(hpn)) {
                dbg(path, "emulate successful unlink: %s", hpn);
                sbox_rewrite_ret(tcp, 0);
            }
        }

        // mark the file deleted
        if ((long)tcp->regs.rax == 0) {
            if (flag == AT_REMOVEDIR) {
                __sbox_delete_dir(hpn);
            } else {
                __sbox_delete_file(hpn);
            }
        }
    }
    return 0;
}

int sbox_unlink(struct tcb *tcp)
{
    return sbox_unlink_general(tcp, AT_FDCWD, 0, 0);
}

int sbox_unlinkat(struct tcb *tcp)
{
    return sbox_unlink_general(tcp, tcp->u_arg[0], 1, tcp->u_arg[2]);
}

int sbox_access_general(struct tcb *tcp, int fd, int arg)
{
    char hpn[PATH_MAX];
    char spn[PATH_MAX];

    if (entering(tcp)) {
        sbox_rewrite_path(tcp, fd, arg, READWRITE_READ);
    } else {
        // exiting and fakeroot enabled
        if (opt_fakeroot && tcp->regs.rax != 0) {
            get_hpn_from_fd_and_arg(tcp, fd, arg, hpn, PATH_MAX);
            get_spn_from_hpn(hpn, spn, PATH_MAX);

            // if exists in host fs, return ok
            if (path_exists(hpn)) {
                dbg(fakeroot, "allow access(%s) = 0", hpn);
                sbox_rewrite_ret(tcp, 0);
            }
        }
    }
    return 0;
}

int sbox_access(struct tcb *tcp)
{
    return sbox_access_general(tcp, AT_FDCWD, 0);
}

int sbox_faccessat(struct tcb *tcp)
{
    return sbox_access_general(tcp, tcp->u_arg[0], 1);
}

int sbox_getdents(struct tcb *tcp)
{
    static char buf[4096];
    static char tmp[4096];

    char spn[PATH_MAX];
    char hpn[PATH_MAX];

    // after pumping files on sandboxfs
    if (exiting(tcp) && tcp->regs.rax == 0) {
        int hostfd = tcp->u_arg[0];

        // NOTE. we only support, a single contiguous getdent()
        if (!(tcp->dentfd_sbox < 0) && tcp->dentfd_host != hostfd) {
            dbg(getdents, "optimistically close(host:%d)", tcp->dentfd_host);
            close(tcp->dentfd_sbox);
            tcp->dentfd_sbox = -1;
            tcp->dentfd_host = -1;
            // should fall into the below if statement
        }

        // just done with sandboxfs
        if (tcp->dentfd_sbox < 0) {
            // get hpn
            if (!get_fd_path(tcp->pid, hostfd, spn, sizeof(spn))) {
                // wrong fd anyway
                return 0;
            }

            // check if calling to sandboxfs
            if (strncmp(spn, opt_root, opt_root_len) >= 0) {

                // XXX. meanwhile, it can modify the same dir in sboxfs, so
                // the getdents(hostfs) might be even wrong. we can handle
                // this situation later.
                ifdbg(getdents, {
                        char xxx[PATH_MAX];
                        snprintf(xxx, sizeof(PATH_MAX), "%s%s", opt_root, spn);
                        if (access(xxx, F_OK) == 0) {
                            dbg(getdents, "XXX. %s exists", xxx);
                        }
                    }
                );

                // return if calls on hostfs
                return 0;
            }

            strncpy(hpn, spn + opt_root_len, sizeof(hpn));
            strncpy(tcp->dentfd_spn, spn, sizeof(tcp->dentfd_spn));

            tcp->dentfd_host = hostfd;
            tcp->dentfd_sbox = open(hpn, O_RDONLY | O_DIRECTORY);
            if (tcp->dentfd_sbox < 0) {
                return 0;
            }
        }

        dbg(getdents, "handle files on sboxfs (host:%d)", tcp->dentfd_host);

        // manually invoke getdents on hostfs.
        // to overwrite less than the memory of tracee (dirp), we use
        // buf with the size less that the given value (count).
        int len = syscall(SYS_getdents, tcp->dentfd_sbox, buf,
                          min(sizeof(buf), tcp->u_arg[2]));

        // done with pumping dirs of sandboxfs
        if (len == 0) {
            dbg(getdents, "No more files in sbox, cloes host:%d", tcp->dentfd_host);

            close(tcp->dentfd_sbox);
            tcp->dentfd_sbox = -1;
            tcp->dentfd_host = -1;
            return 0;
        }

        // filter dir contents
        int dst_iter = 0;
        int src_iter = 0;
        while (src_iter < len) {
            struct linux_dirent *d = (struct linux_dirent *)(buf + src_iter);
            // ignore . and ..
            if (d->d_name[0] == '.') {
                if (d->d_name[1] == '\0' ||
                    (d->d_name[1] == '.' && d->d_name[2] == '\0')) {
                    src_iter += d->d_reclen;
                    continue;
                }
            }

            snprintf(spn, sizeof(spn), "%s/%s", tcp->dentfd_spn, d->d_name);
            // ignore if it is a deleted entry
            if (sbox_is_deleted(spn + opt_root_len)) {
                src_iter += d->d_reclen;
                continue;
            }

            // ignore dentry if exists in sandboxfs
            if (path_exists(spn)) {
                dbg(getdents, "[%3d] found in sbox: %s", src_iter, spn);
                src_iter += d->d_reclen;
                continue;
            }

            // copy to dest
            memcpy(tmp + dst_iter, buf + src_iter, d->d_reclen);
            src_iter += d->d_reclen;
            dst_iter += d->d_reclen;
        }

        // copy buf/ret to tracee
        dbg(getdents, "return: %d", dst_iter);
        sbox_rewrite_ret(tcp, dst_iter);
        sbox_remote_write(tcp, tcp->u_arg[1], tmp, dst_iter);
    }

    return 0;
}

/*
 * allows chdir into sboxfs or hostfs since we sanitize getcwd()
 *
 * NOTE. fchdir() doesn't need to be handled because open() already
 * rewrites the path if needed.
 */
int sbox_chdir(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_READ);
    }
    return 0;
}

int sbox_getcwd(struct tcb *tcp)
{
    // ret = len(buf)
    const long ret = tcp->regs.rax;

    if (exiting(tcp) && ret > 0) {
        char pn[PATH_MAX];
        const long ptr = tcp->u_arg[0];

        if (umovestr(tcp, ptr, PATH_MAX, pn) <= 0) {
            err(1, "failed to copy string from getcwd buf");
        }

        if (is_in_sboxfs(pn)) {
            char *hpn = pn + opt_root_len;
            sbox_remote_write(tcp, ptr, hpn, strlen(hpn)+1);
            sbox_rewrite_ret(tcp, ret - opt_root_len);
        }
    }
    return 0;
}

int sbox_rename(struct tcb *tcp)
{

    if (entering(tcp)) {
        char hpn[PATH_MAX];
        char spn[PATH_MAX];

        get_hpn_from_fd_and_arg(tcp, AT_FDCWD, 0, hpn, PATH_MAX);
        get_spn_from_hpn(hpn, spn, PATH_MAX);

        if (!path_exists(hpn) && !path_exists(spn)) {
            dbg(xxx, "XXXXXXXXXXX:%d", 0);
            return 0;
        }

        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_READ);
        sbox_rewrite_path(tcp, AT_FDCWD, 1, READWRITE_WRITE);
    }
    return 0;
}

int sbox_renameat(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, READWRITE_READ);
        sbox_rewrite_path(tcp, tcp->u_arg[2], 3, READWRITE_WRITE);
    }
    return 0;
}

int sbox_link(struct tcb *tcp)
{
    // NOTE. consider src path is also written, so linked path
    // doesn't escape out of sboxfs
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_WRITE);
        sbox_rewrite_path(tcp, AT_FDCWD, 1, READWRITE_FORCE);
    }
    return 0;
}

int sbox_linkat(struct tcb *tcp)
{
    // see. sbox_link()
    // doesn't escape out of sboxfs
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, tcp->u_arg[0], 1, READWRITE_WRITE);
        sbox_rewrite_path(tcp, tcp->u_arg[2], 3, READWRITE_FORCE);
    }
    return 0;
}

int sbox_symlink(struct tcb *tcp)
{
    // TODO. we don't support relative symlink (.. or any) for
    // now, but we can resolve the 'path2' argument of symlink().
    // for example, if relative -> just use
    //              if absolute -> resolve the path
    char old_hpn[PATH_MAX];
    // char old_spn[PATH_MAX];
    char new_hpn[PATH_MAX];
    char new_spn[PATH_MAX];

    if (entering(tcp)) {
        if (umovestr(tcp, tcp->u_arg[0], PATH_MAX, old_hpn) <= 0) {
            sbox_stop(tcp, "failed to copy from symlink");
        }

        get_hpn_from_fd_and_arg(tcp, AT_FDCWD, 1, new_hpn, PATH_MAX);
        get_spn_from_hpn(new_hpn, new_spn, PATH_MAX);

        // XXX. check if old_hpn contains ".."
        if (strstr(old_hpn, "..") != NULL) {
            sbox_stop(tcp, "old_hpn: %s", old_hpn);
        }

        sbox_rewrite_path(tcp, AT_FDCWD, 1, READWRITE_FORCE);
    }
    return 0;
}

int sbox_symlinkat(struct tcb *tcp)
{
    // see. sbox_symblink()
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_WRITE);
        sbox_rewrite_path(tcp, tcp->u_arg[1], 2, READWRITE_FORCE);
    }
    return 0;
}

int sbox_acct(struct tcb *tcp)
{
    if (entering(tcp)) {
        if (tcp->u_arg[0] == 0) {
            return 0;
        } else {
            sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_WRITE);
        }
    }
    return 0;
}

static
const char *__pf_domain(int flag)
{
    switch (flag) {
    case PF_INET:
        return "PF_INET";
    case PF_INET6:
        return "PF_INET6";
    case PF_NETLINK:
        return "PF_NETLINK";
    }
    return "PF_??";
}

int sbox_bind(struct tcb *tcp)
{
    return 0;
}

int sbox_connect(struct tcb *tcp)
{
    if (entering(tcp)) {
        struct sockaddr *sa \
            = (struct sockaddr *) safe_malloc(tcp->u_arg[2]);
        if (umoven(tcp, tcp->u_arg[1], tcp->u_arg[2], (char *)sa) < 0) {
            // can't access to sockaddr*, but ok
            free(sa);
            return 0;
        }
        // interpret af_inet
        switch (sa->sa_family) {
        case AF_INET: {
            struct netmap *n = get_net_from_netmap(os_netmap, sa);
            int v = n ? n->val : NET_LOG;
            switch (v) {
                case NET_LOG:
                    {
                        struct sockaddr_in *addr = (struct sockaddr_in *)sa;
                        sbox_add_log(tcp, "-> %s:%d",
                                inet_ntoa(addr->sin_addr),
                                ntohs(addr->sin_port));
                        sbox_hijack_mem(tcp, 1, addr, sizeof(struct sockaddr_in));
                        break;
                    }
                case NET_KILL:
                    {
                        struct sockaddr_in *addr = (struct sockaddr_in *)sa;
                        sbox_stop(tcp, "Connect to %s port %d",
                                inet_ntoa(addr->sin_addr),
                                ntohs(addr->sin_port));
                        break;
                    }
                case NET_BLOCK:
                    {
                        struct sockaddr_in *addr = (struct sockaddr_in *)
                            malloc(sizeof(struct sockaddr_in));
                        addr->sin_family = AF_INET;
                        inet_aton("127.0.0.1", &addr->sin_addr);
                        addr->sin_port = htons(1);
                        sbox_hijack_mem(tcp, 1, addr, sizeof(struct sockaddr_in));
                        free(addr);
                        break;
                    }
                case NET_ALLOW:
                    {
                        sbox_hijack_mem(tcp, 1, sa, sizeof(struct sockaddr_in));
                        break;
                    }
            }
            break;
        }

        case AF_INET6: {
            char ip[32];
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)sa;
            sbox_add_log(tcp, "-> %s:%d",
                         inet_ntop(sa->sa_family, sa, ip, tcp->u_arg[2]),
                         ntohs(addr->sin6_port));
            break;
        }
        }
        free(sa);
    }
    return 0;
}

int sbox_socket(struct tcb *tcp)
{
    if (entering(tcp)) {
        long pf = tcp->u_arg[0];
        if (opt_no_nw && pf != PF_LOCAL) {
            sbox_stop(tcp, "Access to the network (socket:%s)", __pf_domain(pf));
        }
        if (pf == PF_INET     \
            || pf == PF_INET6 \
            || pf == PF_NETLINK) {
            sbox_add_log(tcp, "Create socket(%s,...)", __pf_domain(pf));
            return 0;
        }
    }
    return 0;
}

int sbox_getroot(struct tcb *tcp)
{
    if (opt_fakeroot && exiting(tcp)) {
        dbg(fakeroot, "%s() = 0", sysent[tcp->scno].sys_name);
        sbox_rewrite_ret(tcp, 0);
    }
    return 0;
}

int sbox_chown_general(struct tcb *tcp, int fd, int arg)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, fd, arg, READWRITE_WRITE);
    } else {
        // exiting and fakeroot enabled
        if (opt_fakeroot && tcp->regs.rax == -EPERM) {
            dbg(fakeroot, "chown(fd:%d) = 0", fd);
            sbox_rewrite_ret(tcp, 0);
        }
    }
    return 0;
}

int sbox_chown(struct tcb *tcp)
{
    return sbox_chown_general(tcp, AT_FDCWD, 0);
}

int sbox_lchown(struct tcb *tcp)
{
    return sbox_chown_general(tcp, AT_FDCWD, 0);
}

int sbox_fchownat(struct tcb *tcp)
{
    return sbox_chown_general(tcp, tcp->u_arg[0], 1);
}

int sbox_fchown(struct tcb *tcp)
{
    // exiting and fakeroot enabled
    if (opt_fakeroot && exiting(tcp) && tcp->regs.rax == -EPERM) {
        dbg(fakeroot, "fchown(%ld) = 0", tcp->u_arg[0]);
        sbox_rewrite_ret(tcp, 0);
    }
    return 0;
}

int sbox_prctl(struct tcb *tcp)
{
    // support nested seccomp
    if (opt_seccomp \
        && exiting(tcp) \
        && tcp->u_arg[0] == PR_SET_SECCOMP \
        && tcp->u_arg[1] == SECCOMP_MODE_STRICT \
        && tcp->regs.rax != 0) {
        dbg(seccomp, "prctl(SECCOMP, MODE_STRICT) = 0");
        sbox_rewrite_ret(tcp, 0);
    }
    return 0;
}

int sbox_execve(struct tcb *tcp)
{
    if (entering(tcp)) {
        sbox_rewrite_path(tcp, AT_FDCWD, 0, READWRITE_READ);
    } else {
        sbox_get_readonly_ptr(tcp);
    }
    return 0;
}

DEF_SBOX_SC_PATH_AT(utimensat , 0, 1, WRITE);
DEF_SBOX_SC_PATH_AT(readlinkat, 0, 1, READ );
DEF_SBOX_SC_PATH_AT(fchmodat  , 0, 1, WRITE);
DEF_SBOX_SC_PATH_AT(mknodat   , 0, 1, WRITE);
DEF_SBOX_SC_PATH_AT(futimesat , 0, 1, WRITE);

DEF_SBOX_SC_PATH(setxattr     , 0 , WRITE);
DEF_SBOX_SC_PATH(lsetxattr    , 0 , WRITE);
DEF_SBOX_SC_PATH(removexattr  , 0 , WRITE);
DEF_SBOX_SC_PATH(lremovexattr , 0 , WRITE);
DEF_SBOX_SC_PATH(getxattr     , 0 , READ );
DEF_SBOX_SC_PATH(lgetxattr    , 0 , READ );
DEF_SBOX_SC_PATH(listxattr    , 0 , READ );
DEF_SBOX_SC_PATH(llistxattr   , 0 , READ );
DEF_SBOX_SC_PATH(statfs       , 0 , READ );
DEF_SBOX_SC_PATH(uselib       , 0 , READ );
DEF_SBOX_SC_PATH(utimes       , 0 , WRITE);
DEF_SBOX_SC_PATH(utime        , 0 , WRITE);
DEF_SBOX_SC_PATH(chmod        , 0 , WRITE);
DEF_SBOX_SC_PATH(truncate     , 0 , FORCE);
DEF_SBOX_SC_PATH(readlink     , 0 , READ );
DEF_SBOX_SC_PATH(mknod        , 0 , WRITE);

int sbox_not_allowed(struct tcb *tcp)
{
    sbox_stop(tcp, "%s is not allowed", sysent[tcp->scno].sys_name);
    return 0;
}

/* interactive mode */
static
void _sbox_walk(const char *root, const char *name,
                int (*handler)(char *spn, char *hpn))
{
    char pn[PATH_MAX];
    if (name) {
        snprintf(pn, sizeof(pn), "%s/%s", root, name);
    } else {
        strncpy(pn, root, sizeof(pn));
    }

    DIR *dir = opendir(pn);
    if (!dir) {
        err(1, "opendir");
    }

    struct dirent *d;
    while ((d = readdir(dir)) != NULL) {
        const char *n = d->d_name;
        if (d->d_type & DT_DIR) {
            if ((n[0] == '.' && n[1] == '\0') ||
                (n[0] == '.' && n[1] == '.' && n[2] == '\0')) {
                continue;
            }
            _sbox_walk(pn, n, handler);
        } else {
            char spn[PATH_MAX];
            char hpn[PATH_MAX];
            snprintf(spn, sizeof(spn), "%s/%s", pn, n);
            strncpy(hpn, spn + opt_root_len, sizeof(hpn));

            if (handler) {
                handler(spn, hpn);
            }
        }
    }

    closedir(dir);
}

static
char _prompt(const char *menu)
{
    char c;
    printf(" %s ?> ", menu);
    c = kbhit();
    printf("\n");
    return c;
}

static
int _sh_diff(char *a, char *b)
{
    int pid = fork();
    if (!pid) {
        execlp("diff", "diff", "-urN", a, b, NULL);
        err(1, "diff");
    }
    waitpid(pid, NULL, 0);
    return 0;
}

static
int _sh_commit(char *spn, char *hpn)
{
    printf("  > Commiting %s\n", hpn);
    copyfile(spn, hpn, NULL);
    return 0;
}


static
int _sbox_print_file(char *spn, char *hpn)
{
    printf(" > F: %s\n", spn);
    return 0;
}

static
void _sbox_dump_sboxfs(void)
{
    printf("Sandbox Root:\n > %s\n", opt_root);
    _sbox_walk(opt_root, NULL, _sbox_print_file);
}

static
int _sbox_interactive_menu(char *spn, char *hpn)
{
    static int opt_commit_all = 0;

    const char *menu \
        = "[C]ommit all, [c]ommit, [i]gnore, [d]iff, [l]ist tree, [q]uit";

    if (opt_commit_all) {
        _sh_commit(spn, hpn);
        return 0;
    }

    while (1) {
        // TODO. append insteresting flag instead of 'F'
        // N: new file
        // M: modified file
        // D: deleted file
        printf("F:%s\n", hpn);
        switch (_prompt(menu)) {
        case 'C':
            /* XXX. locked all files and commit at the same time */
            opt_commit_all = 1;
            /* fall-in */
        case 'c':
            _sh_commit(spn, hpn);
            /* fall-in */
        case 'i':
            return 0;
            break;
        case 'd':
            _sh_diff(spn, hpn);
            break;
        case 'l':
            _sbox_dump_sboxfs();
            break;
        case 'q':
            exit(0);
            break;
        }
    }
    return 0;
}

int sbox_interactive(void)
{
    _sbox_dump_sboxfs();
    _sbox_walk(opt_root, NULL, _sbox_interactive_menu);

    // XXX. need to walk over deleted files too

    return 0;
}

/* stop on restricted activities */
void sbox_stop(struct tcb *tcp, const char *fmt, ...)
{
    va_list args;

    fprintf(stderr, "\nStop executing pid=%d: ", tcp->pid);

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);

    kill_all(tcp);

    // clean up & info to user
    sbox_cleanup(tcp->outf);
    if (opt_interactive) {
        sbox_interactive();
    }

    exit(0);
}

/* fetch readlony memory address */
void sbox_get_readonly_ptr(struct tcb *tcp)
{
    char proc[256];
    snprintf(proc, sizeof(proc), "/proc/%d/maps", tcp->pid);

    FILE *fp = fopen(proc, "r");
    if (!fp) {
        err(1, "fopen");
    }

    long ptr = -1;
    size_t len = 0;
    char *line = NULL;

    while (getline(&line, &len, fp) != -1) {
        // find the very first non-writable area
        if (strstr(line, "r-xp")) {
            // mem ptr upto '-'
            char *del = strstr(line, "-");
            if (del) {
                sscanf(line, "%lx-", &ptr);
                break;
            }
        }
    }
    fclose(fp);

    if (line) {
        free(line);
    }

    // can't find one, just use $rsp
    if (ptr == -1) {
        dbg(info, "Can't find the readonly ptr, use $rsp");
    } else {
        dbg(info, "Found readonly memory: 0x%lx", ptr);
    }

    // verify if it is writable on debug
    if (debug_flag) {
        int dummy = 0xdeadbeef;
        sbox_remote_write(tcp, ptr, (char *)&dummy, 4);

        int read = ptrace(PTRACE_PEEKDATA, tcp->pid, (char *)ptr, 0);
        if (read != dummy) {
            dbg(info, "0x%lx is not writable", ptr);
        }
    }

    tcp->readonly_ptr = ptr;
}

void sbox_add_log(struct tcb *tcp, const char *fmt, ...)
{
    struct auditlog *entry \
        = (struct auditlog *) safe_malloc(sizeof(struct auditlog));

    va_list args;

    va_start(args, fmt);
    vsnprintf(entry->log, sizeof(entry->log), fmt, args);
    va_end(args);

    entry->prev = tcp->logs;
    tcp->logs = entry;
}

/* load profile */
static
char *__parse_val(char *line)
{
    int last = strlen(line) - 1;
    if (last > 0 && line[last] == '\n') {
        line[last] = '\0';
    }

    char *del = strchr(line, ':');
    if (!del) {
        return NULL;
    }

    del ++;
    while (*del == ' ') {
        del ++;
    }
    return del;
}

static
char *__parse_path_line(char *line)
{
    char *val = __parse_val(line);
    if (!val) {
        return NULL;
    }

    // handle ~
    char path[PATH_MAX];
    if (strbeg(val, "~")) {
        snprintf(path, sizeof(path), "%s/%s", getenv("HOME"), val + 1);
        return realpath(path, NULL);
    }

    return realpath(val, NULL);
}

static
struct sockaddr *__parse_addr_line(char *line)
{
    struct sockaddr_in *res;
    char *val = __parse_val(line);
    if (!val) {
        return NULL;
    }
    res = malloc(sizeof(struct sockaddr_in));
    res->sin_family = AF_INET;
    char *port = strchr(val, ':');
    if (port) {
        *port = '\0';
        port++;
        res->sin_port = htons(atoi(port));
    } else {
        res->sin_port = 0;
    }
    if (inet_pton(AF_INET, val, &res->sin_addr) != 1) {
        free(res);
        return NULL;
    }
    return (struct sockaddr *)res;
}

void sbox_load_profile(char *profile)
{
    int netflag;
    struct sockaddr *addr;
    FILE *fp = fopen(profile, "r");
    if (!fp) {
        err(1, "open %s", profile);
    }

    size_t len = 0;
    char *line = NULL;
    int line_n = 0;

#define SEC_NONE    0
#define SEC_FILE    1
#define SEC_NETWORK 2

    int section = SEC_NONE;

    while (getline(&line, &len, fp) != -1) {
        line_n++;
        while (*line == ' ' || *line == '\t' || *line == '\v'
                || *line == '\f' || *line == '\r') {
            line++;
        }
        // ignore empty line
        if (line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        // ignore comment lines
        if (line[0] == '#') {
            continue;
        }
        // set current section
        if (line[0] == '[') {
            if (strbeg(line, "[fs]")) {
                section = SEC_FILE;
            } else if (strbeg(line, "[network]")) {
                section = SEC_NETWORK;
            } else {
                errx(1, "Not supported yet: %s", line);
            }
            continue;
        }

        // handle each section line
        switch (section) {
        case SEC_NETWORK:
            if (strbeg(line, "block:"))
                netflag = NET_BLOCK;
            else if (strbeg(line, "kill:"))
                netflag = NET_KILL;
            else if (strbeg(line, "log:"))
                netflag = NET_LOG;
            else if (strbeg(line, "allow:"))
                netflag = NET_ALLOW;
            else
                errx(1, "Unknown option: %s", line);
            addr = __parse_addr_line(line);
            if (!addr)
                errx(1, "Error reading net address: %s", line);
            add_addr_to_netmap(&os_netmap, addr, netflag);
            break;
        case SEC_FILE:
            if (strbeg(line, "hide:")) {
                char *path =  __parse_path_line(line);
                if (!path)
                    errx(1, "Incorrect path in profile file at line %d", line_n);
                dbg(profile, "hide-> %s", path);
                __sbox_delete_file(path);
                free(path);
            } else if (strbeg(line, "direct:")) {
                char *path = __parse_path_line(line);
                if (!path)
                    errx(1, "Incorrect path in profile file at line %d", line_n);
                dbg(profile, "direct-> %s", path);
                __sbox_direct_path(path);
                free(path);
            } else if (strbeg(line, "allow:")) {
                char *path = __parse_path_line(line);
                if (!path)
                    errx(1, "Incorrect path in profile file at line %d", line_n);
                dbg(profile, "allow-> %s", path);
                __sbox_allow_path(path);

                // allowed, so sync in sboxfs
                char sboxpath[PATH_MAX];
                snprintf(sboxpath, sizeof(sboxpath), "%s/%s", opt_root, path);
                mkdirp(sboxpath, 0700);
                free(path);
            }
            break;
        default:
            break;
        }
    }

#undef SEC_NONE
#undef SEC_FILE
#undef SEC_NETWORK

    fclose(fp);
}

int sbox_mprotect(struct tcb *tcp)
{
    // for mprotect(WRITE)
    if (entering(tcp) && (tcp->u_arg[2] & PROT_WRITE)) {
        // make sure if others in the 'entry' state
        if (has_any_entering_proc(tcp)) {
            sbox_stop(tcp, "Should wait until other syscalls to be done");
        }
    }
    return 0;
}

/* specifically the first argument for address, sencod argument for the size */
static
void _check_memory_region(struct tcb *tcp)
{
    unsigned long beg = tcp->u_arg[0];
    unsigned long end = beg + tcp->u_arg[1];
    unsigned long ptr = (unsigned long) tcp->readonly_ptr;

    if (tcp->readonly_ptr != -1
        && beg != 0
        && beg < end
        && beg < ptr
        && ptr < end) {

        const char *sname = "";
        if (SCNO_IN_RANGE(tcp->scno)) {
            sname = sysent[tcp->scno].sys_name;
        }
        sbox_stop(tcp, "It's not allowed to call %s on %p",
                  sname, (void *)ptr);
    }
}

int sbox_mmap(struct tcb *tcp)
{
    if (entering(tcp)) {
        _check_memory_region(tcp);
    }
    return 0;
}

int sbox_mremap(struct tcb *tcp)
{
    if (entering(tcp)) {
        _check_memory_region(tcp);
    }
    return 0;
}

int sbox_brk(struct tcb *tcp)
{
    if (exiting(tcp)) {
        unsigned long arg = tcp->u_arg[0];
        unsigned long new = tcp->u_rval;
        unsigned long ptr = (unsigned long)tcp->readonly_ptr;

        if (arg != 0
            && tcp->readonly_ptr != -1
            && new < ptr) {
            sbox_stop(tcp, "brk() is not allowed if targetting the arg ptr");
        }
    }
    return 0;
}
