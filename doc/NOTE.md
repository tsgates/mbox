# note
 - PTRACE_O_EXITKILL: kill all child when exiting (plan to introduce @3.8)
 - namespace for non-root users (plan to introduce @3.8)
 - overlayfs (plan to introduce @3.10 cycle)
   - whiteout prefix seems better than maintaining 'deleted' map
   - they also cover readdir() issues (see overlayfs.txt)
   - copy_up() also covers symlink() issues
 - docker: http://docker.io/
   - released March 26th
 
# use cases (in high level)
 - run unknown binary
   - download "convert" on the internet, saying epub -> mobi converter
   - $ sandbox --no-network --no-ipc convert in.epub out.mobi
   - commit only out.mobi? or check what convert did

 - XXX
   - $ sandbox bash
   - $ apt-get install A
   - run A (give it a shot)
   - don't like A, then destroy all together (or commit)

 - XXX
   - $ sudo sandbox bash
   - $ vim /etc/apache.conf
   - $ vim /etc/my.conf
   - commit at the same time

 - XXX: python sandboxing?
   - $ netcat -l -e "sandbox python -i" -p 8080

 - pkg manager itself (as transaction)

 - virtual env (python-virtualenv, cabal-dev ...)
   - $ sandbox -r ~/devenv bash
   - $ apt-get install A-lib B-lib ....
   - develop
   - $ sandbox -r ~/devenv bash

 - make/configure/install
 - fake root
 
# features (profile)
 - network profile
 - fs profile
   - --no-home-directory (other than current)
   - --as-fake-root
 - selinux
 - ipc?

# contribution
 - usability
   - summarize side-effects (fs/network)
   - commit them at the end (or selectively commit)
 - syscall rewriting technique
   - pathname rewriting (fd-relative trick, read-only open)
   - tricks
     - race with malicious threads: rewrite arg to the read-only region
     - restricting/emulating /proc
 - re-thinking sandbox (what is important to users?)
   - restricting network (app-based profile base like apparmor)
   - installing packages to /bin/usr
   - restricting fs (sandboxfs profile)
     (ex) prune /home/taesoo
                /home/taesoo/download/pkg/...

# XXX do not read it
# XXX:old design
 - key-value store in the kernel memory
   - unlink: tracking individual file
   - rmdir : merging on rmdir syscall (rm -rf /)
   - write : memory write on fs-sandbox
   - read  : if missed, fall into master

   {task}+ -> {fs-sandbox}

    how to intercept? new vfs? or hardcode?
    CLONE_NEW_FS?

 - also ptrace equivalent might be useful in practice (userspace)

# XXX:old step (mostly done listed here)
 - chroot /tmp/xx process
   - clone(CLONE_SANDBOX)
   - create PWD
   - ls?
 - allow read on master
 - allow write on local
 - dump at the end

 - open(R):
   - if pn in [sandboxfs]
     - if deleted (inode flag): ENOENT
     - otherwise, return inode
   - otherwise: open(R) on [hostfs]

 - open(W):
   - if pn in [sandboxfs]
     - clean up deleted flag
     - return inode

 - XXX. open(RW):
   - if pn in [sandboxfs]; return inode
   - otherwise:
     - copy to sandboxfs
     - return inode [sandboxfs]

 - open(R: directory):
   - if pn in [sandboxfs]
     - get dentries() from [sandboxfs]
     - XXX. get dentries() from [hostfs]
     - removed deleted files from [sandboxfs]
   - otherwise
     - get deleted() from [hostfs]

  - unlink
    - if pn in [sandboxfs] or pn in [hostfs];
      - inode.flag |= DELETED

# NOTE
 - XXX. thread modifying stack while rewriting syscall argument
   - tracer can write read-only memory of tracee!
   - mmap RW/RO tracer/tracee

# ref
  - altroot long time ago: 7f2da1e7d0330395e5e9e350b879b98a1ea495df
  - codespeed: https://github.com/tobami/codespeed/
  - pypy: http://speed.pypy.org/
  - minijail: https://gerrit.chromium.org/gerrit/gitweb?p=chromiumos/platform/minijail.git