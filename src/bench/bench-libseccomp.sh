#!/bin/bash
DIR=$(dirname "$0")/..
TMP=/tmp/libseccomp

if [ ! -e $TMP ]; then
  git clone --depth=1 git://git.code.sf.net/p/libseccomp/libseccomp $TMP
fi

run() {
  (cd $TMP; make clean &>/dev/null)
  echo "Run: $@" >&2
  time "$@"
  echo "--------" >&2
}

run make -C $TMP src >/tmp/make.log
run $DIR/sandbox.py -j ptrace  -C $TMP make src >/tmp/sb-ptrace.log
run $DIR/sandbox.py -j seccomp -C $TMP make src >/tmp/sb-seccomp.log
run strace -f -o /dev/null make -C $TMP src >/tmp/strace.log
run $DIR/sandbox.py -n -j ptrace  -C $TMP make src >/tmp/nosb-ptrace.log
run $DIR/sandbox.py -n -j seccomp -C $TMP make src >/tmp/nosb-seccomp.log
