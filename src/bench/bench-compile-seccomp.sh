#!/bin/bash

DIR=$(dirname "$0")/..
TMP=/tmp/libseccomp

if [ ! -e $TMP ]; then
  echo "Cloning the repo since it is the first time to run the bench"
  git clone --depth=1 git://git.code.sf.net/p/libseccomp/libseccomp $TMP
fi

run() {
  (cd $TMP; make clean &>/dev/null)

  OUT=$(mktemp /tmp/bench-libseccomp-XXXX)
  echo "Run: $@"
  time "$@" >$OUT || {
    echo ">> stdout: (see. $OUT)"
    cat $OUT
    exit
  }
  echo "--------"
}

run make -C $TMP src
run $DIR/strace -C $TMP make src
run $DIR/strace -s -C $TMP make src
run strace -f -o /dev/null make -C $TMP src
