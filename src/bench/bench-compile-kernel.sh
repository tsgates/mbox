#!/bin/bash

DIR=$(dirname "$0")/..
KER=${KER:-/tmp/linux-git}

if [ ! -e $KER ]; then
  echo "Can't find the $KER dir"
  exit 1
fi

run() {
  (cd $KER; make clean &>/dev/null)

  OUT=$(mktemp /tmp/bench-kernel-XXXXX)
  echo "Run: $@ (see $OUT)"
  time "$@" >$OUT || {
    echo ">> stdout: (see. $OUT)"
    cat $OUT
    exit
  }
  echo "--------"
}

for i in `seq 1 5`; do
  run make -C $KER -j4 kernel
  run $DIR/strace -s -- make -C $KER -j4 kernel
done
