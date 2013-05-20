#!/bin/bash

JOB=${JOB:--j1}
DIR=$(dirname "$0")/..
KER=${KER:-/tmp/linux-3.8}

if [ ! -e $KER ]; then
  echo "Can't find the $KER dir"
  exit 1
fi

run() {
  (cd $KER; make clean &>/dev/null)

  OUT=$(mktemp /tmp/bench-kernel-XXXXX)
  CPU=$(cat /sys/devices/system/cpu/online)
  echo "CPU: $CPU"
  echo "KER: $(uname -a)"
  echo "Run: $@ (see $OUT)"
  time "$@" >$OUT || {
    echo ">> stdout: (see. $OUT)"
    cat $OUT
    exit
  }
  echo "--------"
}

run make -C $KER $JOB kernel
run $DIR/mbox -i -- make -C $KER $JOB kernel
run $DIR/mbox -i -s -- make -C $KER $JOB kernel

# for i in `seq 1 5`; do
#   run make -C $KER $JOB kernel
#   run $DIR/mbox -i -s -- make -C $KER $JOB kernel
# done
