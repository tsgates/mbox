#!/bin/bash

DIR=$(dirname "$0")/..
KER=${KER:-/tmp/linux-3.8}
ZIP=${ZIP:-out.tar.gz}

if [ ! -e $KER ]; then
  echo "Can't find the $KER dir"
  exit 1
fi

run() {
  rm -f $ZIP

  OUT=$(mktemp /tmp/bench-gzip-XXXXX)
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

run tar zcf $ZIP $KER
run $DIR/mbox -i -- tar zcf $ZIP $KER
run $DIR/mbox -i -s -- tar zcf $ZIP $KER
