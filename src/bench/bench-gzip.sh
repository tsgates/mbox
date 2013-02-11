#!/bin/bash

DIR=$(dirname "$0")/..
KER=${KER:-/tmp/linux-git}
ZIP=${ZIP:-out.tar.gz}

if [ ! -e $KER ]; then
  echo "Can't find the $KER dir"
  exit 1
fi

run() {
  (cd $KER; make clean &>/dev/null)
  rm -f $ZIP

  OUT=$(mktemp /tmp/bench-gzip-XXXXX)
  echo "Run: $@ (see $OUT)"
  time "$@" >$OUT || {
    echo ">> stdout: (see. $OUT)"
    cat $OUT
    exit
  }
  echo "--------"
}

run tar zcf $ZIP $KER
run $DIR/strace -- tar zcf $ZIP $KER
run $DIR/strace -s -- tar zcf $ZIP $KER
