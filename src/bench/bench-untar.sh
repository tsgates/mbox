#!/bin/bash

DIR=$(dirname "$0")/..
KER=${KER:-/tmp/linux-3.8.tar.bz2}
DST=${DST:-/tmp/linux-3.8}

if [ ! -e $KER ]; then
  echo "Downloading $KER"
  wget http://www.kernel.org/pub/linux/kernel/v3.0/linux-3.8.tar.bz2 -O $KER
fi

run() {
  rm -rf $DST
  mkdir $DST

  OUT=$(mktemp /tmp/untar-XXXXX)
  echo "Run: $@ (see $OUT)"
  time "$@" >$OUT || {
    echo ">> stdout: (see. $OUT)"
    cat $OUT
    exit
  }
  echo "--------"
}

run tar jxf $KER -C $DST
run $DIR/mbox -i $@ -- tar jxf $KER -C $DST
run $DIR/mbox -i $@ -s -- tar jxf $KER -C $DST
