#!/bin/bash -x
#
# pre: test ! -d no-such-a-dir
# post: test -d $SPWD/no-such-a-dir
# post: test -f $SPWD/no-such-a-dir/file
#

mkdir no-such-a-dir
pwd
cd no-such-a-dir
pwd
echo 1 > file
ls -al file