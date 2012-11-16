#!/bin/sh -x
#
# pre: test -d tests
# post: test -f tests/NOTE
# post: test -f tests/test-chdir.sh
#

ls -al tests
pwd
cd ..
pwd
cd /tmp
pwd
ls
pwd
cd -
pwd
cd tests
pwd
ls -al .