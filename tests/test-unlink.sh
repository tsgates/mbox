#!/bin/sh
#
# pre: test ! -f tests/crash/newfile
# pre: test -f tests/crash/abort.c
# post: test -f $HPWD/tests/crash/abort.c
# post: test ! -f $SPWD/tests/crash/newfile
#

# creating new file
echo 1234 > ./tests/crash/newfile
# checking
ls ./tests/crash
# unlinking the existing file
rm ./tests/crash/abort.c
# unlinking the new file
rm ./tests/crash/newfile
# double checking
ls ./tests/crash
