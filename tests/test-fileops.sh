#!/bin/sh
#
# pre: test -d tests/crash
# pre: test -f tests/crash/abort.c
# pre: test ! -f tests/crash/test
# post: grep 1234 $SPWD/tests/crash/abort.c
# post: test ! -f $SPWD/tests/crash/test

# listing
/bin/ls -al ./tests/crash
# overwriting
echo 1234 > ./tests/crash/abort.c
# creating a new file
echo 5678 > ./tests/crash/test
# reading the overwritten file
/bin/cat ./tests/crash/abort.c
# checking
/bin/ls -al ./tests/crash
# unlinking
/bin/rm ./tests/crash/test