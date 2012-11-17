#!/bin/sh
#
# pre: test -d tests
# pre: test -f tests/NOTE
# pre: test ! -f tests/test
# post: grep 1234 $SPWD/tests/NOTE
# post: test ! -f $SPWD/tests/test
#

# listing
/bin/ls -al ./tests
# overwriting
echo 1234 > ./tests/NOTE
# creating a new file
echo 5678 > ./tests/test
# reading the overwritten file
/bin/cat ./tests/abort.c
# checking
/bin/ls -al ./tests
# unlinking
/bin/rm ./tests/test