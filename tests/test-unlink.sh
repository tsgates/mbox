#!/bin/sh
#
# pre: test ! -f tests/newfile
# pre: test -f tests/NOTE
# post: test -f $HPWD/tests/NOTE
# post: test ! -f $SPWD/tests/newfile
#

# creating new file
echo 1234 > ./tests/newfile
# checking
ls ./tests
# unlinking the existing file
rm ./tests/NOTE
# unlinking the new file
rm ./tests/newfile
# double checking
ls ./tests
