#!/bin/bash -x
#
# pre: test ! -f tests/newfile
# pre: test -f tests/NOTE
# post: test -f $HPWD/tests/NOTE
# post: test ! -f $SPWD/tests/newfile
#

# creating a new file
echo 1234 > ./tests/newfile
ls ./tests | grep newfile

# unlinking the existing file
ls ./tests | grep NOTE
rm ./tests/NOTE

# unlinking the new file
ls ./tests | grep newfile
rm ./tests/newfile
