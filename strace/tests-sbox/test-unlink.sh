#!/bin/sh -x
#
# pre: test ! -f tests-sbox/newfile
# pre: test -f tests-sbox/NOTE
# post: test -f $HPWD/tests-sbox/NOTE
# post: test ! -f $SPWD/tests-sbox/newfile
#

# creating a new file
echo 1234 > ./tests-sbox/newfile
ls ./tests-sbox | grep newfile

# unlinking the existing file
ls ./tests-sbox | grep NOTE
rm ./tests-sbox/NOTE

# unlinking the new file
ls ./tests-sbox | grep newfile
rm ./tests-sbox/newfile
