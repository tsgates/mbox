#!/bin/sh
#
# pre: test -d tests-sbox
# pre: test -f tests-sbox/NOTE
# pre: test ! -f tests-sbox/test
# post: grep 1234 $SPWD/tests-sbox/NOTE
# post: test ! -f $SPWD/tests-sbox/test
#

# listing
/bin/ls -al ./tests-sbox
# overwriting
echo 1234 > ./tests-sbox/NOTE
# creating a new file
echo 5678 > ./tests-sbox/test
# reading the overwritten file
/bin/cat ./tests-sbox/NOTE
# checking if dirent works?
/bin/ls -al ./tests-sbox
# unlinking
/bin/rm ./tests-sbox/test