#!/bin/bash -x
#
# pre: test -f tests-sbox/NOTE
# post: test -f $HPWD/tests-sbox/NOTE
# post: grep -q "No such file" $SPWD/err-rm
# post: grep -q "No such file" $SPWD/err-head
#

# unlinking the existing file
ls ./tests-sbox | grep NOTE
rm ./tests-sbox/NOTE

# no such a file
rm ./tests-sbox/NOTE &> err-rm

# no such a file
head -1 ./tests-sbox/NOTE &> err-head

# ok
exit 0