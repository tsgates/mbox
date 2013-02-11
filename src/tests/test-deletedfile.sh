#!/bin/bash -x
#
# pre: test -f tests/NOTE
# post: test -f $HPWD/tests/NOTE
# post: grep -q "No such file" $SPWD/err-rm
# post: grep -q "No such file" $SPWD/err-head
#

# unlinking the existing file
ls ./tests | grep NOTE
rm ./tests/NOTE

# no such a file
rm ./tests/NOTE &> err-rm

# no such a file
head -1 ./tests/NOTE &> err-head

# ok
exit 0