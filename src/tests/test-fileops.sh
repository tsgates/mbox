#!/bin/bash
#
# pre: test -d tests
# pre: test -f tests/NOTE
# pre: test ! -f tests/test
# post: grep 1234 $SPWD/tests/NOTE
# post: test ! -f $SPWD/tests/test
# post: test -f $SPWD/total
# post: test $(wc -l $SPWD/total | cut -d' ' -f1) -gt 4
#

# listing
/bin/ls -al ./tests
# overwriting
echo 1234 > ./tests/NOTE
# creating a new file
echo 5678 > ./tests/test
# reading the overwritten file
/bin/cat ./tests/NOTE
# checking if dirent works?
/bin/ls -al ./tests | tee total
# unlinking
/bin/rm ./tests/test