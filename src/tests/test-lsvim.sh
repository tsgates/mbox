#!/bin/bash -x
#
# pre: test -f tests/NOTE
# post: diff "$SPWD/tests/NOTE" "$HPWD/tests/NOTE" | grep -q NOTE
#

ls .
vim -c ":delete" -c ":wq" tests/NOTE
vi  -c ":wq" tests/NOTE
