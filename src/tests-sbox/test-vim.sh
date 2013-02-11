#!/bin/bash -x
#
# pre: test -f tests-sbox/NOTE
# post: diff "$SPWD/tests-sbox/NOTE" "$HPWD/tests-sbox/NOTE" | grep -q NOTE
#

# launching vim
vim -c ":q"

# delete one line and write
vim -c ":delete" -c ":wq" tests-sbox/NOTE

# launch vi
vi  -c ":wq" tests-sbox/NOTE
