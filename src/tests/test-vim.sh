#!/bin/bash -x
#
# pre: test -f tests/NOTE
# post: diff "$SPWD/tests/NOTE" "$HPWD/tests/NOTE" | grep -q NOTE
#

# launching vim
vim -c ":q"

# delete one line and write
vim -c ":delete" -c ":wq" tests/NOTE

# launch vi
vi  -c ":wq" tests/NOTE
