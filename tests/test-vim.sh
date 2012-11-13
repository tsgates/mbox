#!/bin/bash -x
#
# pre: test -f README
# post: diff "$SPWD/README" "$HPWD/README" | grep -q Python
#

vim -c ":delete" -c ":wq" README
vi  -c ":wq" README
