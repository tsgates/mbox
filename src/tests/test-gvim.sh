#!/bin/bash -x
#
# pre: test -f tests/NOTE
# post: diff "$SPWD/tests/NOTE" "$HPWD/tests/NOTE" | grep -q NOTE
#

gvim -c ":delete" -c ":wq" tests/NOTE
