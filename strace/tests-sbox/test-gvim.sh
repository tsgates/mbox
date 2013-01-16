#!/bin/bash -x
#
# pre: test -f tests-sbox/NOTE
# post: diff "$SPWD/tests-sbox/NOTE" "$HPWD/tests-sbox/NOTE" | grep -q NOTE
#

gvim -c ":delete" -c ":wq" tests-sbox/NOTE
