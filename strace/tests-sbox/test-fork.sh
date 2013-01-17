#!/bin/bash
#
# pre: test ! -f out
# post test -f $SPWD/out
# post test ! -f $HPWD/out
#

ls | grep test | grep t | grep e | grep s | grep t > out
exit 0