#!/bin/bash

cat <<EOF
#pragma once

static struct sock_filter filter[] = {
    LD_SYSCALL,
EOF

cat linux/syscall.h| grep sbox_ \
    | sed -e 's/int sbox_/    TRACE_SYSCALL(/g' -e 's/();/),/g'

cat <<EOF
    ALLOWED,
};
EOF

