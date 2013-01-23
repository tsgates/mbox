#!/bin/bash

DIR=$(dirname "$0")/..
CMD="octave -q $DIR/bench/octave.m"

time $CMD
time $DIR/strace -- $CMD
time $DIR/strace -s -- $CMD
