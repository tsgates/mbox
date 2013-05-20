#!/bin/bash

DIR=$(dirname "$0")/..
CMD="octave -q $DIR/bench/octave.m"

time $CMD
time $DIR/mbox -i -- $CMD
time $DIR/mbox -i -s -- $CMD
