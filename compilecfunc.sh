#!/bin/sh
set -e
set -x

gcc cfunctions.c -fPIC -shared -o cfunctions.so
