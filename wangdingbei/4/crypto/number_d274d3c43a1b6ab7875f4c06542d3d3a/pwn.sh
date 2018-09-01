#!/bin/sh
#name:pwn.sh

socat tcp-l:5884,fork exec:./number.pyc