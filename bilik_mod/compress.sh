#!/bin/sh
gcc -o exp_mod exp_mod.c -static $1
mv ./exp_mod ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs.cpio
