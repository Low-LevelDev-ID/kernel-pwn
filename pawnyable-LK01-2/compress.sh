#!/bin/sh
gcc -o exp1 exp1.c -static $1
mv ./exp1 ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
