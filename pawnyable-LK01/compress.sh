#!/bin/sh
gcc exp2.c -o exp2 -static $1
mv ./exp2 ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
