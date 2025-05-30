#!/bin/sh
gcc exp_pipe.c -o exp_pipe -static $1
mv ./exp_pipe ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
