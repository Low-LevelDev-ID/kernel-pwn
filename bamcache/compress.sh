#!/bin/sh
gcc -o exp-page exp-page.c -static $1
mv ./exp-page ./rootfs
cd rootfs
find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs.cpio
