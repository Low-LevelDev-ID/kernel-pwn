#!/bin/sh
qemu-system-x86_64 \
    -s \
    -S  \
    -kernel ./bzImage \
    -cpu qemu64,+smep,+smap \
    -m 4G \
    -smp 4 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 nokaslr kpti=1" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
