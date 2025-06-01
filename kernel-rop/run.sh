#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smap,+smep \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
