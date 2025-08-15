#!/bin/sh
timeout 300s qemu-system-x86_64  \
    -m 256M \
    -cpu qemu64,+smep,+smap \
    -kernel bzImage \
    -initrd rootfs.cpio \
    -append "module.sig_enforce=0 console=ttyS0 kaslr quiet panic=1" \
    -nographic \
    -no-reboot \
    -drive file=/home/ctf/flag,if=virtio,format=raw,readonly=on \
    -monitor /dev/null