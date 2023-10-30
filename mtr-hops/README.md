Requirements:
* Archlinux (doesn't compile even on other Linux as new as Fedora 38)
* `pacman -S make clang lib32-glibc`

```console
# server
$ make && make start

# client
$ ip -o address show dev eth0
17: eth0    inet 192.168.98.7/24 brd 192.168.98.255 scope global eth0\       valid_lft forever preferred_lft forever
                 ^^^^^^^^^^^^
$ mtr -wn 192.168.98.1
Start: 2023-10-30T19:16:39+0000
HOST: 45e5a1953131   Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- ???            100.0    10    0.0   0.0   0.0   0.0   0.0
  2.|-- 192.168.98.192  0.0%    10    0.1   0.1   0.1   0.1   0.0
  3.|-- 192.168.98.168  0.0%    10    0.1   0.1   0.1   0.1   0.0
  4.|-- 192.168.98.98   0.0%    10    0.1   0.1   0.1   0.1   0.0
  5.|-- 192.168.99.7    0.0%    10    0.1   0.1   0.1   0.1   0.0
  6.|-- ???            100.0    10    0.0   0.0   0.0   0.0   0.0
  7.|-- 192.168.98.1    0.0%    10    0.1   0.1   0.1   0.1   0.0
```
You'll find the source IP in the last byte of the IP address for hops 2, 3, 4, and 5.

You can use `tc exec bpf dbg` to see the debug print messages.

With help from:
* https://taoshu.in/unix/modify-udp-packet-using-ebpf.html
* https://man.archlinux.org/man/bpf-helpers.7.en
* https://hechao.li/2020/04/10/Checksum-or-fxxk-up/

`bpf.c` is licensed as GPLv3 so that it can be used as a kernel filter.
