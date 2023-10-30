Requirements:
* Server: `pacman -S make gcc libnetfilter_log` (or equivalent)
* Client: ping from https://github.com/iputils/iputils

```console
# server
$ make build && make run

# client
$ ip -o -4 a
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
18: eth0    inet 192.168.98.7/24 brd 192.168.98.255 scope global eth0\       valid_lft forever preferred_lft forever
                 ^^^^^^^^^^^^
$ ping -c1 192.168.98.1
PING 192.168.98.1 (192.168.98.1) 56(84) bytes of data.
64 bytes from 192.168.98.1: icmp_seq=1 ttl=64 time=1921680980071020 ms

--- 192.168.98.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1921680980071019.925/1921680980071020.032/1921680980071019.925/-5411360113588140.-32 ms
                       ^^^^^^^^^^^^
```

With help from:
* https://www.netfilter.org/projects/libnetfilter_log/doxygen/html/
* https://datatracker.ietf.org/doc/html/rfc792
