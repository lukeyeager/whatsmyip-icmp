build:
	clang --target=bpf -O2 -g -Wall -Wunused-variable -c bpf.c -o bpf.o

# NOTE: need to edit this for each host
DEV := enp9s0f2

start: stop
	sudo tc qdisc add dev $(DEV) clsact
	sudo tc filter add dev $(DEV) ingress bpf object-file bpf.o section ingress direct-action
	sudo tc filter add dev $(DEV) egress  bpf object-file bpf.o section egress  direct-action

stop:
	-sudo tc filter del dev $(DEV) ingress
	-sudo tc filter del dev $(DEV) egress
	-sudo tc qdisc del dev $(DEV) clsact
	-sudo rm -vf /sys/fs/bpf/tc/globals/payload_map
