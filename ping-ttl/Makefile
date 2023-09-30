CFLAGS := -std=gnu11 -g -Wall -Wunused-variable -fstack-protector-strong $(CFLAGS)
LDFLAGS := -Wl,-znoexecstack -Wl,-zrelro -Wl,-znow $(shell pkg-config --libs libnetfilter_log) $(LDFLAGS)

build:
	$(CC) $(CFLAGS) $(LDFLAGS) -o pong main.c

run:
	sudo iptables -I INPUT -p icmp --icmp-type echo-request -j DROP
	sudo iptables -I INPUT -p icmp --icmp-type echo-request -j NFLOG
	-sudo ./pong
	-sudo iptables -D INPUT -p icmp --icmp-type echo-request -j DROP
	-sudo iptables -D INPUT -p icmp --icmp-type echo-request -j NFLOG
