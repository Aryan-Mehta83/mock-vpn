CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET_SERVER = mock-vpn-server
TARGET_CLIENT = mock-vpn-client
SOURCE = mock-vpn.c

.PHONY: all server client clean test

all: server client

server:
	$(CC) $(CFLAGS) -DVPN_MODE=1 -o $(TARGET_SERVER) $(SOURCE)

client:
	$(CC) $(CFLAGS) -DVPN_MODE=0 -o $(TARGET_CLIENT) $(SOURCE)

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)

test: server client
	@echo "Compiled server and client binaries"
	@echo "Run 'sudo ./mock-vpn-server' in one terminal"
	@echo "Run 'sudo ./mock-vpn-client' in another terminal"
