CC = gcc
CFLAGS = -Wall -Wextra

TARGET = packet_sniffer
SRC = packet_sniffer.c

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
