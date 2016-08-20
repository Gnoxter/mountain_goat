
all: mountain_goat

mountain_goat: mountain_goat.c layers.h layers.c
	gcc -g -o mountain_goat mountain_goat.c layers.c -l pcap


clean:
	rm -f mountain_goat
