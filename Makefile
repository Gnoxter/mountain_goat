
all: mountain_goat

mountain_goat: mountain_goat.c layers.h layers.c
	gcc -g -o mountain_goat mountain_goat.c layers.c -l pcap -std=c99 -D_GNU_SOURCE


clean:
	rm -f mountain_goat
