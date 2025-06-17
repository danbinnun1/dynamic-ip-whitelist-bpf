CC=gcc
CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=-lpcap

filter: main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: filter
	pytest -v

clean:
	rm -f filter

.PHONY: test clean
