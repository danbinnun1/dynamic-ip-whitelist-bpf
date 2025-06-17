CC=gcc
CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=-lpcap

filter: main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: filter
	coverage run -m pytest -v
	coverage report -m

clean:
	rm -f filter

.PHONY: test clean
