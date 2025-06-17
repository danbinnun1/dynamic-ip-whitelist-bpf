CC=gcc
CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=-lpcap

filter: main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: CFLAGS += -g --coverage
test: LDFLAGS += --coverage
test: clean filter
	coverage run -m pytest -v
	gcovr -r . --exclude tests
	coverage report -m

clean:
	rm -f filter

.PHONY: test clean
