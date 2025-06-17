CC=gcc
CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=-lpcap

filter: main.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test: CFLAGS+=--coverage -O0
test: LDFLAGS+=--coverage

test: filter
	coverage run -m pytest -v
	coverage html -d pycov
	coverage report -m
	lcov --capture --directory . --output-file c_cov.info
	genhtml c_cov.info --output-directory c_html > /dev/null

clean:
	rm -f filter *.gcno *.gcda c_cov.info
	rm -rf pycov c_html

.PHONY: test clean
