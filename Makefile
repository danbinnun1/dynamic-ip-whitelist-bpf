CC=gcc
CFLAGS?=-Wall -Wextra -O2
LDFLAGS?=-lpcap

filter: filter_main.c whitelist.c whitelist.h
	$(CC) $(CFLAGS) filter_main.c whitelist.c -o $@ $(LDFLAGS)

test: CFLAGS+=--coverage -O0
test: LDFLAGS+=--coverage

test: filter
	pytest -v
	lcov --rc lcov_branch_coverage=1 --capture --directory . --output-file c_cov.info
	genhtml --branch-coverage c_cov.info --output-directory c_html > /dev/null

clean:
	rm -f filter *.gcno *.gcda c_cov.info
	rm -rf pycov c_html

.PHONY: test clean
