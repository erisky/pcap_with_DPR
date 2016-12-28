
.PHONY: all

all:
	gcc -o test test.c -I./inc -L./lib -lpcap

clean:
	rm -f test
