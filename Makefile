TARGETS=testmain libmonkey.so test_inject.so

all: $(TARGETS)
	LD_PRELOAD=$(shell pwd)/test_inject.so ./testmain

clean:
	-rm -f $(TARGETS)

CFLAGS=-ggdb3 -O0

testmain: testmain.c
	$(CC) $(CFLAGS) -o $@ $^

libmonkey.so: libmonkey.c fn_override.c
	$(CC) $(CFLAGS) -Wall -shared -o $@ -fPIC $^

test_inject.so: libmonkey.so test_inject.c
	$(CC) $(CFLAGS) -shared -fPIC test_inject.c -o $@ -Wl,-rpath='$$ORIGIN' -L. -lmonkey

paste:
	head -n 1000 *.{c,h} Makefile | nopaste -lc


