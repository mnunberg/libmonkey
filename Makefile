TARGETS=testmain libmonkey.so test_inject.so

all: $(TARGETS)
	LD_PRELOAD=$(shell pwd)/test_inject.so ./testmain

clean:
	-rm -f $(TARGETS)

CFLAGS= -Wall

testmain: testmain.c
	$(CC) $(CFLAGS) -O0 -o $@ $^

libmonkey.so: libmonkey.c fn_override.c
	$(CC) -O0 $(CFLAGS) -shared -o $@ -fPIC $^

test_inject.so: libmonkey.so test_inject.c
	$(CC) -O0 $(CFLAGS) -shared -fPIC test_inject.c -o $@ -Wl,-rpath='$$ORIGIN' -L. -lmonkey

paste:
	head -n 1000 *.{c,h} Makefile | nopaste -lc


