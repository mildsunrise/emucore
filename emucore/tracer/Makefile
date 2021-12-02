all: tracer.so

clean:
	rm -rf tracer.so

CFLAGS := -fPIC -O3 -Wall -Wextra -Wno-unused-parameter

tracer.so: tracer.c
	cc $(CFLAGS) tracer.c -shared -nostdlib -o tracer.so
