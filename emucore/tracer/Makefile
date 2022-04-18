all: tracer.so

clean:
	rm -rf tracer.so

CFLAGS := -O -C panic=abort

tracer.so: tracer.rs
	rustc $(CFLAGS) tracer.rs --crate-type cdylib -C default-linker-libraries=no -o tracer.so
