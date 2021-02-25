CFLAGS=-arch x86_64 -arch arm64e

macher: append_data.o macher.h macher.c
	gcc ${CFLAGS} -o macher append_data.o macher.c

macher.h:
	/usr/bin/env python3 make_header.py > macher.h

append_data.o: append_data.c
	gcc ${CFLAGS} -c append_data.c

example/hello.zip: example/main.tcl
	cd example; zip hello.zip main.tcl

example/hello: macher example/hello.zip
	./macher append example/tclsh8.7 example/hello.zip example/hello
	chmod +x example/hello

.PHONY: example

example: example/hello example/hello.zip example/main.tcl example/tclsh8.7
	example/hello

clean:
	rm -f *.o macher example/hello*
