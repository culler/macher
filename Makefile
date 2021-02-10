macher: append_data.o macher.h macher.c
	gcc -o macher append_data.o macher.c

macher.h:
	/usr/bin/env python3 makeheader.py

append_data.o:
	gcc -c append_data.c

clean:
	rm -f *.o macher
