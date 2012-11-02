CC=gcc
CFLAGS=-fPIC -shared -Wall -Wextra -Wextra $(shell python-config --cflags)
LIBS=$(shell python-config --libs)
LIBRARY=cptrace.so

$(LIBRARY): cptrace.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	rm -f $(LIBRARY)
