CC 		= gcc
CFLAGS 	= -O3
LFLAGS  = -lgcrypt
PREFIX  = /usr/local

.PHONY: clean

all: cisco-encrypt
install: cisco-encrypt
	install -D $^ -t $(DESTDIR)$(PREFIX)/bin/

%: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LFLAGS)

clean:
	rm -f cisco-encrypt
