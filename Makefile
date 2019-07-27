CC 		= gcc
CFLAGS 	= -O3
LFLAGS  = -lgcrypt

.PHONY: clean

all: cisco-encrypt
install:
	cp cisco-encrypt /usr/local/bin/

%: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LFLAGS)

clean:
	rm -f cisco-encrypt
