CC     ?= cc
CFLAGS ?= -O2 -g -Wall -pthread

all: wakelat hog

%: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f wakelat hog

.PHONY: all clean
