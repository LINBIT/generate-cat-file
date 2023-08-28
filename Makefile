CFLAGS=-Wall -g
INSTALL_DIR?=/usr/local/bin

all: generate-cat-file strip-pe-image

clean:
	rm -f generate-cat-file strip-pe-image

install:
	cp gencat.sh generate-cat-file strip-pe-image $(INSTALL_DIR)
