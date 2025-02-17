CFLAGS=-Wall -g
INSTALL_DIR?=/usr/local/bin

all: generate-cat-file strip-pe-image

clean:
	rm -f generate-cat-file strip-pe-image

install:
	cp gencat.sh generate-cat-file strip-pe-image $(INSTALL_DIR)

test: all
	cd test && ../gencat.sh -T 250101120000Z -G 00000000-0000-4000-8000-000000000000 -o test-generated.cat file1 file2 file3 && diff test-correct.cat test-generated.cat
