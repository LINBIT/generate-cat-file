CFLAGS=-Wall -g

all: generate-cat-file strip-pe-image

clean:
	rm -f generate-cat-file strip-pe-image
