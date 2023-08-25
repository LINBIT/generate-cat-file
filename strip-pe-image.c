#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char ** argv)
{
	char *buffer;
	long file_size;
	FILE *f;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <path-to-sys-file>\n", argv[0]);
		exit(1);
	}
	f = fopen(argv[1], "r");
	if (f == NULL) {
		perror("opening image file");
		exit(1);
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		perror("seeking end of file");
		exit(1);
	}
	file_size = ftell(f);
	if (file_size == -1L) {
		perror("getting file pointer");
		exit(1);
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		perror("seeking beginning of file");
		exit(1);
	}
	buffer = malloc(file_size);
	if (buffer == NULL) {
		perror("allocating buffer");
		exit(1);
	}
	if (fread(buffer, 1, file_size, f) != file_size) {
		perror("reading from file");
		exit(1);
	}
	if (fclose(f) != 0) {
		perror("closing file");
		exit(1);
	}
	return 0;
}

