#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

char *read_file(const char *fname, long *size_return)
{
	char *buffer;
	long file_size;
	FILE *f;

	f = fopen(fname, "r");
	if (f == NULL) {
		perror("opening image file");
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		perror("seeking end of file");
		return NULL;
	}
	file_size = ftell(f);
	if (file_size == -1L) {
		perror("getting file pointer");
		return NULL;
	}
	if (fseek(f, 0, SEEK_SET) != 0) {
		perror("seeking beginning of file");
		return NULL;
	}
	buffer = malloc(file_size);
	if (buffer == NULL) {
		perror("allocating buffer");
		return NULL;
	}
	if (fread(buffer, 1, file_size, f) != file_size) {
		perror("reading from file");
		return NULL;
	}
	if (fclose(f) != 0) {
		perror("closing file");
		return NULL;
	}
	if (size_return != NULL)
		*size_return = file_size;

	return buffer;
}

#define REQUIRE_SIZE(want,have) \
	{ \
		if (have < want) { \
			fprintf(stderr, "buffer overflow (want=%d, have=%zd)\n", want, have); \
			return false; \
		} \
	}

bool is_pe_image(const char *buffer, size_t buffer_size)
{
	uint32_t pe_header_offset;

	REQUIRE_SIZE(2, buffer_size);
	if (buffer[0] != 'M' || buffer[1] != 'Z') {
		fprintf(stderr, "No DOS header magic ('MZ')\n");
		return false;
	}
	pe_header_offset = *(uint32_t*)(buffer+0x3c);

	REQUIRE_SIZE(pe_header_offset+2, buffer_size);
	if (buffer[pe_header_offset] != 'P' || buffer[pe_header_offset+1] != 'E') {
		fprintf(stderr, "No PE header magic ('PE')\n");
		return false;
	}
	return true;
}

int main(int argc, char ** argv)
{
	char *buffer;
	long file_size;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <path-to-sys-file>\n", argv[0]);
		return 1;
	}
	buffer = read_file(argv[1], &file_size);
	if (buffer == NULL) {
		fprintf(stderr, "Couldn't read file contents of %s, giving up.\n", argv[1]);
		return 1;
	}
	if (is_pe_image(buffer, file_size)) {
	} else {
		fprintf(stderr, "Not a PE image\n");
		return 2;
	}
	return 0;
}

