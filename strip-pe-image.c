#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(_WINDOWS) || defined(_WIN32) || defined(WIN32)
	#include <fcntl.h>
	#include <io.h>

	#define IS_WINDOWS

	#ifdef _O_BINARY
		#define HAVE_SETMODE
	#endif
#endif

char *read_file(const char *fname, long *size_return)
{
	char *buffer;
	long file_size;
	FILE *f;

#ifdef IS_WINDOWS
	#ifdef HAVE_SETMODE
	if (_setmode(_fileno(stdout), _O_BINARY) == -1)
	{
		fprintf(stderr, "cannot set binary mode for stdout\noutput canceled due to translation(known \"corruption\" in text mode)\nhttps://stackoverflow.com/a/5537079");
		exit(1);
	}
	#else
	freopen("CON", "wb", stdout);
	//stdout = fdopen(STDOUT_FILENO, "wb");
	#endif
	f = fopen(fname, "rb");
#else
	f = fopen(fname, "r");
#endif

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
			fprintf(stderr, "buffer overflow (want=%zd, have=%zd)\n", (size_t) want, have); \
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
	REQUIRE_SIZE(0x40, buffer_size);
	pe_header_offset = *(uint32_t*)(buffer+0x3c);

	REQUIRE_SIZE((size_t) pe_header_offset+2, buffer_size);
	if (buffer[pe_header_offset] != 'P' || buffer[pe_header_offset+1] != 'E') {
		fprintf(stderr, "No PE header magic ('PE')\n");
		return false;
	}
	return true;
}

#define WRITE(n) \
	{ \
		REQUIRE_SIZE(pos+n, buffer_size); \
		fwrite(buffer+pos, n, 1, stdout); \
		pos+=n; \
	}

#define SKIP(n) \
	{ \
		REQUIRE_SIZE(pos+n, buffer_size); \
		pos+=n; \
	}

bool strip_and_write(const char *buffer, size_t buffer_size)
{
	uint32_t pe_header_offset;
	uint16_t pe_magic;
	size_t pos=0;
	uint32_t file_offset_of_certificate_table;
	uint32_t size_of_certificate_table;

	REQUIRE_SIZE(0x40, buffer_size);
	pe_header_offset = *(uint32_t*)(buffer+0x3c);

	REQUIRE_SIZE(pe_header_offset+0x20, buffer_size);
	pe_magic = *(uint16_t*)(buffer+pe_header_offset+0x18);

		/* Write the DOS header */
	WRITE(pe_header_offset);
		/* PE header without checksum field */
	WRITE(0x58);
	SKIP(4);
	WRITE(0x1c);

		/* Data Directories up to Certificate table */
	switch (pe_magic) {
	case 0x20b:	/* PE32+ 64 bit executable */
		WRITE(0x30);
		break;
	case 0x10b:	/* PE32 32 bit executable */
		WRITE(0x20);
		break;
	default:
		fprintf(stderr, "Invalid or unsupported PE magic %04x\n", pe_magic);
		return false;
	}
	file_offset_of_certificate_table = *(uint32_t*)(buffer+pos);
	size_of_certificate_table = *(uint32_t*)(buffer+pos+4);
	SKIP(8);

	if (file_offset_of_certificate_table != 0) {

			/* Everything up to start of certificate table */
		WRITE(file_offset_of_certificate_table-pos);
		SKIP(size_of_certificate_table);
	}

	/* Everything after the certificate table or the
	 * data directory entry (if there are no certficates)
	 */

	if (pos > buffer_size) {
		fprintf(stderr, "Uh were accessing after end of file. Sorry for that\n");
		return false;
	}
	WRITE(buffer_size-pos);

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
	if (is_pe_image(buffer, file_size) && strip_and_write(buffer, file_size))
	{
		return 0;
	} else {
		fprintf(stderr, "Not a PE image\n");
		return 2;
	}
}

