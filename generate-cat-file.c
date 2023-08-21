#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>

/* DER encoding */

#define SEQUENCE_TAG	0x30
#define OID_TAG		0x06
#define NULL_TAG	0x05
#define INTEGER_TAG	0x02

struct oid {
		/* the OID in human readable format */
	char oid[40];
};

struct null {
};

struct array_like_sequence {
	int nelem;
};

struct test {
	int z;
	char *oid;
};

struct pkcs7_toplevel {
/*
	struct oid signed_data;
	struct a_sequence {
		int an_int;
		struct algo {
			struct oid algo_oid;
			struct null a_null;
		} algo;
	} sequence;
*/
	int x;
	int y;
	struct test t;
};

size_t buflen;
char buffer[1024*1024];

void __attribute((noreturn)) fatal(const char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(1);
}

size_t append_to_buffer(size_t n, char *data, bool write)
{
	if (buflen + n >= sizeof(buffer)) {
		fatal("buffer size too small, please recompile with bigger buffer.\n");
	}

	if (write) {
		memcpy(buffer+buflen, data, n);
		buflen+=n;
	}
	return n;
}

size_t encode_integer(int i, bool write)
{
	char int_buf[10] = { INTEGER_TAG, };
	char sign = 0;

	if (i < 0) {
		i = -i;
		sign = 0x80;
	}
	if (i < 0x80) {
		int_buf[1] = 1;	/* length (without header) */
		int_buf[2] = i | sign;
		return append_to_buffer(3, int_buf, write);
	}
	if (i < 0x8000) {
		int_buf[1] = 2;	/* length */
		int_buf[2] = (i >> 8) | sign;
		int_buf[3] = i & 0xff;
		return append_to_buffer(4, int_buf, write);
	}
	if (i < 0x800000) {
		int_buf[1] = 3;	/* length */
		int_buf[2] = (i >> 16) | sign;
		int_buf[3] = (i >> 8) & 0xff;
		int_buf[4] = i & 0xff;
		return append_to_buffer(5, int_buf, write);
	}
	if (i < 0x80000000) {
		int_buf[1] = 4;	/* length */
		int_buf[2] = (i >> 24) | sign;
		int_buf[3] = (i >> 16) & 0xff;
		int_buf[4] = (i >> 8) & 0xff;
		int_buf[5] = i & 0xff;
		return append_to_buffer(6, int_buf, write);
	}
	fatal("Can't encode this integer\n");
}

size_t encode_oid_component(int oc, bool write)
{
	char oid_buf[10];

	if (oc < 0) {
		fatal("OID component must not be negative.\n");
	}
	if (oc < 0x80) {
		oid_buf[0] = oc;
		return append_to_buffer(1, oid_buf, write);
	}
	if (oc < 0x4000) {
		oid_buf[0] = ((oc >> 7) & 0x7f) | 0x80 ;
		oid_buf[1] = oc & 0x7f;
		return append_to_buffer(2, oid_buf, write);
	}
	if (oc < 0x200000) {
		oid_buf[0] = ((oc >> 14) & 0x7f) | 0x80 ;
		oid_buf[1] = ((oc >> 7) & 0x7f) | 0x80 ;
		oid_buf[2] = oc & 0x7f;
		return append_to_buffer(3, oid_buf, write);
	}
	fatal("Can't encode this OID component\n");
}

size_t encode_oid(char *oid, bool write)
{
	char *next;
	size_t len;
	int l0, l1, l;

	l0 = strtoul(oid, &next, 10);
	if (l0 == 0 && errno != 0) {
		fatal("could not parse OID element\n");
	}
	if (*next != '.') {
		fatal("Syntax error in OID\n");
	}
	l1 = strtoul(next+1, &next, 10);
	if (l1 == 0 && errno != 0) {
		fatal("could not parse OID element\n");
	}
	if (*next != '.' && *next != '\0') {
		fatal("Syntax error in OID\n");
	}
	len = encode_oid_component(l0*40 + l1, write);

	while (*next != '\0') {
		l = strtoul(next+1, &next, 10);
		if (l == 0 && errno != 0) {
			fatal("could not parse OID element\n");
		}
		if (*next != '.' && *next != '\0') {
			fatal("Syntax error in OID\n");
		}
		len += encode_oid_component(l, write);
	}
	return len;
}

size_t encode_null(bool write)
{
	char null_buf[2] = { NULL_TAG, 0x00 };
	return append_to_buffer(sizeof(null_buf), null_buf, write);
}

size_t encode_tag_and_length(char tag, size_t length, bool write)
{
	char tag_and_length[10];
	tag_and_length[0] = tag;

	if (length < 0x80) {
		tag_and_length[1] = length;
		return append_to_buffer(2, tag_and_length, write);
	}
	if (length < 0x10000) {
		tag_and_length[1] = 0x82;	/* 2 more length bytes */
		tag_and_length[2] = (length >> 8) & 0xff;
		tag_and_length[3] = length & 0xff;
		return append_to_buffer(4, tag_and_length, write);
	}
	if (length < 0x1000000) {
		tag_and_length[1] = 0x83;	/* 3 more length bytes */
		tag_and_length[2] = (length >> 16) & 0xff;
		tag_and_length[3] = (length >> 8) & 0xff;
		tag_and_length[4] = length & 0xff;
		return append_to_buffer(5, tag_and_length, write);
	}
	fatal("This length is not supported\n");
}

size_t encode_oid_with_header(char *oid, bool write)
{
	size_t len = encode_oid(oid, false);

	size_t l2 = encode_tag_and_length(OID_TAG, len, write);
	return encode_oid(oid, write) + l2;
}

size_t encode_sequence(void *s, size_t a_fn(void*, bool), bool write)
{
	size_t length = a_fn(s, false);

	size_t l2 = encode_tag_and_length(SEQUENCE_TAG, length, write);
	return a_fn(s, write) + l2;
}

size_t encode_test(void *p, bool write)
{
	struct test *t = p;
	size_t len;

	len = encode_integer(t->z, write);
	len += encode_oid_with_header(t->oid, write);

	return len;
}

size_t encode_pkcs7_toplevel(void *p, bool write)
{
	struct pkcs7_toplevel *s = p;
	size_t length = 0;

	length += encode_integer(s->x, write);
	length += encode_integer(s->y, write);
	length += encode_sequence(&s->t, encode_test, write);

	return length;
}

int main(int argc, char ** argv)
{
	struct pkcs7_toplevel s = { 0 };
	size_t len;
	/* initialize data structure */

	s.x = 42;
	s.y = 0x41424344;
	s.t.z = 128;
	/* s.t.oid = "1.2.3.4.5.6.40000.2000000000"; */
	s.t.oid = "1.2.840.113549.1.7.2";

	/* compute lengths */
	/* generate binary DER */
	len = encode_sequence(&s, encode_pkcs7_toplevel, true);
	if (len != buflen)
		fatal("length mismatch\n");

		/* and write to stdout or so ... */
	fwrite(buffer, buflen, 1, stdout);
}
