#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>

/* DER encoding */

#define SEQUENCE_TAG	0x30
#define SET_TAG		0x31
#define ARRAY_TAG	0xA0
#define OID_TAG		0x06
#define NULL_TAG	0x05
#define INTEGER_TAG	0x02
#define OCTET_STRING_TAG	0x04
#define UTC_TIME_TAG	0x17

struct oid {
		/* the OID in human readable format */
	char *oid;
};

struct octet_string {
	size_t len;
	void *data;
};

struct utc_time {
	char *date_time;  /* 221020135745Z with trailing '\0' */
};

struct null {
};

struct array_like_sequence {
	int nelem;
};

struct algo {
	struct oid algo_oid;
	struct null a_null;
};

struct catalog_list_element {
	struct oid catalog_list_oid;
	struct octet_string a_hash;
	struct utc_time a_time;
	struct oid catalog_list_member_oid;
};

struct cert_trust_list {
	struct oid cert_trust_oid;
	struct catalog_list_element catalog_list_element;
};

struct pkcs7_data {
	int an_int;
	/* empty set: using SHA-1 which is default */
	struct algo algo;
	struct cert_trust_list cert_trust_list;
};

struct pkcs7_toplevel {
	struct oid signed_data_oid;
	struct pkcs7_data data;
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

size_t encode_octet_string(struct octet_string *s, bool write)
{
	size_t l2 = encode_tag_and_length(OCTET_STRING_TAG, s->len, write);
	return append_to_buffer(s->len, s->data, write) + l2;
}

size_t encode_utc_time(struct utc_time *t, bool write)
{
	size_t len = strlen(t->date_time);
	size_t l2 = encode_tag_and_length(UTC_TIME_TAG, len, write);
	return append_to_buffer(len, t->date_time, write) + l2;
}

size_t encode_oid_with_header(struct oid *oid, bool write)
{
	size_t len = encode_oid(oid->oid, false);

	size_t l2 = encode_tag_and_length(OID_TAG, len, write);
	return encode_oid(oid->oid, write) + l2;
}

size_t encode_sequence(void *s, size_t a_fn(void*, bool), bool write)
{
	size_t length = a_fn(s, false);

	size_t l2 = encode_tag_and_length(SEQUENCE_TAG, length, write);
	return a_fn(s, write) + l2;
}

	/* TODO: differs only in tag value ... */
size_t encode_set(void *s, size_t a_fn(void*, bool), bool write)
{
	size_t length = a_fn(s, false);

	size_t l2 = encode_tag_and_length(SET_TAG, length, write);
	return a_fn(s, write) + l2;
}

size_t encode_array(void *s, size_t a_fn(void*, bool), bool write)
{
	size_t length = a_fn(s, false);

	size_t l2 = encode_tag_and_length(ARRAY_TAG, length, write);
	return a_fn(s, write) + l2;
}

size_t encode_algo(void *p, bool write)
{
	struct algo *a = p;
	size_t length = 0;

	length += encode_oid_with_header(&a->algo_oid, write);
	length += encode_null(write);

	return length;
}

size_t encode_algo_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_algo, write);
}

size_t encode_catalog_list_member_oid(void *p, bool write)
{
	struct catalog_list_element *e = p;
	size_t length = 0;

	length += encode_oid_with_header(&e->catalog_list_member_oid, write);
	length += encode_null(write);

	return length;
}

size_t encode_catalog_list_oid(void *p, bool write)
{
	struct catalog_list_element *e = p;

	return encode_oid_with_header(&e->catalog_list_oid, write);
}

size_t encode_catalog_list_elements(void *p, bool write)
{
	struct catalog_list_element *e = p;
	size_t length = 0;

	length += encode_sequence(e, encode_catalog_list_oid, write);
	length += encode_octet_string(&e->a_hash, write);
	length += encode_utc_time(&e->a_time, write);
	length += encode_sequence(p, encode_catalog_list_member_oid, write);

	return length;
}

size_t encode_catalog_list_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_catalog_list_elements, write);
}

size_t encode_cert_trust_list(void *p, bool write)
{
	struct cert_trust_list *c = p;
	size_t length = 0;

	length += encode_oid_with_header(&c->cert_trust_oid, write);
	length += encode_array(&c->catalog_list_element, encode_catalog_list_sequence, write);

	return length;
}

size_t encode_pkcs7_data(void *p, bool write)
{
	struct pkcs7_data *d = p;
	size_t length = 0;

	length += encode_integer(d->an_int, write);
	length += encode_set(&d->algo, encode_algo_sequence, write);
	length += encode_sequence(&d->cert_trust_list, encode_cert_trust_list, write);

	return length;
}

size_t encode_pkcs7_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_pkcs7_data, write);
}

size_t encode_pkcs7_toplevel(void *p, bool write)
{
	struct pkcs7_toplevel *s = p;
	size_t length = 0;

	length += encode_oid_with_header(&s->signed_data_oid, write);
	// length += encode_sequence(&s->data, encode_pkcs7_array, write);
	length += encode_array(&s->data, encode_pkcs7_sequence, write);

	return length;
}

int main(int argc, char ** argv)
{
	struct pkcs7_toplevel s = { 0 };
	size_t len;
	/* initialize data structure */
	char a_hash[16] = {0xDD, 0x43, 0x67, 0xE3, 0x2B, 0xAB, 0xE1, 0x44, 0xB7, 0xCB, 0xEC, 0x31, 0xCE, 0xB9, 0xD5, 0xA6};

	s.signed_data_oid.oid = "1.2.840.113549.1.7.2";
	s.data.an_int = 1;
	s.data.algo.algo_oid.oid = "2.16.840.1.101.3.4.2.1";
	s.data.cert_trust_list.cert_trust_oid.oid = "1.3.6.1.4.1.311.10.1";
	s.data.cert_trust_list.catalog_list_element.catalog_list_oid.oid =
		"1.3.6.1.4.1.311.12.1.1";
	s.data.cert_trust_list.catalog_list_element.a_hash.len = 16;
	s.data.cert_trust_list.catalog_list_element.a_hash.data = a_hash;
	s.data.cert_trust_list.catalog_list_element.a_time.date_time = "221020135745Z";
	s.data.cert_trust_list.catalog_list_element.catalog_list_member_oid.oid = "1.3.6.1.4.1.311.12.1.2";

	/* compute lengths */
	/* generate binary DER */
	len = encode_sequence(&s, encode_pkcs7_toplevel, true);
	if (len != buflen)
		fatal("length mismatch\n");

		/* and write to stdout or so ... */
	fwrite(buffer, buflen, 1, stdout);
}
