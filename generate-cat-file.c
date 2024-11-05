#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include <ctype.h>
#include <unistd.h>

/* DER encoding */

#define SEQUENCE_TAG	0x30
#define SET_TAG		0x31
#define ARRAY_TAG	0xA0
#define OID_TAG		0x06
#define NULL_TAG	0x05
#define INTEGER_TAG	0x02
#define OCTET_STRING_TAG	0x04
#define BMP_STRING_TAG	0x1E
#define UTC_TIME_TAG	0x17

struct oid {
		/* the OID in human readable format */
	char *oid;
};

struct octet_string {
	size_t len;
	void *data;
};

struct bmp_string {
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

struct an_attribute {
	char *name;
	char *value;
	bool encode_as_set;	/* SET or OCTET_STRING */
};

struct a_file {
	char *a_hash;
	char *guid;	/* {C689AAB8-8E78-11D0-8C47-00C04FC295EE} */
	char *sha1_hash;  /* seems to be the same as a_hash but coded differently */

	struct an_attribute file_attribute;
	struct an_attribute os_attribute;

	struct oid member_info_oid;
	bool is_link;
};

struct catalog_list_element {
	struct oid catalog_list_oid;
	struct octet_string a_hash;
	struct utc_time a_time;
	struct oid catalog_list_member_oid;

	struct an_attribute hardware_id;
	struct an_attribute os_info;

	int nr_files;
	struct a_file files[0];
};

struct cert_trust_list {
	struct oid cert_trust_oid;
	struct catalog_list_element *catalog_list_element;
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

size_t encode_empty_set(bool write)
{
	char empty_set_buf[2] = { SET_TAG, 0x00 };
	return append_to_buffer(sizeof(empty_set_buf), empty_set_buf, write);
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

	/* This one is big endian for UFT-16 */
size_t encode_bmp_string(struct bmp_string *s, bool write)
{
	size_t l2 = encode_tag_and_length(BMP_STRING_TAG, s->len, write);
	return append_to_buffer(s->len, s->data, write) + l2;
}

size_t encode_utc_time(struct utc_time *t, bool write)
{
	size_t len = strlen(t->date_time);
	size_t l2 = encode_tag_and_length(UTC_TIME_TAG, len, write);
	return append_to_buffer(len, t->date_time, write) + l2;
}

size_t encode_string_as_utf16(const char *s, bool write)
{
	unsigned short utf16[1000];
	int i;
	struct octet_string os;

	for (i=0;s[i]!='\0' && i<sizeof(utf16)/sizeof(utf16[0]);i++) {
		utf16[i]=(unsigned char)(s[i]);
	}
	if (s[i] != '\0')
		fatal("string too long\n");
	utf16[i] = 0;
	i++;

	os.len = i*sizeof(utf16[0]);
	os.data = utf16;

	return encode_octet_string(&os, write);
}

size_t encode_string_as_utf16_bmp(const char *s, bool write)
{
	unsigned short utf16[1000];
	int i;
	struct bmp_string os;

	for (i=0;s[i]!='\0' && i<sizeof(utf16)/sizeof(utf16[0]);i++) {
		utf16[i]=(unsigned char)(s[i]) << 8;
	}
	if (s[i] != '\0')
		fatal("string too long\n");

	os.len = i*sizeof(utf16[0]);
	os.data = utf16;

	return encode_bmp_string(&os, write);
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

size_t encode_as_octet_string(void *s, size_t a_fn(void*, bool), bool write)
{
	size_t length = a_fn(s, false);

	size_t l2 = encode_tag_and_length(OCTET_STRING_TAG, length, write);
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

size_t encode_attribute_name_and_value(void *p, bool write)
{
	struct an_attribute *a = p;
	size_t length;

	length = encode_string_as_utf16_bmp(a->name, write);
	length += encode_integer(268500993, write);
	length += encode_string_as_utf16(a->value, write);

	return length;
}

size_t encode_attribute_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_attribute_name_and_value, write);
}

size_t encode_attribute(void *p, bool write)
{
	struct an_attribute *a = p;
	size_t length;
	struct oid name_value = { "1.3.6.1.4.1.311.12.2.1" };

	length = encode_oid_with_header(&name_value, write);
	if (a->encode_as_set) {
		length += encode_set(a, encode_attribute_sequence, write);
	} else {
		length += encode_as_octet_string(a, encode_attribute_sequence, write);
	}

	return length;
}

size_t encode_member_info(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;

	length = encode_string_as_utf16_bmp(f->guid, write);
	length += encode_integer(512, write);

	return length;
}

size_t encode_member_info_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_member_info, write);
}

size_t encode_member_info_oid(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;

	length = encode_oid_with_header(&f->member_info_oid, write);
	length += encode_set(f, encode_member_info_sequence, write);

	return length;
}

size_t encode_obsolete_image_data(void *p, bool write)
{
	char image_data[0x26] = { 0x03, 0x02, 0x05, 0xA0, 0xA0, 0x20, 0xA2, 0x1E , 0x80 , 0x1C , 0x00 , 0x3C , 0x0, 0x3C, 0x0, 0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E };
//	char image_data[0x18] = { 0x03, 0x02, 0x05, 0xA0, 0xA0, 0x12, 0xA2, 0x10 , 0x80 , 0x0E, 0x00, 0x5A, 0x00, 0x61, 0x00, 0x6B, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x62, 0x00, 0x74 };

// 03 02 05 A0 A0 12 A2
// 10 80 0E 00 7A 00 61 00  6B 00 6C 00 65 00 62 00
// 74 30 21 30 09 06 05 2B
// zaklebt: hacked catgen
// 007A0061006B006C006500620074

	return append_to_buffer(sizeof(image_data), image_data, write);
}

size_t encode_spc_image_data(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;
	struct oid spc_image_data_oid = { "1.3.6.1.4.1.311.2.1.15" };

	length = encode_oid_with_header(&spc_image_data_oid, write);
	length += encode_sequence(f, encode_obsolete_image_data, write);

	return length;
}

size_t encode_spc_link(void *p, bool write)
{
	size_t length;
	struct oid spc_link_oid = { "1.3.6.1.4.1.311.2.1.25" };
/*	char link_data[0x20] = {
		0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C,
		0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C,
		0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E,
		0x00, 0x3E };
*/
	char link_data[0x12] = { 0xA2, 0x10, 0x80, 0x0E, 0x00, 0x7A, 0x00, 0x61, 0x00, 0x6B, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x62, 0x00, 0x74 };

// A2 10 80 0E 00 7A
// 00 61 00 6B 00 6C 00 65  00 62 00 74 

	length = encode_oid_with_header(&spc_link_oid, write);
	length += append_to_buffer(sizeof(link_data), link_data, write);

	return length;
}

int hexdigit(char c)
{
	if (c>='0' && c<='9')
		return c-'0';
	c = toupper(c);
	if (c>='A' && c<='F')
		return c-'A'+10;

	fatal("invalid hex digit\n");
}

size_t encode_spc_algo_oid(void *p, bool write)
{
	struct oid spc_algo_oid = { "1.3.14.3.2.26" };
	size_t length;

	length = encode_oid_with_header(&spc_algo_oid, write);
	length += encode_null(write);

	return length;
}

size_t encode_spc_algo(void *p, bool write)
{
	struct a_file *f = p;
	char sha1[20];
	int i;
	struct octet_string oc;
	size_t length;

	length = encode_sequence(f, encode_spc_algo_oid, write);
	for (i=0;i<sizeof(sha1);i++) {
		sha1[i] = hexdigit(f->sha1_hash[i*2])*16 + hexdigit(f->sha1_hash[i*2+1]);
	}

	oc.len = 20;
	oc.data = sha1;
	length += encode_octet_string(&oc, write);

	return length;
}

size_t encode_spc(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;

	if (!f->is_link) {
		length = encode_sequence(p, encode_spc_image_data, write);
	} else {
		length = encode_sequence(p, encode_spc_link, write);
	}
	length += encode_sequence(p, encode_spc_algo, write);

	return length;
}

size_t encode_spc_sequence(void *p, bool write)
{
	return encode_sequence(p, encode_spc, write);
}

size_t encode_spc_oid(void *p, bool write)
{
	struct oid spc_oid = { "1.3.6.1.4.1.311.2.1.4" };
	struct a_file *f = p;
	size_t length;

	length = encode_oid_with_header(&spc_oid, write);
	length += encode_set(f, encode_spc_sequence, write);

	return length;
}

size_t encode_file_attributes(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;

	length = encode_sequence(&f->file_attribute, encode_attribute, write);
	length += encode_sequence(&f->os_attribute, encode_attribute, write);
	length += encode_sequence(f, encode_spc_oid, write);
	length += encode_sequence(f, encode_member_info_oid, write);

	return length;
}

size_t encode_one_file(void *p, bool write)
{
	struct a_file *f = p;
	size_t length;

	length = encode_string_as_utf16(f->a_hash, write);
	length += encode_set(f, encode_file_attributes, write);

	return length;
}

size_t encode_files(void *p, bool write)
{
	struct catalog_list_element *e = p;
	size_t length = 0;
	int i;

	for (i=0;i<e->nr_files;i++) {
		length += encode_sequence(&e->files[i], encode_one_file, write);
	}

	return length;
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

size_t encode_global_attributes2(void *p, bool write)
{
	struct catalog_list_element *e = p;
	size_t length = 0;

	length += encode_sequence(&e->os_info, encode_attribute, write);
	length += encode_sequence(&e->hardware_id, encode_attribute, write);

	return length;
}

size_t encode_global_attributes(void *p, bool write)
{
	return encode_sequence(p, encode_global_attributes2, write);
}

size_t encode_catalog_list_elements(void *p, bool write)
{
	struct catalog_list_element *e = p;
	size_t length = 0;

	length += encode_sequence(e, encode_catalog_list_oid, write);
	length += encode_octet_string(&e->a_hash, write);
	length += encode_utc_time(&e->a_time, write);
	length += encode_sequence(p, encode_catalog_list_member_oid, write);
	length += encode_sequence(p, encode_files, write);
	length += encode_array(p, encode_global_attributes, write);

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
	length += encode_array(c->catalog_list_element, encode_catalog_list_sequence, write);

	return length;
}

size_t encode_pkcs7_data(void *p, bool write)
{
	struct pkcs7_data *d = p;
	size_t length = 0;

	length += encode_integer(d->an_int, write);
	// length += encode_set(&d->algo, encode_algo_sequence, write);
	length += encode_empty_set(write);
	length += encode_sequence(&d->cert_trust_list, encode_cert_trust_list, write);
	length += encode_empty_set(write);

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

void __attribute((noreturn)) usage_and_exit(void)
{
	fprintf(stderr, "Usage: generate_cat_file [-h <hardware-id>] [-O OS string] [-A OS attribute string] file-with-hash1 [ file-with-hash2 ... ]\n");
	fprintf(stderr, "Generates a Microsoft Security Catalog (\".cat\") file.\n");
	fprintf(stderr, "file-with-hash has the format filename:sha1-hash-in-hex[:PE]\n");
	fprintf(stderr, "Use osslsigncode to sign it afterwards.\n");
	exit(1);
}

void parse_file_arg(char *arg, struct a_file *f, char *os_attr)
{
	char *s = strdup(arg);
	char *fname, *hash, *s1;
	bool is_pe;

	if (s == NULL) {
		fatal("Out of memory");
	}
	fname = s;
	for (s1=s;*s1 && *s1 != ':';s1++) ;
	if (!*s1) {
		usage_and_exit();
	}
	*s1 = '\0';
	s1++;
	hash = s1;
	for (;*s1 && *s1 != ':';s1++) ;
	if (!*s1) {
		is_pe = false;
	} else {
		*s1 = '\0';
		s1++;
		if (strcmp("PE", s1) == 0) {
			is_pe = true;
		} else {
			usage_and_exit();
		}
	}

	f->a_hash = hash;
	f->sha1_hash = hash;

	f->file_attribute.value = fname;
	f->file_attribute.name = "File";
	f->os_attribute.value = os_attr;
	f->os_attribute.name = "OSAttr";
	f->member_info_oid.oid = "1.3.6.1.4.1.311.12.2.2";
	f->file_attribute.encode_as_set = true;
	f->os_attribute.encode_as_set = true;

	if (is_pe) {
		f->guid = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
		f->is_link = false;
	} else {
		f->guid = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
		f->is_link = true;
	}
}

int main(int argc, char ** argv)
{
	struct pkcs7_toplevel s = { 0 };
	size_t len;
	/* initialize data structure */
//	char a_hash[16] = {0xDD, 0x43, 0x67, 0xE3, 0x2B, 0xAB, 0xE1, 0x44, 0xB7, 0xCB, 0xEC, 0x31, 0xCE, 0xB9, 0xD5, 0xA6};
//	char a_hash[16] = {0xEF, 0xAB, 0xFC, 0x01, 0x4F, 0xD8, 0x47, 0x42, 0xA0, 0x0B, 0x7C, 0x78, 0x8E, 0x6D, 0xD1, 0xC1};
// this is correct:
	// char a_hash[16] = {0x58, 0x72, 0xA5, 0x5B, 0xFE, 0xF3, 0xCD, 0x46, 0x91, 0x3C, 0xEF, 0x00, 0xC7, 0x7A, 0x97, 0x69};
	// char a_hash[16] = {0x59, 0x72, 0xA5, 0x5B, 0xFE, 0xF3, 0xCD, 0x46, 0x91, 0x3C, 0xEF, 0x00, 0xC7, 0x7A, 0x97, 0x69};
	char a_hash[16];
	int i;

	char *os_string = "7X64,8X64,10X64";
	char *os_attr_string = "2:6.1,2:6.2,2:6.4";
	char *hardware_id = "windrbd";
	int nr_files;
	char c;

	while ((c = getopt(argc, argv, "h:A:O:")) != -1) {
		switch (c) {
		case 'h':
			hardware_id = optarg;
			break;
		case 'A':
			os_attr_string = optarg;
			break;
		case 'O':
			os_string = optarg;
			break;
		default:
			usage_and_exit();
		}
	}
	if (argc <= optind) {
		usage_and_exit();
	}
	nr_files = argc-optind;
	s.data.cert_trust_list.catalog_list_element = malloc(sizeof(struct catalog_list_element)+sizeof(struct a_file)*nr_files);
	if (s.data.cert_trust_list.catalog_list_element == NULL) {
		fatal("Out of memory");
	}
	for (i=0;i<sizeof(a_hash);i++)
		a_hash[i] = i;

	s.signed_data_oid.oid = "1.2.840.113549.1.7.2";
	s.data.an_int = 1;
	s.data.algo.algo_oid.oid = "2.16.840.1.101.3.4.2.1";
	s.data.cert_trust_list.cert_trust_oid.oid = "1.3.6.1.4.1.311.10.1";
	s.data.cert_trust_list.catalog_list_element->catalog_list_oid.oid =
		"1.3.6.1.4.1.311.12.1.1";
	s.data.cert_trust_list.catalog_list_element->a_hash.len = 16;
	s.data.cert_trust_list.catalog_list_element->a_hash.data = a_hash;
	s.data.cert_trust_list.catalog_list_element->a_time.date_time = "230823140713Z";
	s.data.cert_trust_list.catalog_list_element->catalog_list_member_oid.oid = "1.3.6.1.4.1.311.12.1.2";
	s.data.cert_trust_list.catalog_list_element->hardware_id.name = "HWID1";
	s.data.cert_trust_list.catalog_list_element->hardware_id.value = hardware_id;
	s.data.cert_trust_list.catalog_list_element->hardware_id.encode_as_set = false;
	s.data.cert_trust_list.catalog_list_element->os_info.name = "OS";
//	s.data.cert_trust_list.catalog_list_element->os_info.value = "XP_X86,Vista_X86,Vista_X64,7_X86,7_X64,8_X86,8_X64,6_3_X86,6_3_X64,10_X86,10_X64";
	s.data.cert_trust_list.catalog_list_element->os_info.value = os_string;
	s.data.cert_trust_list.catalog_list_element->os_info.encode_as_set = false;

	s.data.cert_trust_list.catalog_list_element->nr_files = nr_files;

	for (i=0;i<nr_files;i++) {
		parse_file_arg(argv[i+optind], &s.data.cert_trust_list.catalog_list_element->files[i], os_attr_string);
	}


	/* compute lengths */
	/* generate binary DER */
	len = encode_sequence(&s, encode_pkcs7_toplevel, true);
	if (len != buflen)
		fatal("length mismatch\n");

		/* and write to stdout or so ... */
	fwrite(buffer, buflen, 1, stdout);
}
