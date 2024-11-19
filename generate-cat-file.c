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

#define SHA1_BYTE_LEN	20
#define SHA1_STR_LEN	SHA1_BYTE_LEN * 2
#define UTF16_MAX_LEN	1000


//kind of interface for linked-list-node-like structs
struct i_list_node {
	struct i_list_node *next;
};

struct oid_data {
	/* the OID in human readable form */
	char *string;
	/* the OID in the end-form(includes header) */
	char *bytes;
	/* length of the OID in the end-form */
	size_t length;
};

// unused
//struct octet_string {
//	size_t len;
//	void *data;
//};
//
//struct bmp_string {
//	size_t len;
//	void *data;
//};
//
//struct utc_time {
//	char *date_time;  /* 221020135745Z with trailing '\0' */
//};
//
//struct array_like_sequence {
//	int nelem;
//};

struct null {
};

struct algo {
	struct oid_data *algo_oid;
	struct null a_null;
};

struct an_attribute {
	char *name;
	char *value;
	bool encode_as_set;	/* SET or OCTET_STRING */
};

struct a_file {
	struct i_list_node node;
	
	char *guid;	/* {C689AAB8-8E78-11D0-8C47-00C04FC295EE} */
	//struct oid_data *member_info_oid; //file is a "hot" struct
	char *sha1_str; //sha1 string
	
	struct an_attribute name_attribute;
	struct an_attribute os_attribute;
	
	bool is_pe;
	
	//char sha1_str[SHA1_STR_LEN + 1]; //sha1 string
	char sha1_bytes[SHA1_BYTE_LEN];  //sha1 bytes in big endian order
};

struct catalog_list_element {
	struct oid_data *catalog_list_oid;
	char *a_hash;
	char *a_time;
	struct oid_data *catalog_list_member_oid;
	
	struct a_file *files;
	
	struct an_attribute hardware_id;
	struct an_attribute os_info;
};

struct cert_trust_list {
	struct oid_data *cert_trust_oid;
	struct catalog_list_element *catalog_list_element;
};

struct pkcs7_data {
	int an_int;
	/* empty set: using SHA-1 which is default */
	struct algo algo;
	struct cert_trust_list cert_trust_list;
};

struct pkcs7_toplevel {
	struct oid_data *signed_data_oid;
	struct pkcs7_data data;
};

struct known_oids {
	//cold, used once (if used)
	struct oid_data algo_oid;
	//hot, x2 per file, per HWID and one more
	struct oid_data attribute_name_value_oid;
	//cold, used once
	struct oid_data catalog_list_oid;
	//cold, used once (now, depends on tree)
	struct oid_data catalog_list_member_oid;
	//cold, used once
	struct oid_data cert_trust_oid;
	//warm, per file
	struct oid_data member_info_oid;
	//cold, used once
	struct oid_data signed_data_oid;
	//warm, per file
	struct oid_data spc_oid;
	//warm, per file
	struct oid_data spc_algo_oid;
	//warm, per file
	struct oid_data spc_image_data_oid;
	//warm, per file
	struct oid_data spc_link_oid;
};

struct cache {
	struct known_oids *oids;
};

size_t buflen = 0;
size_t bufsz = 0;
char *buffer = NULL;

struct cache datacache = { 0 };


void __attribute((noreturn)) fatal(const char *msg)
{
	fprintf(stderr, "%s", msg);
	exit(1);
}

size_t append_to_buffer(size_t n, char *data)
{
	if (buffer == NULL)
		fatal("buffer not initialized\n");
	if ((buflen + n) > bufsz)
		fatal("insufficient buffer size\n");
	
	memcpy(buffer + buflen, data, n);
	buflen += n;
	
	return n;
}

//primitive writers

size_t encode_null(bool write)
{
	if (!write)
		return 2;
	
	char null_buf[2] = { NULL_TAG, 0x00 };
	return append_to_buffer(2, null_buf);
}

size_t encode_empty_set(bool write)
{
	if (!write)
		return 2;
	
	char empty_set_buf[2] = { SET_TAG, 0x00 };
	return append_to_buffer(2, empty_set_buf);
}

size_t encode_integer(int i, bool write)
{
	char sign = 0;
	
	if (i < 0) {
		i = -i;
		sign = 0x80;
	}
	
	if (write)
	{
		char int_buf[6] = { INTEGER_TAG, };
		
		if (i < 0x80) {
			int_buf[1] = 1;	/* length (without header) */
			int_buf[2] = i | sign;
			return append_to_buffer(3, int_buf);
		}
		if (i < 0x8000) {
			int_buf[1] = 2;	/* length */
			int_buf[2] = (i >> 8) | sign;
			int_buf[3] = i & 0xff;
			return append_to_buffer(4, int_buf);
		}
		if (i < 0x800000) {
			int_buf[1] = 3;	/* length */
			int_buf[2] = (i >> 16) | sign;
			int_buf[3] = (i >> 8) & 0xff;
			int_buf[4] = i & 0xff;
			return append_to_buffer(5, int_buf);
		}
		if (i < 0x80000000) {
			int_buf[1] = 4;	/* length */
			int_buf[2] = (i >> 24) | sign;
			int_buf[3] = (i >> 16) & 0xff;
			int_buf[4] = (i >> 8) & 0xff;
			int_buf[5] = i & 0xff;
			return append_to_buffer(6, int_buf);
		}
	}
	else
	{
		if (i < 0x80)
			return 3;
		if (i < 0x8000)
			return 4;
		if (i < 0x800000)
			return 5;
		if (i < 0x80000000)
			return 6;
	}
	fatal("can't encode this integer\n");
}

size_t encode_length_to_cache(size_t len, char* buf)
{
	if (len < 0x80) {
		buf[0] = len;
		return 1;
	}
	if (len < 0x100) {
		buf[0] = 0x81;	/* 1 more length bytes */
		buf[1] = len;
		return 2;
	}
	if (len < 0x10000) {
		buf[0] = 0x82;	/* 2 more length bytes */
		buf[1] = (len >> 8) & 0xff;
		buf[2] = len & 0xff;
		return 3;
	}
	if (len < 0x1000000) {
		buf[0] = 0x83;	/* 3 more length bytes */
		buf[1] = (len >> 16) & 0xff;
		buf[2] = (len >> 8) & 0xff;
		buf[3] = len & 0xff;
		return 4;
	}
	fatal("unsupported tag length\n");
}

size_t encode_tag_and_length(char tag, size_t len, bool write)
{
	if (write)
	{
		char buf[5] = { tag, };
		size_t length = 1 + encode_length_to_cache(len, buf + 1);
		return append_to_buffer(length, buf);
	}
	else
	{
		if (len < 0x80)
			return 2;
		if (len < 0x100)
			return 3;
		if (len < 0x10000)
			return 4;
		if (len < 0x1000000)
			return 5;
	}
	fatal("unsupported tag length\n");
}

size_t sizeof_oid_arc(int arc)
{
	if (arc < 0)
		fatal("OID arc must not be negative\n");
	
	if (arc < 0x80)
		return 1;
	if (arc < 0x4000)
		return 2;
	if (arc < 0x200000)
		return 3;
	
	fatal("can't encode this OID arc\n");
}

size_t encode_oid_arc_to_cache(int arc, char *buf)
{
	if (arc < 0)
		fatal("OID arc must not be negative\n");
	
	if (arc < 0x80) {
		buf[0] = arc;
		return 1;
	}
	if (arc < 0x4000) {
		buf[0] = ((arc >> 7) & 0x7f) | 0x80 ;
		buf[1] = arc & 0x7f;
		return 2;
	}
	if (arc < 0x200000) {
		buf[0] = ((arc >> 14) & 0x7f) | 0x80 ;
		buf[1] = ((arc >> 7) & 0x7f) | 0x80 ;
		buf[2] = arc & 0x7f;
		return 3;
	}
	
	fatal("can't encode this OID arc\n");
}

size_t encode_oid_arc(int arc)
{
	char buf[3];
	size_t length = encode_oid_arc_to_cache(arc, buf);
	return append_to_buffer(length, buf);
}


// oids encoders

size_t encode_oid(char *oid, bool write)
{
	char *next;
	size_t length;
	int root, sroot, child;
	
	size_t(*oid_arc_handler)(int) = sizeof_oid_arc;
	
	
	root = strtoul(oid, &next, 10);
	if (root == 0 && errno != 0) {
		fatal("could not parse OID root arc\n");
	}
	if (*next != '.') {
		fatal("syntax error in OID\n");
	}
	sroot = strtoul(next+1, &next, 10);
	if (sroot == 0 && errno != 0) {
		fatal("could not parse OID sub-root arc\n");
	}
	if (*next != '.' && *next != '\0') {
		fatal("syntax error in OID\n");
	}
	if (write)
		oid_arc_handler = encode_oid_arc;
	
	length = oid_arc_handler(root*40 + sroot);
	
	while (*next != '\0') {
		child = strtoul(next+1, &next, 10);
		if (child == 0 && errno != 0) {
			fatal("could not parse OID child arc\n");
		}
		if (*next != '.' && *next != '\0') {
			fatal("syntax error in OID\n");
		}
		length += oid_arc_handler(child);
	}
	return length;
}

size_t encode_oid_to_cache(char *oid, char *buf, size_t buf_sz)
{
	size_t length;
	char *next;
	int root, sroot, child;
	
	
	root = strtoul(oid, &next, 10);
	if (root == 0 && errno != 0) {
		fatal("could not parse OID root arc\n");
	}
	if (*next != '.') {
		fatal("syntax error in OID\n");
	}
	sroot = strtoul(next+1, &next, 10);
	if (sroot == 0 && errno != 0) {
		fatal("could not parse OID sub-root arc\n");
	}
	if (*next != '.' && *next != '\0') {
		fatal("syntax error in OID\n");
	}
	length = encode_oid_arc_to_cache(root * 40 + sroot, buf);
	
	while (*next != '\0') {
		if ((length + 3) > buf_sz)
			fatal("can't encode this OID\n");
		
		child = strtoul(next+1, &next, 10);
		if (child == 0 && errno != 0)
			fatal("could not parse OID child arc\n");
		if (*next != '.' && *next != '\0')
			fatal("syntax error in OID\n");
		
		length += encode_oid_arc_to_cache(child, buf + length);
	}
	return length;
}

//for any oids; necessary data is calculated on each request; may be expensive with "hot" oids
size_t encode_plain_oid_with_header(char *oid, bool write)
{
	size_t data_length = encode_oid(oid, false);
	
	size_t head_length = encode_tag_and_length(OID_TAG, data_length, write);
	if (write)
		return encode_oid(oid, true) + head_length;
	
	return data_length + head_length;
}

//for known oids; necessary data is calculated on first request and cached inside the oid object for further usage
size_t encode_known_oid_with_header(struct oid_data *oid, bool write)
{
	if (oid->string == NULL || *oid->string == '\0')
		fatal("the string value of the known OID must be not NULL nor empty string\n");
	
	if (oid->bytes == NULL)
	{
		// size of this buffer(256 + 4) is based on
		// max length of oid arc in bytes(3 for local encoder) times max known count of arcs(34)
		// rounded to nearest power of two
		// plus max length of length value(4 for local encoder)
		char oid_buf[0x104];
		size_t data_length = encode_oid_to_cache(oid->string, oid_buf + 4, 0x100);
		size_t head_length = 1 + encode_length_to_cache(data_length, oid_buf);
		oid->length = data_length + head_length;
		oid->bytes = malloc(oid->length);
		oid->bytes[0] = OID_TAG;
		memcpy(oid->bytes + 1, oid_buf, head_length);
		memcpy(oid->bytes + head_length, oid_buf + 4, data_length);
	}
	
	if (write)
		return append_to_buffer(oid->length, oid->bytes);
	
	return oid->length;
}


//generic string writer
size_t encode_tagged_string(char tag, size_t len, char *str, bool write)
{
	size_t head_length = encode_tag_and_length(tag, len, write);
	if (write)
		return append_to_buffer(len, str) + head_length;
	
	return len + head_length;
}

//string converters

size_t encode_string_as_utf16(const char *s, bool write)
{
	int i;
	
	if (write)
	{
		unsigned short utf16[UTF16_MAX_LEN];
		
		for (i = 0; i < UTF16_MAX_LEN && s[i] != '\0'; ++i) {
			utf16[i]=(unsigned char)(s[i]);
		}
		if (i < UTF16_MAX_LEN)
		{
			utf16[i] = 0;
			++i;
			
			return encode_tagged_string(OCTET_STRING_TAG, i * sizeof(utf16[0]), (char*)utf16, true);
		}
	}
	else
	{
		i = strlen(s);
		if (i < UTF16_MAX_LEN)
		{
			return encode_tagged_string(OCTET_STRING_TAG, (i + 1) * sizeof(unsigned short), NULL, false);
		}
	}
	
	fatal("string too long\n");
}

size_t encode_string_as_utf16_bmp(const char *s, bool write)
{
	int i;
	
	if (write)
	{
		unsigned short utf16[UTF16_MAX_LEN];
		
		for (i = 0; i < UTF16_MAX_LEN && s[i] != '\0'; ++i) {
			utf16[i]=(unsigned char)(s[i]) << 8;
		}
		
		if (s[i] == '\0')
		{
			return encode_tagged_string(BMP_STRING_TAG, i * sizeof(utf16[0]), (char*)utf16, true);
		}
	}
	else
	{
		i = strlen(s);
		if (i <= UTF16_MAX_LEN)
		{
			return encode_tagged_string(BMP_STRING_TAG, i * sizeof(unsigned short), NULL, false);
		}
	}
	
	fatal("string too long\n");
}


//generic data encoder
size_t encode_tagged_data(char tag, void *s, size_t a_fn(void*, bool), bool write)
{
	size_t data_length = a_fn(s, false);
	
	size_t head_length = encode_tag_and_length(tag, data_length, write);
	if (write)
		return a_fn(s, true) + head_length;
	
	return data_length + head_length;
}


//hi-level encoders

size_t encode_algo(void *p, bool write)
{
	size_t length = 0;
	
	//length += encode_known_oid_with_header(((struct algo*)p)->algo_oid, write);
	length += encode_known_oid_with_header(&datacache.oids->algo_oid, write);
	length += encode_null(write);
	
	return length;
}

size_t encode_algo_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_algo, write);
}

size_t encode_attribute_name_and_value(void *p, bool write)
{
	struct an_attribute *attr = p;
	size_t length = 0;
	
	length += encode_string_as_utf16_bmp(attr->name, write);
	length += encode_integer(268500993, write);
	length += encode_string_as_utf16(attr->value, write);
	
	return length;
}

size_t encode_attribute_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_attribute_name_and_value, write);
}

size_t encode_attribute(void *p, bool write)
{
	struct an_attribute *attr = p;
	size_t length = 0;
	
	length += encode_known_oid_with_header(&datacache.oids->attribute_name_value_oid, write);
	length += encode_tagged_data(attr->encode_as_set? SET_TAG : OCTET_STRING_TAG, p, encode_attribute_sequence, write);
	
	return length;
}

size_t encode_member_info(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	length += encode_string_as_utf16_bmp(file->guid, write);
	length += encode_integer(512, write);
	
	return length;
}

size_t encode_member_info_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_member_info, write);
}

size_t encode_member_info_oid(void *p, bool write)
{
	size_t length = 0;
	
	length += encode_known_oid_with_header(&datacache.oids->member_info_oid, write);
	length += encode_tagged_data(SET_TAG, p, encode_member_info_sequence, write);
	
	return length;
}

size_t encode_spc_image_data(void *p, bool write)
{
	size_t length = encode_known_oid_with_header(&datacache.oids->spc_image_data_oid, write);
	
	//*
	if (!write)
		return length + 0x28;
	
	// <<<obsolete>>>: vanila         vv                                  vv          vv          vv |  value utf-16-bmp, to the end
	char image_data[0x28] = { 0x30, 0x26, 0x03, 0x02, 0x05, 0xA0, 0xA0, 0x20, 0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E };
	
	return 
		length + append_to_buffer(sizeof(image_data), image_data);
	/*/
	if (!write)
		return length + 0x1A;
	
	// zaklebt: hacked catgen         vv                                  vv          vv          vv |  value utf-16-bmp, to the end
	char image_data[0x1A] = { 0x30, 0x18, 0x03, 0x02, 0x05, 0xA0, 0xA0, 0x12, 0xA2, 0x10, 0x80, 0x0E, 0x00, 0x5A, 0x00, 0x61, 0x00, 0x6B, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x62, 0x00, 0x74 };
	
	return 
		length + append_to_buffer(sizeof(image_data), image_data);
	/**/
}

size_t encode_spc_link(void *p, bool write)
{
	size_t length = encode_known_oid_with_header(&datacache.oids->spc_link_oid, write);
	
	//*
	if (!write)
		return length + 0x20;
	
	// <<<obsolete>>>: vanila        vv          vv |  value utf-16-bmp, to the end
	char link_data[0x20] = { 0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E };
	
	return
		length + append_to_buffer(sizeof(link_data), link_data);
	/*/
	if (!write)
		return length + 0x12;
	
	// zaklebt: hacked catgen        vv          vv |  value utf-16-bmp, to the end
	char link_data[0x12] = { 0xA2, 0x10, 0x80, 0x0E, 0x00, 0x7A, 0x00, 0x61, 0x00, 0x6B, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x62, 0x00, 0x74 };
	
	return
		length + append_to_buffer(sizeof(link_data), link_data);
	/**/
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
	size_t length = 0;
	
	length += encode_known_oid_with_header(&datacache.oids->spc_algo_oid, write);
	length += encode_null(write);
	
	return length;
}

size_t encode_spc_algo(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_spc_algo_oid, write);
	length += encode_tagged_string(OCTET_STRING_TAG, SHA1_BYTE_LEN, file->sha1_bytes, write);
	
	return length;
}

size_t encode_spc(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	length += encode_tagged_data(SEQUENCE_TAG, p, file->is_pe? encode_spc_image_data : encode_spc_link, write);
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_spc_algo, write);
	
	return length;
}

size_t encode_spc_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_spc, write);
}

size_t encode_spc_oid(void *p, bool write)
{
	size_t length = 0;
	
	length += encode_known_oid_with_header(&datacache.oids->spc_oid, write);
	length += encode_tagged_data(SET_TAG, p, encode_spc_sequence, write);
	
	return length;
}

size_t encode_file_attributes(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	/*
	//initial order
	length += encode_tagged_data(SEQUENCE_TAG, &file->name_attribute, encode_attribute, write);
	length += encode_tagged_data(SEQUENCE_TAG, &file->os_attribute, encode_attribute, write);
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_spc_oid, write);
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_member_info_oid, write);
	/*/
	//Inf2Cat like order
	length += encode_tagged_data(SEQUENCE_TAG, &file->os_attribute, encode_attribute, write);
	length += encode_tagged_data(SEQUENCE_TAG, &file->name_attribute, encode_attribute, write);
	if (file->is_pe)
	{
		length += encode_tagged_data(SEQUENCE_TAG, p, encode_member_info_oid, write);
		length += encode_tagged_data(SEQUENCE_TAG, p, encode_spc_oid, write);
	}
	else
	{
		length += encode_tagged_data(SEQUENCE_TAG, p, encode_spc_oid, write);
		length += encode_tagged_data(SEQUENCE_TAG, p, encode_member_info_oid, write);
	}
	/**/
	
	return length;
}

size_t encode_one_file(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	length += encode_string_as_utf16(file->sha1_str, write);
	length += encode_tagged_data(SET_TAG, p, encode_file_attributes, write);
	
	return length;
}

size_t encode_files(void *p, bool write)
{
	struct i_list_node *node = p;
	size_t length = 0;
	
	while (node) {
		length += encode_tagged_data(SEQUENCE_TAG, node, encode_one_file, write);
		node = node->next;
	}
	
	return length;
}

size_t encode_catalog_list_member_oid(void *p, bool write)
{
	size_t length = 0;
	
	//length += encode_known_oid_with_header(((struct catalog_list_element*)p)->catalog_list_member_oid, write);
	length += encode_known_oid_with_header(&datacache.oids->catalog_list_member_oid, write);
	length += encode_null(write);
	
	return length;
}

size_t encode_catalog_list_oid(void *p, bool write)
{
	//return encode_known_oid_with_header(((struct catalog_list_element*)p)->catalog_list_oid, write);
	return encode_known_oid_with_header(&datacache.oids->catalog_list_oid, write);
}

size_t encode_global_attributes2(void *p, bool write)
{
	struct catalog_list_element *elem = p;
	size_t length = 0;
	
	length += encode_tagged_data(SEQUENCE_TAG, &elem->os_info, encode_attribute, write);
	length += encode_tagged_data(SEQUENCE_TAG, &elem->hardware_id, encode_attribute, write);
	
	return length;
}

size_t encode_global_attributes(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_global_attributes2, write);
}

size_t encode_catalog_list_elements(void *p, bool write)
{
	struct catalog_list_element *elem = p;
	size_t length = 0;
	
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_catalog_list_oid, write);
	length += encode_tagged_string(OCTET_STRING_TAG, 16, elem->a_hash, write);
	length += encode_tagged_string(UTC_TIME_TAG, 13, elem->a_time, write);
	length += encode_tagged_data(SEQUENCE_TAG, p, encode_catalog_list_member_oid, write);
	length += encode_tagged_data(SEQUENCE_TAG, elem->files, encode_files, write);
	length += encode_tagged_data(ARRAY_TAG, p, encode_global_attributes, write);
	
	return length;
}

size_t encode_catalog_list_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_catalog_list_elements, write);
}

size_t encode_cert_trust_list(void *p, bool write)
{
	struct cert_trust_list *cert = p;
	size_t length = 0;
	
	length += encode_known_oid_with_header(cert->cert_trust_oid, write);
	//length += encode_known_oid_with_header(&datacache.oids->cert_trust_oid, write);
	length += encode_tagged_data(ARRAY_TAG, cert->catalog_list_element, encode_catalog_list_sequence, write);
	
	return length;
}

size_t encode_pkcs7_data(void *p, bool write)
{
	struct pkcs7_data *data = p;
	size_t length = 0;
	
	length += encode_integer(data->an_int, write);
	//length += encode_tagged_data(SET_TAG, &data->algo, encode_algo_sequence, write);
	length += encode_empty_set(write);
	length += encode_tagged_data(SEQUENCE_TAG, &data->cert_trust_list, encode_cert_trust_list, write);
	length += encode_empty_set(write);
	
	return length;
}

size_t encode_pkcs7_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_pkcs7_data, write);
}

size_t encode_pkcs7_toplevel(void *p, bool write)
{
	struct pkcs7_toplevel *sdat = p;
	size_t length = 0;
	
	length += encode_known_oid_with_header(sdat->signed_data_oid, write);
	//length += encode_known_oid_with_header(&datacache.oids->signed_data_oid, write);
	//length += encode_tagged_data(SEQUENCE_TAG, &sdat->data, encode_pkcs7_array, write);
	length += encode_tagged_data(ARRAY_TAG, &sdat->data, encode_pkcs7_sequence, write);
	
	return length;
}

void free_allocated(struct pkcs7_toplevel *s)
{
	struct a_file *next_file = s->data.cert_trust_list.catalog_list_element->files;
	struct a_file *this_file;
	s->data.cert_trust_list.catalog_list_element->files = NULL;
	while (next_file)
	{
		this_file = next_file;
		next_file = (struct a_file*)this_file->node.next;
		//free(this_file->name_attribute.value);
		this_file->name_attribute.value = NULL;
		this_file->node.next = NULL;
		free(this_file);
	}
	
	struct oid_data *one_oid = (struct oid_data*)datacache.oids;
	size_t oids_cnt = sizeof(struct known_oids) / sizeof(struct oid_data);
	datacache.oids = NULL;
	while (oids_cnt--)
	{
		free(one_oid->bytes);
		one_oid->bytes = NULL;
		one_oid->length = 0;
		++one_oid;
	}
	
	
	free(s->data.cert_trust_list.catalog_list_element);
}

void create_binary_tree(void *s)
{
	/* compute sufficient buffer size */
	buflen = 0;
	size_t data_length = encode_pkcs7_toplevel(s, false);
	bufsz = encode_tag_and_length(SEQUENCE_TAG, data_length, false) + data_length;
	
	/* place for extra limitation
	   take a note:
	     while limitation of the redirection usually not reachable or depends on the target file system
	     it's much lower for pipes https://unix.stackexchange.com/a/11954
	*/
	
	/* create buffer of computed size */
	buffer = malloc(bufsz);
	if (buffer == NULL)
		fatal("out of memory");
	/* write data to buffer */
	encode_tag_and_length(SEQUENCE_TAG, data_length, true);
	encode_pkcs7_toplevel(s, true);
	
	/* check written data length */
	if (buflen != bufsz)
		fatal("length mismatch\n");
}

void __attribute((noreturn)) usage_and_exit(void)
{
	fprintf(stderr, "Usage: generate_cat_file [-h <hardware-id>] [-O OS string] [-A OS attribute string] file-with-hash1 [ file-with-hash2 ... ]\n");
	fprintf(stderr, "Generates a Microsoft Security Catalog (\".cat\") file.\n");
	fprintf(stderr, "file-with-hash has the format filename:sha1-hash-in-hex[:PE]\n");
	fprintf(stderr, "Use osslsigncode to sign it afterwards.\n");
	exit(1);
}

//note: it does modify f_args content (replace colon with null) and creates references to its particular parts
void parse_file_args(char **f_args, int f_count, char *os_attr, struct a_file **file)
{
	char *arg_p, *fname_p, *hash_p;
	struct a_file *this_file;
	//char *fname_buf;
	int fname_len;
	bool is_pe;
	
	*file = NULL;
	
	while (f_count--)
	{
		arg_p = f_args[f_count];
		fname_p = arg_p;
		for (; *arg_p && *arg_p != ':'; ++arg_p) ;
		if (!*arg_p) {
			usage_and_exit();
		}
		fname_len = arg_p - fname_p;
		if (fname_len == 0) {
			fatal("file name can't be empty\n");
		}
		
		hash_p = ++arg_p;
		
		for (; *arg_p && *arg_p != ':'; ++arg_p) ;
		if (arg_p - hash_p != SHA1_STR_LEN) {
			fatal("unsupported hash, sha1 expected\n");
		}
		
		if (*arg_p)
		{
			if (strcmp(":PE", arg_p)) //if not equals
				usage_and_exit();
			
			is_pe = true;
		}
		else
			is_pe = false;
		
		this_file = malloc(sizeof(struct a_file));
		if (this_file == NULL) {
			fatal("out of memory");
		}
		//fname_buf = malloc(fname_len + 1);
		//if (fname_buf == NULL) {
		//	fatal("out of memory");
		//}
		
		//memcpy(fname_buf, fname_p, fname_len);
		//fname_buf[fname_len] = '\0';
		fname_p[fname_len] = '\0';
		
		//memcpy(this_file->sha1_str, hash_p, SHA1_STR_LEN);
		this_file->sha1_str = hash_p;
		this_file->sha1_str[SHA1_STR_LEN] = '\0';
		for (int i = 0, j = 0; i < SHA1_BYTE_LEN; ++i, j += 2) {
			this_file->sha1_bytes[i] = (hexdigit(hash_p[j]) << 4) + hexdigit(hash_p[j + 1]);
		}
		
		this_file->name_attribute.name = "File";
		//this_file->name_attribute.value = fname_buf;
		this_file->name_attribute.value = fname_p;
		this_file->name_attribute.encode_as_set = true;
		this_file->os_attribute.name = "OSAttr";
		this_file->os_attribute.value = os_attr;
		this_file->os_attribute.encode_as_set = true;
		
		//this_file->member_info_oid.oid = "1.3.6.1.4.1.311.12.2.2";
		this_file->is_pe = is_pe;
		
		if (this_file->is_pe) {
			this_file->guid = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
		} else {
			this_file->guid = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
		}
		
		this_file->node.next = (struct i_list_node*)*file;
		*file = this_file;
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
	
	char *os_string = "7X64,8X64,_v100_X64";
	char *os_attr_string = "2:6.1,2:6.2,2:10.0";
	char *hardware_id = "windrbd";
	struct a_file *files = NULL;
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
	
	parse_file_args(argv + optind, argc - optind, os_attr_string, &files);
	
	s.data.cert_trust_list.catalog_list_element = malloc(sizeof(struct catalog_list_element));
	if (s.data.cert_trust_list.catalog_list_element == NULL) {
		fatal("Out of memory");
	}
	for (i=0;i<sizeof(a_hash);i++)
		a_hash[i] = i;
	
	s.data.an_int = 1;
	s.data.cert_trust_list.catalog_list_element->a_hash = a_hash;
	s.data.cert_trust_list.catalog_list_element->a_time = "230823140713Z";
	s.data.cert_trust_list.catalog_list_element->hardware_id.name = "HWID1";
	s.data.cert_trust_list.catalog_list_element->hardware_id.value = hardware_id;
	s.data.cert_trust_list.catalog_list_element->hardware_id.encode_as_set = false;
	s.data.cert_trust_list.catalog_list_element->files = files;
	s.data.cert_trust_list.catalog_list_element->os_info.name = "OS";
//	s.data.cert_trust_list.catalog_list_element->os_info.value = "XP_X86,Vista_X86,Vista_X64,7_X86,7_X64,8_X86,8_X64,6_3_X86,6_3_X64,10_X86,10_X64";
	s.data.cert_trust_list.catalog_list_element->os_info.value = os_string;
	s.data.cert_trust_list.catalog_list_element->os_info.encode_as_set = false;
	
	/* init OIDs cache, actual data will be computed on first access per OID */
	struct known_oids oids = { 0 };
	datacache.oids = &oids;
	oids.signed_data_oid.string				= "1.2.840.113549.1.7.2";
	//{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) sha256(1)}
	oids.algo_oid.string					= "2.16.840.1.101.3.4.2.1";
	oids.cert_trust_oid.string				= "1.3.6.1.4.1.311.10.1";
	oids.catalog_list_oid.string			= "1.3.6.1.4.1.311.12.1.1";
	oids.catalog_list_member_oid.string		= "1.3.6.1.4.1.311.12.1.2";
	oids.attribute_name_value_oid.string	= "1.3.6.1.4.1.311.12.2.1";
	oids.member_info_oid.string				= "1.3.6.1.4.1.311.12.2.2";
	oids.spc_oid.string						= "1.3.6.1.4.1.311.2.1.4";
	oids.spc_image_data_oid.string			= "1.3.6.1.4.1.311.2.1.15";
	oids.spc_link_oid.string				= "1.3.6.1.4.1.311.2.1.25";
	//{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) sha1(26)}
	oids.spc_algo_oid.string				= "1.3.14.3.2.26";
	
	/* these references should be ok cuz both s and oids created on current stack, so they invalidates together */
	s.signed_data_oid = &oids.signed_data_oid;
	s.data.algo.algo_oid = &oids.algo_oid;
	s.data.cert_trust_list.cert_trust_oid = &oids.cert_trust_oid;
	s.data.cert_trust_list.catalog_list_element->catalog_list_oid = &oids.catalog_list_oid;
	s.data.cert_trust_list.catalog_list_element->catalog_list_member_oid = &oids.catalog_list_member_oid;
	
	
	
	/* generate binary DER */
	create_binary_tree(&s);
	
	/* free the memory allocated on the heap */
	free_allocated(&s);
	files = NULL;
	
	/* and write to stdout or so ... */
	fwrite(buffer, buflen, 1, stdout);
	free(buffer); buffer = NULL;
}
