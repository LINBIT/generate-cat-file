#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#if !defined(_WIN32) && (defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__)))
	#include <sys/errno.h>
#endif

#if defined(_WINDOWS) || defined(_WIN32) || defined(WIN32)
	#include <fcntl.h>
	#include <io.h>
	
	#define IS_WINDOWS
#endif


/* DER encoding */

#define INTEGER_TAG         0x02
#define OCTET_STRING_TAG    0x04
#define NULL_TAG            0x05
#define OID_TAG             0x06
#define UTC_TIME_TAG        0x17
#define BMP_STRING_TAG      0x1E
#define SEQUENCE_TAG        0x30  //sub-elements must appear in the definition order
#define SET_TAG             0x31  //sub-elements may appear in any order, regardless of the definition
#define ARRAY_TAG           0xA0

#define SHA1_BYTE_LEN   20
#define SHA1_STR_LEN    SHA1_BYTE_LEN * 2
#define UTF16_MAX_LEN   1000

const char *const ERR_OOM		= "Out of memory";

//linked-list-node
struct list_node {
	struct list_node *next;
	void *data;
};

struct oid_data {
	/* the OID in human readable form */
	char *string;
	/* the OID in the end-form(includes header) */
	char *bytes;
	/* length of the OID in the end-form */
	size_t length;
};

struct null {
};

struct algo {
	struct oid_data *algo_oid;
	struct null a_null;
};

struct an_attribute_data {
	char *name;
	char *value;
};

struct an_attribute {
	struct an_attribute_data data;
	bool encode_as_set;	/* SET or OCTET_STRING */
};

struct a_file {
	char *guid;	/* {C689AAB8-8E78-11D0-8C47-00C04FC295EE} */
	char *sha1_str; //sha1 string
	
	struct an_attribute name_attribute;
	struct an_attribute os_attribute;
	
	bool is_pe;
	
	char sha1_bytes[SHA1_BYTE_LEN];  //sha1 bytes in big endian order
};

struct catalog_list_element {
	struct oid_data *catalog_list_oid;
	char *a_guid;
	char *a_time;
	struct oid_data *catalog_list_member_oid;
	
	struct list_node *files;
	struct list_node *hwids;
	
	struct an_attribute os_info;
};

struct cert_trust_list {
	struct oid_data *cert_trust_oid;
	struct catalog_list_element *catalog_list_element;
};

struct pkcs7_data {
	struct cert_trust_list cert_trust_list;
	/* empty set: using SHA-1 which is default */
	struct algo algo;
	int an_int;
};

struct pkcs7_toplevel {
	struct oid_data *signed_data_oid;
	struct pkcs7_data data;
};

struct known_oids {
	//cold, used once
	struct oid_data signed_data_oid;
	//cold, used once (if used)
	struct oid_data algo_oid;
	//cold, used once
	struct oid_data cert_trust_oid;
	//cold, used once
	struct oid_data catalog_list_oid;
	//cold, used once (now, depends on tree)
	struct oid_data catalog_list_member_oid;
	//hot, x2 per file, per HWID and one more
	struct oid_data attribute_name_value_oid;
	//warm, per file
	struct oid_data member_info_oid;
	//warm, per file
	struct oid_data spc_oid;
	//warm, per file
	struct oid_data spc_image_data_oid;
	//warm, per file
	struct oid_data spc_link_oid;
	//warm, per file
	struct oid_data spc_algo_oid;
};

static struct known_oids oids;

struct node_data {
	size_t length;
};

struct cache {
	//each calculation/write advance this to last visited leaf in current branch
	//so, on write just after calc for the same branch, store current node before calc and restore it before write
	struct list_node *node;
};

size_t buflen = 0;
size_t bufsz = 0;
char *buffer = NULL;

struct cache datacache = { 0 };


void __attribute((noreturn)) fatal(const char *msg)
{
	fputs(msg, stderr);
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
	//-128 and 128 (or -1 and 255) both can be encoded in one byte
	//read 8.3.2 and 8.3.3 of X.690, take account of NOTE for 8.3.2
	//not full two's complement conversion, on storing the original value is used
	int tmp = i < 0? ~i : i;
	
	if (write)
	{
		char int_buf[6] = { INTEGER_TAG, };
		
		if (tmp < 0x80) {
			int_buf[1] = 1;	/* length (without header) */
			int_buf[2] = i & 0xff;
			return append_to_buffer(3, int_buf);
		}
		if (tmp < 0x8000) {
			int_buf[1] = 2;	/* length */
			int_buf[2] = (i >> 8) & 0xff;
			int_buf[3] = i & 0xff;
			return append_to_buffer(4, int_buf);
		}
		if (tmp < 0x800000) {
			int_buf[1] = 3;	/* length */
			int_buf[2] = (i >> 16) & 0xff;
			int_buf[3] = (i >> 8) & 0xff;
			int_buf[4] = i & 0xff;
			return append_to_buffer(5, int_buf);
		}
		if (tmp < 0x80000000) {
			int_buf[1] = 4;	/* length */
			int_buf[2] = (i >> 24) & 0xff;
			int_buf[3] = (i >> 16) & 0xff;
			int_buf[4] = (i >> 8) & 0xff;
			int_buf[5] = i & 0xff;
			return append_to_buffer(6, int_buf);
		}
	}
	else
	{
		if (tmp < 0x80)
			return 3;
		if (tmp < 0x8000)
			return 4;
		if (tmp < 0x800000)
			return 5;
		if (tmp < 0x80000000)
			return 6;
	}
	fatal("can't encode this integer\n");
}

size_t encode_length_to_cache(size_t len, char *buf)
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

	size_t (*oid_arc_handler)(int) = sizeof_oid_arc;

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

	length = oid_arc_handler(root * 40 + sroot);

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

//for any oids; byte form is calculated on each write; may be expensive with "hot" oids
size_t encode_plain_oid_with_header(char *oid, bool write)
{
	size_t oid_length = encode_oid(oid, false);
	size_t head_length = encode_tag_and_length(OID_TAG, oid_length, write);
	if (write)
		return encode_oid(oid, true) + head_length;

	return oid_length + head_length;
}

//for known oids; necessary data is calculated on first request and cached inside the oid object for further usage
size_t encode_known_oid_with_header(struct oid_data *oid, bool write)
{
	if (oid->string == NULL || *oid->string == '\0')
		fatal("the string value of the known OID must be not NULL nor empty string\n");

	if (oid->bytes == NULL)
	{
		// size of this buffer(128 + 4) is based on
		// max length of oid arc in bytes(3 for local encoder) times max known count of arcs(34)
		// rounded to nearest power of two
		// plus max length of length value(4 for local encoder)
		char oid_buf[0x84];
		size_t data_length = encode_oid_to_cache(oid->string, oid_buf + 4, 0x80);
		size_t head_length = encode_length_to_cache(data_length, oid_buf);
		oid->length = data_length + head_length + 1;
		oid->bytes = malloc(oid->length);
		if (oid->bytes == NULL)
		{
			fatal(ERR_OOM);
		}
		oid->bytes[0] = OID_TAG;
		memcpy(oid->bytes + 1, oid_buf, head_length);
		memcpy(oid->bytes + 1 + head_length, oid_buf + 4, data_length);
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
			utf16[i++] = 0;
			return encode_tagged_string(OCTET_STRING_TAG, i * sizeof(utf16[0]), (char *) utf16, true);
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
			return encode_tagged_string(BMP_STRING_TAG, i * sizeof(utf16[0]), (char *) utf16, true);
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
size_t encode_tagged_data(char tag, void *s, size_t a_fn(void *, bool), bool write)
{
	struct list_node *this_node = datacache.node->next;
	struct node_data *node_data;
	
	if (this_node == NULL)
	{
		this_node = malloc(sizeof(struct list_node) + sizeof(struct node_data));
		if (this_node == NULL)
		{
			fatal(ERR_OOM);
		}
		datacache.node->next = this_node;
		datacache.node = this_node;
		this_node->next = NULL;
		this_node->data = this_node + 1;
		node_data = this_node->data;
		node_data->length = a_fn(s, false);
	}
	
	node_data = this_node->data;
	size_t head_length = encode_tag_and_length(tag, node_data->length, write);
	if (write)
	{
		//(re-)set datacache.node to proper reference
		datacache.node = this_node;
		return a_fn(s, true) + head_length;
	}
	
	return node_data->length + head_length;
}


//hi-level encoders

size_t encode_algo(void *p, bool write)
{
	size_t length = 0;

	length += encode_known_oid_with_header(&oids.algo_oid, write);
	length += encode_null(write);

	return length;
}

size_t encode_algo_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_algo, write);
}

size_t encode_attribute_name_and_value(void *p, bool write)
{
	struct an_attribute_data *attr = p;
	size_t length = 0;
	
	length += encode_string_as_utf16_bmp(attr->name, write);
	//mscat.h
	//                         CRYPTCAT_ATTR_AUTHENTICATED
	//                         |  CRYPTCAT_ATTR_DATAASCII
	//                         |  |   CRYPTCAT_ATTR_NAMEASCII
	//                         v  v   v
	length += encode_integer(0x10010001, write);
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
	
	length += encode_known_oid_with_header(&oids.attribute_name_value_oid, write);
	length += encode_tagged_data(attr->encode_as_set? SET_TAG : OCTET_STRING_TAG, p, encode_attribute_sequence, write);
	
	return length;
}

size_t encode_member_info(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
	length += encode_string_as_utf16_bmp(file->guid, write);
	//CryptCATOpen() ms docs : version, can be 0x100, 0x200
	length += encode_integer(0x200, write);
	
	return length;
}

size_t encode_member_info_sequence(void *p, bool write)
{
	return encode_tagged_data(SEQUENCE_TAG, p, encode_member_info, write);
}

size_t encode_member_info_oid(void *p, bool write)
{
	size_t length = 0;
	
	length += encode_known_oid_with_header(&oids.member_info_oid, write);
	length += encode_tagged_data(SET_TAG, p, encode_member_info_sequence, write);
	
	return length;
}

size_t encode_spc_image_data(void *p, bool write)
{
	size_t length = encode_known_oid_with_header(&oids.spc_image_data_oid, write);
	
	//*
	if (!write)
		return length + 0x28;
	
	// <<<obsolete>>>: vanila         vv                                  vv          vv          vv |  value utf-16-bmp, to the end
	char image_data[0x28] = { 0x30, 0x26, 0x03, 0x02, 0x05, 0xA0, 0xA0, 0x20, 0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E };
	
	return length + append_to_buffer(sizeof(image_data), image_data);
}

size_t encode_spc_link(void *p, bool write)
{
	size_t length = encode_known_oid_with_header(&oids.spc_link_oid, write);
	
	if (!write)
		return length + 0x20;
	
	// <<<obsolete>>>: vanila        vv          vv |  value utf-16-bmp, to the end
	char link_data[0x20] = { 0xA2, 0x1E, 0x80, 0x1C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x4F, 0x00, 0x62, 0x00, 0x73, 0x00, 0x6F, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x74, 0x00, 0x65, 0x00, 0x3E, 0x00, 0x3E, 0x00, 0x3E };
	
	return length + append_to_buffer(sizeof(link_data), link_data);
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
	
	length += encode_known_oid_with_header(&oids.spc_algo_oid, write);
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
	
	length += encode_known_oid_with_header(&oids.spc_oid, write);
	length += encode_tagged_data(SET_TAG, p, encode_spc_sequence, write);
	
	return length;
}

size_t encode_file_attributes(void *p, bool write)
{
	struct a_file *file = p;
	size_t length = 0;
	
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
	struct list_node *node = p;
	size_t length = 0;
	
	while (node) {
		length += encode_tagged_data(SEQUENCE_TAG, node->data, encode_one_file, write);
		node = node->next;
	}
	
	return length;
}

size_t encode_catalog_list_member_oid(void *p, bool write)
{
	size_t length = 0;
	
	length += encode_known_oid_with_header(&oids.catalog_list_member_oid, write);
	length += encode_null(write);
	
	return length;
}

size_t encode_catalog_list_oid(void *p, bool write)
{
	return encode_known_oid_with_header(&oids.catalog_list_oid, write);
}

//specialized version of encode_attribute()
size_t encode_one_hwid(void *p, bool write)
{
	size_t length = 0;

	length += encode_known_oid_with_header(&oids.attribute_name_value_oid, write);
	length += encode_tagged_data(OCTET_STRING_TAG, p, encode_attribute_sequence, write);

	return length;
}

size_t encode_hwids(struct list_node *hwid, bool write)
{
	size_t length = 0;
	
	while (hwid) {
		length += encode_tagged_data(SEQUENCE_TAG, hwid->data, encode_one_hwid, write);
		hwid = hwid->next;
	}
	
	return length;
}

size_t encode_global_attributes2(void *p, bool write)
{
	struct catalog_list_element *elem = p;
	size_t length = 0;
	
	length += encode_tagged_data(SEQUENCE_TAG, &elem->os_info, encode_attribute, write);
	length += encode_hwids(elem->hwids, write);
	
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
	length += encode_tagged_string(OCTET_STRING_TAG, 16, elem->a_guid, write);
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
	length += encode_tagged_data(ARRAY_TAG, cert->catalog_list_element, encode_catalog_list_sequence, write);
	
	return length;
}

size_t encode_pkcs7_data(void *p, bool write)
{
	struct pkcs7_data *data = p;
	size_t length = 0;
	
	length += encode_integer(data->an_int, write); //version?
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
	length += encode_tagged_data(ARRAY_TAG, &sdat->data, encode_pkcs7_sequence, write);
	
	return length;
}

void free_allocated(struct pkcs7_toplevel *sdat)
{
	struct list_node *next_node;
	struct list_node *this_node;

	struct node_data *node_data;
	next_node = datacache.node;
	datacache.node = NULL;
	while (next_node)
	{
		this_node = next_node;
		next_node = this_node->next;
		node_data = this_node->data;
		node_data->length = 0;
		this_node->data = NULL;
		this_node->next = NULL;
		free(this_node);
	}

	struct a_file *file_data;
	next_node = sdat->data.cert_trust_list.catalog_list_element->files;
	sdat->data.cert_trust_list.catalog_list_element->files = NULL;
	while (next_node)
	{
		this_node = next_node;
		next_node = this_node->next;
		file_data = this_node->data;
		file_data->name_attribute.data.value = NULL;
		this_node->data = NULL;
		this_node->next = NULL;
		free(this_node);
	}

	struct an_attribute_data *hwid_data;
	next_node = sdat->data.cert_trust_list.catalog_list_element->hwids;
	sdat->data.cert_trust_list.catalog_list_element->hwids = NULL;
	while (next_node)
	{
		this_node = next_node;
		next_node = this_node->next;
		hwid_data = this_node->data;
		free(hwid_data->name);
		hwid_data->name = NULL;
		hwid_data->value = NULL;
		this_node->data = NULL;
		this_node->next = NULL;
		free(this_node);
	}

	free(sdat->data.cert_trust_list.catalog_list_element->a_time);
	sdat->data.cert_trust_list.catalog_list_element->a_time = NULL;

	free(sdat->data.cert_trust_list.catalog_list_element->a_guid);
	sdat->data.cert_trust_list.catalog_list_element->a_guid = NULL;

	free(sdat->data.cert_trust_list.catalog_list_element);
}

void create_binary_tree(struct pkcs7_toplevel *sdat)
{
	buflen = 0;
	/* store root_node, as it will be used for buffer size and also as reset point */
	struct list_node *root_node = datacache.node;
	struct node_data *root_data = root_node->data;
	/* compute sufficient buffer size and store it in root node */
	root_data->length = encode_pkcs7_toplevel(sdat, false);
	bufsz =
		  encode_tag_and_length(SEQUENCE_TAG, root_data->length, false)
		+ root_data->length
	;
	
	if (buflen != 0)
		fatal("unexpected write\n");
	
	/* place for extra limitation
	   take a note:
	     while limitation of the redirection usually not reachable or depends on the target file system
	     it's much lower for pipes https://unix.stackexchange.com/a/11954
	*/
	
	/* create buffer of computed size */
	buffer = malloc(bufsz);
	if (buffer == NULL)
		fatal(ERR_OOM);
	/* reset cache node to root_node */
	datacache.node = root_node;
	/* write data to buffer */
	encode_tag_and_length(SEQUENCE_TAG, root_data->length, true);
	encode_pkcs7_toplevel(sdat, true);
	
	/* check written data length */
	if (buflen != bufsz)
		fatal("length mismatch\n");
}

void __attribute((noreturn)) usage_and_exit(void)
{
	fprintf(stderr, "Usage: generate_cat_file -h <hardware-ids> [-O OS string] [-A OS attribute string] [-G <cat-guid>] [-T <generation-time>] file-with-hash1 [ file-with-hash2 ... ]\n");
	fprintf(stderr, "Generates a Microsoft Security Catalog (\".cat\") file.\n");
	fprintf(stderr, "hardware-ids is comma separated list\n");
	fprintf(stderr, "generation-time has the format YYmmddHHMMSSZ, Z is constant, means 0 timezone\n");
	fprintf(stderr, "file-with-hash has the format filename:sha1-hash-in-hex[:PE]\n");
	fprintf(stderr, "Use osslsigncode to sign it afterwards.\n");
	exit(1);
}

char* generate_pseudo_GUID_bytes()
{
	char *a_guid = malloc(0x10);
	float rf_num;
	int *ri_num = (int*)&rf_num; //float "projection"
	time_t guid_time = time(NULL);
	srand(guid_time);
	//5 floats as ints xor-ed with overlap
	//this divisions only to get more scattered bits, divisors are just random numbers
	rf_num = rand() / 0.73; *(int*)(a_guid + 0xC) ^= *ri_num;
	rf_num = rand() / 0.61; *(int*)(a_guid + 0x9) ^= *ri_num;
	rf_num = rand() / 0.98; *(int*)(a_guid + 0x6) ^= *ri_num;
	rf_num = rand() / 0.24; *(int*)(a_guid + 0x3) ^= *ri_num;
	rf_num = rand() / 0.35; *(int*)(a_guid + 0x0) ^= *ri_num;
	
	//xor time
	*(unsigned long long*)a_guid ^= (unsigned long long)guid_time << 0x10;
	
	//set certain bits
	a_guid[0x7] = 0x40 | (a_guid[0x7] & 0x0F); //ver 4, note: modified byte is a byte 8 instead of 7 - SM things
	a_guid[0x8] = 0x80 | (a_guid[0x8] & 0x3F); //var 1
	
	return a_guid;
}

char* validate_GUID_str(char *guid_str)
{
	size_t guid_str_len = strlen(guid_str);
	char guid_version, guid_variation;
	int dash_len = 0;
	
	switch (guid_str_len)
	{
		case 0x26: // {00000000-0000-4000-8000-000000000000} - windows format
			if (guid_str[0x00] != '{' || guid_str[guid_str_len - 1] != '}')
				fatal("invalid GUID format");
			++guid_str; //skip opened curly brace and intentional fall to the next branch (0x24) as this two formats only differ by wrapping in curly braces
			
		case 0x24: // 00000000-0000-4000-8000-000000000000 - general format
			if (guid_str[0x08] != '-' || guid_str[0x0D] != '-' || guid_str[0x12] != '-' || guid_str[0x17] != '-')
				fatal("invalid GUID format");
			guid_version = guid_str[0x0E];
			guid_variation = hexdigit(guid_str[0x13]);
			dash_len = 1;
			break;
		case 0x20: // 00000000000040008000000000000000 - dashless format
			guid_version = guid_str[0x0C];
			guid_variation = hexdigit(guid_str[0x10]);
			break;
		default:
			fatal("GUID must be a UUID string of length 32(dashless format) or 36(general format) or 38(windows format)");
	}
	
	if (guid_version != '4' || (guid_variation & 0x0C) != 0x08)
		fatal("GUID must be version 4 variation 1");
	
	//weird SmallMushy order
	int i = 8;
	char *a_guid = malloc(0x10);
	a_guid[0x3] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[0x2] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[0x1] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[0x0] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	guid_str += dash_len;
	a_guid[0x5] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[0x4] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	guid_str += dash_len;
	a_guid[0x7] = 0x40 + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[0x6] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	guid_str += dash_len;
	a_guid[i++] = (guid_variation << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	guid_str += dash_len;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	a_guid[i++] = (hexdigit(guid_str[0]) << 4) + hexdigit(guid_str[1]); guid_str += 2;
	
	return a_guid;
}

//note: it does modify f_args content (replace colon with null) and creates references to its particular parts
void parse_file_args(char **f_args, int f_count, char *os_attr, struct list_node **file)
{
	char *arg_p, *fname_p, *hash_p;
	struct list_node *this_file;
	struct a_file *file_data;
	int fname_len;
	bool is_pe;
	
	*file = NULL;
	
	while (f_count--)
	{
		arg_p = f_args[f_count];
		fname_p = arg_p;
		while (*arg_p != '\0' && *arg_p != ':') {
			++arg_p;
		}
		if (!*arg_p) {
			usage_and_exit();
		}
		fname_len = arg_p - fname_p;
		if (fname_len == 0) {
			fatal("file name can't be empty\n");
		}
		
		hash_p = ++arg_p;
		
		while (*arg_p != '\0' && *arg_p != ':') {
			++arg_p;
		}
		if (arg_p - hash_p != SHA1_STR_LEN) {
			fatal("unsupported hash, sha1 expected\n");
		}
		
		if (*arg_p)
		{
			if (strcmp(":PE", arg_p) != 0) //if not equals
				usage_and_exit();
			
			is_pe = true;
		}
		else
			is_pe = false;
		
		this_file = malloc(sizeof(struct list_node) + sizeof(struct a_file));
		if (this_file == NULL) {
			fatal(ERR_OOM);
		}
		this_file->data = this_file + 1;
		file_data = this_file->data;
		

		fname_p[fname_len] = '\0';
		
		file_data->sha1_str = hash_p;
		file_data->sha1_str[SHA1_STR_LEN] = '\0';
		for (int i = 0, j = 0; i < SHA1_BYTE_LEN; ++i, j += 2) {
			file_data->sha1_bytes[i] = (hexdigit(hash_p[j]) << 4) + hexdigit(hash_p[j + 1]);
		}
		
		file_data->name_attribute.data.name = "File";
		file_data->name_attribute.data.value = fname_p;
		file_data->name_attribute.encode_as_set = true;
		file_data->os_attribute.data.name = "OSAttr";
		file_data->os_attribute.data.value = os_attr;
		file_data->os_attribute.encode_as_set = true;
		
		file_data->is_pe = is_pe;
		
		if (file_data->is_pe) {
			file_data->guid = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
		} else {
			file_data->guid = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
		}
		
		this_file->next = *file;
		*file = this_file;
	}
}

#define FUNC_CREATE_HWID_NODE() {\
	/*create new struct and chain it with previouse
	//reverse order is based on observed cat files */ \
	*hwid = malloc(sizeof(struct list_node) + sizeof(struct an_attribute_data)); \
	if (*hwid == NULL) \
	{ \
		fatal(ERR_OOM); \
	} \
	(*hwid)->next = hwid_last; \
	hwid_last = *hwid; \
	hwid_last->data = hwid_last + 1; \
	hwid_data = hwid_last->data; \
	\
	/*create buffer, enough to store "HWID" + uint64 (4 + 20) */ \
	hwid_data->name = malloc(0x18); \
	if (hwid_data->name == NULL) \
	{ \
		fatal(ERR_OOM); \
	} \
	memcpy(hwid_data->name, "HWID", 4); \
	/*increase hwid number and put it to hwid name */ \
	++hwid_num; \
	sprintf(hwid_data->name + 4, "%d", hwid_num); \
	/*store current hwid begin position */ \
	hwid_data->value = hwid_begin; \
}

//note: it does modify hwids content (replace each comma, that comes 1st after hwid, with null) and creates references to its particular parts
int parse_hwids_arg(char *hwids, struct list_node **hwid)
{
	struct list_node *hwid_last = NULL;
	struct an_attribute_data *hwid_data;
	char *hwid_begin = hwids;
	int hwid_num = 0;
	
	while (*hwids)
	{
		if (*hwids == ',')
		{
			//check if delimiter is NOT immediately after another one (empty entries must be skipped, delimiter is not allowed in the value)
			if (hwids > hwid_begin)
			{
				FUNC_CREATE_HWID_NODE();
				
				//"cut" string to current hwid end
				*hwids = '\0';
			}
			//update current position AND move position of current hwid begin to it
			hwid_begin = ++hwids;
		}
		else
			++hwids;
	}
	
	//grab last entry, if any
	if (hwids > hwid_begin)
	{
		FUNC_CREATE_HWID_NODE();
	}
	
	//not inspect much file, but generally atleast one hwid is specified
	//if hwid-less cat possible - this restriction can be removed
	if (hwid_last == NULL)
		fatal("atleast one hardwareID required\n");
	
	return hwid_num;
}

int main(int argc, char **argv)
{
#ifdef IS_WINDOWS
	#ifdef _O_BINARY
	if (_setmode(_fileno(stdout), _O_BINARY) == -1)
	#endif
	{
		fatal("cannot set binary mode for stdout\noperation canceled due to translation(known \"corruption\" in text mode)\nhttps://stackoverflow.com/a/5537079");
	}
	
#endif /* IS_WINDOWS */
	
	
	struct pkcs7_toplevel s = { 0 };
	
	struct list_node *root_node = NULL;
	struct list_node *files = NULL;
	struct list_node *hwids = NULL;
	
	char *os_string = "7X64,8X64,_v100_X64";
	char *os_attr_string = "2:6.1,2:6.2,2:10.0";
	char *hardware_ids = NULL;
	char *gen_time = NULL;
	char *a_guid = NULL;
	char c;
	while ((c = getopt(argc, argv, "h:A:O:T:G:")) != -1) {
		switch (c) {
		case 'h':
			hardware_ids = optarg;
			break;
		case 'A':
			os_attr_string = optarg;
			break;
		case 'O':
			os_string = optarg;
			break;
		case 'T':
			gen_time = strdup(optarg); //strdup for avoid complications with freeing
			break;
		case 'G':
			a_guid = validate_GUID_str(optarg);
			break;
		default:
			usage_and_exit();
		}
	}
	
	if (argc <= optind || hardware_ids == NULL) {
		usage_and_exit();
	}
	
	if (gen_time) {
		if (strlen(gen_time) != 13 || gen_time[12] != 'Z')
			usage_and_exit();
	}
	else {
		gen_time = malloc(14);
		time_t t = time(NULL);
		strftime(gen_time, 14, "%y%m%d%H%M%SZ", gmtime(&t));
	}
	
	parse_hwids_arg(hardware_ids, &hwids);
	parse_file_args(argv + optind, argc - optind, os_attr_string, &files);
	
	s.data.cert_trust_list.catalog_list_element = malloc(sizeof(struct catalog_list_element));
	if (s.data.cert_trust_list.catalog_list_element == NULL) {
		fatal(ERR_OOM);
	}
	
	//generate pseudo guid if not provided
	if (a_guid == NULL)
		a_guid = generate_pseudo_GUID_bytes();
	
	s.data.an_int = 1;
	s.data.cert_trust_list.catalog_list_element->a_guid = a_guid;
	s.data.cert_trust_list.catalog_list_element->a_time = gen_time;
	s.data.cert_trust_list.catalog_list_element->hwids = hwids;
	s.data.cert_trust_list.catalog_list_element->files = files;
	s.data.cert_trust_list.catalog_list_element->os_info.data.name = "OS";
	s.data.cert_trust_list.catalog_list_element->os_info.data.value = os_string;
	s.data.cert_trust_list.catalog_list_element->os_info.encode_as_set = false;
	
	/* init OIDs cache, actual data will be computed on first access per OID */
	oids.signed_data_oid.string             = "1.2.840.113549.1.7.2";
	//{joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) hashAlgs(2) sha256(1)}
	oids.algo_oid.string                    = "2.16.840.1.101.3.4.2.1";
	oids.cert_trust_oid.string              = "1.3.6.1.4.1.311.10.1";
	oids.catalog_list_oid.string            = "1.3.6.1.4.1.311.12.1.1";
	oids.catalog_list_member_oid.string     = "1.3.6.1.4.1.311.12.1.2";
	oids.attribute_name_value_oid.string    = "1.3.6.1.4.1.311.12.2.1";
	oids.member_info_oid.string             = "1.3.6.1.4.1.311.12.2.2";
	oids.spc_oid.string                     = "1.3.6.1.4.1.311.2.1.4";
	oids.spc_image_data_oid.string          = "1.3.6.1.4.1.311.2.1.15";
	oids.spc_link_oid.string                = "1.3.6.1.4.1.311.2.1.25";
	//{iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2) sha1(26)}
	oids.spc_algo_oid.string                = "1.3.14.3.2.26";
	
	/* these references should be ok cuz both s and oids created on current stack, so they invalidates together */
	s.signed_data_oid = &oids.signed_data_oid;
	s.data.algo.algo_oid = &oids.algo_oid;
	s.data.cert_trust_list.cert_trust_oid = &oids.cert_trust_oid;
	s.data.cert_trust_list.catalog_list_element->catalog_list_oid = &oids.catalog_list_oid;
	s.data.cert_trust_list.catalog_list_element->catalog_list_member_oid = &oids.catalog_list_member_oid;
	
	//create root node, that will be used in create_binary_tree()
	root_node = calloc(1, sizeof(struct list_node) + sizeof(struct node_data));
	if (root_node == NULL)
	{
		fatal(ERR_OOM);
	}
	root_node->data = root_node + 1;
	datacache.node = root_node;
	
	
	/* generate binary DER */
	create_binary_tree(&s);
	
	/* free the memory allocated on the heap */
	datacache.node = root_node; //otherwise, all used nodes except the last one would not be freed
	free_allocated(&s);
	root_node = NULL; files = NULL;
	gen_time = NULL;
	a_guid = NULL;
	hwids = NULL;
	
	/* and write to stdout or so ... */
	fwrite(buffer, buflen, 1, stdout);
	free(buffer); buffer = NULL;

	return 0;
}
