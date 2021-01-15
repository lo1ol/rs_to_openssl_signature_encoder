/*
 * asn1.h: ASN.1 header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OPENSC_ASN1_H
#define _OPENSC_ASN1_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stdio.h"
#include "types.h"
#include "errors.h"

#define SC_PKCS15_PIN_MAGIC             0x31415926
#define SC_PKCS15_MAX_PINS              8
#define SC_PKCS15_MAX_LABEL_SIZE        255
#define SC_PKCS15_MAX_ID_SIZE           255
#define SC_PKCS15_MAX_ACCESS_RULES      8

struct sc_algorithm_id {
	unsigned int algorithm;
	struct sc_object_id oid;
	void *params;
};

struct sc_pbkdf2_params {
	u8 salt[16];
	size_t salt_len;
	int iterations;
	size_t key_length;
	struct sc_algorithm_id hash_alg;
};

struct sc_pbes2_params {
	struct sc_algorithm_id derivation_alg;
	struct sc_algorithm_id key_encr_alg;
};

typedef struct {
	/** the version number of this structure (0 for this version) */
	unsigned int ver;
	/** creates a mutex object */
	int (*create_mutex)(void **);
	/** locks a mutex object (blocks until the lock has been acquired) */
	int (*lock_mutex)(void *);
	/** unlocks a mutex object  */
	int (*unlock_mutex)(void *);
	/** destroys a mutex object */
	int (*destroy_mutex)(void *);
	/** returns unique identifier for the thread (can be NULL) */
	unsigned long (*thread_id)(void);
} sc_thread_context_t;

/* work around lack of inttypes.h support in broken Microsoft Visual Studio compilers */
#if defined(_MSC_VER)
#include <basetsd.h>
typedef UINT8   uint8_t;
typedef UINT16  uint16_t;
typedef ULONG32 uint32_t;
typedef UINT64  uint64_t;
typedef INT8    int8_t;
typedef INT16   int16_t;
typedef LONG32  int32_t;
typedef INT64   int64_t;
#else
#include <inttypes.h>   /* (u)int*_t */
#endif
#include <errno.h>
#include <sys/types.h>

/* bases on OpenSSL's version in e_os2.h  */
#if !defined(inline)
/* Be friend of both C90 and C99 compilers */
# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
   /* "inline" and "restrict" are keywords */
#  define simclist_inline  inline
# elif defined(__GNUC__) && __GNUC__>=2
#  define simclist_inline  __inline__
# elif defined(_MSC_VER)
#  define simclist_inline __inline
# else
#  define simclist_inline
# endif
#else    /* use what caller wants as inline  may be from config.h */
#   define simclist_inline  inline           /* inline */
#endif

/* bases on OpenSSL's version in e_os2.h  */
/* On MacOS  C++ is used for tokend */
#if !defined(restrict)
/* Be friend of both C90 and C99 compilers */
# if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
   /* "inline" and "restrict" are keywords */
#  define simclist_restrict restrict         /* restrict */
# elif defined(__GNUC__) && __GNUC__>=2
#  define simclist_restrict __restrict__
# elif defined(_MSC_VER)
#  define simclist_restrict __restrict
# else
#  define simclist_restrict
# endif
#else    /* use what caller wants as restrict may be from config.h */
#   define simclist_restrict  restrict
#endif


/**
 * Type representing list hashes.
 *
 * This is a signed integer value.
 */
typedef int32_t list_hash_t;

#ifdef SIMCLIST_DUMPRESTORE
typedef struct {
    uint16_t version;       /* dump version */
    int64_t timestamp;      /* when the list has been dumped, microseconds from UNIX epoch */
    uint32_t list_size;
    uint32_t list_numels;
    list_hash_t list_hash;       /* hash of the list when dumped, or 0 if invalid */
    uint32_t dumpsize;
    int consistent;         /* 1 if the dump is verified complete/consistent; 0 otherwise */
} list_dump_info_t;
#endif

/**
 * a comparator of elements.
 *
 * A comparator of elements is a function that:
 *      -# receives two references to elements a and b
 *      -# returns {<0, 0, >0} if (a > b), (a == b), (a < b) respectively
 *
 * It is responsibility of the function to handle possible NULL values.
 */
typedef int (*element_comparator)(const void *a, const void *b);

/**
 * a seeker of elements.
 *
 * An element seeker is a function that:
 *      -# receives a reference to an element el
 *      -# receives a reference to some indicator data
 *      -# returns non-0 if the element matches the indicator, 0 otherwise
 *
 * It is responsibility of the function to handle possible NULL values in any
 * argument.
 */
typedef int (*element_seeker)(const void *el, const void *indicator);

/**
 * an element length meter.
 *
 * An element meter is a function that:
 *      -# receives the reference to an element el
 *      -# returns its size in bytes
 *
 * It is responsibility of the function to handle possible NULL values.
 */
typedef size_t (*element_meter)(const void *el);

/**
 * a function computing the hash of elements.
 *
 * An hash computing function is a function that:
 *      -# receives the reference to an element el
 *      -# returns a hash value for el
 *
 * It is responsibility of the function to handle possible NULL values.
 */
typedef list_hash_t (*element_hash_computer)(const void *el);

/**
 * a function for serializing an element.
 *
 * A serializer function is one that gets a reference to an element,
 * and returns a reference to a buffer that contains its serialization
 * along with the length of this buffer.
 * It is responsibility of the function to handle possible NULL values,
 * returning a NULL buffer and a 0 buffer length.
 *
 * These functions have 3 goals:
 *  -# "freeze" and "flatten" the memory representation of the element
 *  -# provide a portable (wrt byte order, or type size) representation of the element, if the dump can be used on different sw/hw combinations
 *  -# possibly extract a compressed representation of the element
 *
 * @param el                reference to the element data
 * @param serialize_buffer  reference to fill with the length of the buffer
 * @return                  reference to the buffer with the serialized data
 */
typedef void *(*element_serializer)(const void *simclist_restrict el, uint32_t *simclist_restrict serialize_buffer);

/**
 * a function for un-serializing an element.
 *
 * An unserializer function accomplishes the inverse operation of the
 * serializer function.  An unserializer function is one that gets a
 * serialized representation of an element and turns it backe to the original
 * element. The serialized representation is passed as a reference to a buffer
 * with its data, and the function allocates and returns the buffer containing
 * the original element, and it sets the length of this buffer into the
 * integer passed by reference.
 *
 * @param data              reference to the buffer with the serialized representation of the element
 * @param data_len          reference to the location where to store the length of the data in the buffer returned
 * @return                  reference to a buffer with the original, unserialized representation of the element
 */
typedef void *(*element_unserializer)(const void *simclist_restrict data, uint32_t *simclist_restrict data_len);


struct list_attributes_s {
    /* user-set routine for comparing list elements */
    element_comparator comparator;
    /* user-set routing for seeking elements */
    element_seeker seeker;
    /* user-set routine for determining the length of an element */
    element_meter meter;
    int copy_data;
    /* user-set routine for computing the hash of an element */
    element_hash_computer hasher;
    /* user-set routine for serializing an element */
    element_serializer serializer;
    /* user-set routine for unserializing an element */
    element_unserializer unserializer;
};

typedef struct {
    struct list_entry_s *head_sentinel;
    struct list_entry_s *tail_sentinel;
    struct list_entry_s *mid;

    unsigned int numels;

    /* array of spare elements */
    struct list_entry_s **spareels;
    unsigned int spareelsnum;

#ifdef SIMCLIST_WITH_THREADS
    /* how many threads are currently running */
    unsigned int threadcount;
#endif

    /* service variables for list iteration */
    int iter_active;
    unsigned int iter_pos;
    struct list_entry_s *iter_curentry;

    /* list attributes */
    struct list_attributes_s attrs;
} list_t;

typedef struct _scconf_block scconf_block;

typedef struct _scconf_list {
	struct _scconf_list *next;
	char *data;
} scconf_list;

#define SCCONF_ITEM_TYPE_COMMENT	0	/* key = NULL, comment */
#define SCCONF_ITEM_TYPE_BLOCK		1	/* key = key, block */
#define SCCONF_ITEM_TYPE_VALUE		2	/* key = key, list */

typedef struct _scconf_item {
	struct _scconf_item *next;
	int type;
	char *key;
	union {
		char *comment;
		scconf_block *block;
		scconf_list *list;
	} value;
} scconf_item;

struct _scconf_block {
	scconf_block *parent;
	scconf_list *name;
	scconf_item *items;
};

typedef struct {
	char *filename;
	int debug;
	scconf_block *root;
	char *errmsg;
} scconf_context;

typedef struct sc_context {
	scconf_context *conf;
	scconf_block *conf_blocks[3];
	char *app_name;
	int debug;
	unsigned long flags;

	FILE *debug_file;
	char *debug_filename;
	char *preferred_language;

	list_t readers;

	struct sc_reader_driver *reader_driver;
	void *reader_drv_data;

	struct sc_card_driver *card_drivers[SC_MAX_CARD_DRIVERS];
	struct sc_card_driver *forced_driver;

	sc_thread_context_t	*thread_ctx;
	void *mutex;

	unsigned int magic;
} sc_context_t;

struct sc_pkcs15_der {
	u8 *		value;
	size_t		len;
};
typedef struct sc_pkcs15_der sc_pkcs15_der_t;

struct sc_pkcs15_u8 {
	u8 *		value;
	size_t		len;
};
typedef struct sc_pkcs15_u8 sc_pkcs15_u8_t;

struct sc_pkcs15_data {
	u8 *data;	/* DER encoded raw data object */
	size_t data_len;
};
typedef struct sc_pkcs15_data sc_pkcs15_data_t;

struct sc_pkcs15_id {
	u8 value[SC_PKCS15_MAX_ID_SIZE];
	size_t len;
};
typedef struct sc_pkcs15_id sc_pkcs15_id_t;

struct sc_pkcs15_accessrule {
	unsigned access_mode;
	struct sc_pkcs15_id auth_id;
};
typedef struct sc_pkcs15_accessrule sc_pkcs15_accessrule_t;

typedef struct sc_pkcs15_sec_env_info {
	int			se;
	struct sc_object_id	owner;
	struct sc_aid aid;
} sc_pkcs15_sec_env_info_t;

struct sc_pkcs15_object {
	unsigned int type;
	/* CommonObjectAttributes */
	char label[SC_PKCS15_MAX_LABEL_SIZE];	/* zero terminated */
	unsigned int flags;
	struct sc_pkcs15_id auth_id;

	int usage_counter;
	int user_consent;

	struct sc_pkcs15_accessrule access_rules[SC_PKCS15_MAX_ACCESS_RULES];

	/* Object type specific data */
	void *data;
	/* emulated object pointer */
	void *emulated;

	struct sc_pkcs15_df *df; /* can be NULL, if object is 'floating' */
	struct sc_pkcs15_object *next, *prev; /* used only internally */

	struct sc_pkcs15_der content;

	int session_object;	/* used internally. if nonzero, object is a session object. */
};
typedef struct sc_pkcs15_object sc_pkcs15_object_t;

struct sc_asn1_entry {
	const char *name;
	unsigned int type;
	unsigned int tag;
	unsigned int flags;
	void *parm;
	void *arg;
};

struct sc_asn1_pkcs15_object {
	struct sc_pkcs15_object *p15_obj;
	struct sc_asn1_entry *asn1_class_attr;
	struct sc_asn1_entry *asn1_subclass_attr;
	struct sc_asn1_entry *asn1_type_attr;
};

struct sc_asn1_pkcs15_algorithm_info {
	int id;
	struct sc_object_id oid;
	int (*decode)(struct sc_context *, void **, const u8 *, size_t, int);
	int (*encode)(struct sc_context *, void *, u8 **, size_t *, int);
	void (*free)(void *);
};


/* Utility functions */
void sc_format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg,
			  int set_present);
void sc_copy_asn1_entry(const struct sc_asn1_entry *src,
			struct sc_asn1_entry *dest);

/* DER tag and length parsing */
int sc_asn1_encode(struct sc_context *ctx, const struct sc_asn1_entry *asn1,
		   u8 **buf, size_t *bufsize);
int _sc_asn1_encode(struct sc_context *, const struct sc_asn1_entry *,
		   u8 **, size_t *, int);

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
		     unsigned int *tag_out, size_t *taglen);
const u8 *sc_asn1_find_tag(struct sc_context *ctx, const u8 * buf,
			   size_t buflen, unsigned int tag, size_t *taglen);
const u8 *sc_asn1_verify_tag(struct sc_context *ctx, const u8 * buf,
			     size_t buflen, unsigned int tag, size_t *taglen);
const u8 *sc_asn1_skip_tag(struct sc_context *ctx, const u8 ** buf,
			   size_t *buflen, unsigned int tag, size_t *taglen);

/* DER encoding */

/* Argument 'ptr' is set to the location of the next possible ASN.1 object.
 * If NULL, no action on 'ptr' is performed.
 * If out is NULL or outlen is zero, the length that would be written is returned.
 * If data is NULL, the data field will not be written. This is helpful for constructed structures. */
int sc_asn1_put_tag(unsigned int tag, const u8 * data, size_t datalen, u8 * out, size_t outlen, u8 ** ptr);


/* ASN.1 object decoding functions */
int sc_asn1_utf8string_to_ascii(const u8 * buf, size_t buflen,
				u8 * outbuf, size_t outlen);
/* non-inverting version */
int sc_asn1_encode_object_id(u8 **buf, size_t *buflen,
				const struct sc_object_id *id);

/* algorithm encoding/decoding */
int sc_asn1_encode_algorithm_id(struct sc_context *,
				u8 **, size_t *,
				const struct sc_algorithm_id *, int);
void sc_asn1_clear_algorithm_id(struct sc_algorithm_id *);


/* ASN.1 object encoding functions */
int sc_asn1_write_element(sc_context_t *ctx, unsigned int tag,
		const u8 * data, size_t datalen, u8 ** out, size_t * outlen);

int sc_asn1_sig_value_rs_to_sequence(unsigned char *in, size_t inlen,
                unsigned char **buf, size_t *buflen);
int sc_asn1_sig_value_sequence_to_rs(struct sc_context *ctx,
		const unsigned char *in, size_t inlen,
                unsigned char *buf, size_t buflen);

/* long form tags use these */
/* Same as  SC_ASN1_TAG_* shifted left by 24 bits  */
#define SC_ASN1_CLASS_MASK		0xC0000000
#define SC_ASN1_UNI			0x00000000 /* Universal */
#define SC_ASN1_APP			0x40000000 /* Application */
#define SC_ASN1_CTX			0x80000000 /* Context */
#define SC_ASN1_PRV			0xC0000000 /* Private */
#define SC_ASN1_CONS			0x20000000

#define SC_ASN1_CLASS_CONS		0xE0000000 /* CLASS and CONS */
#define SC_ASN1_TAG_MASK		0x00FFFFFF
#define SC_ASN1_TAGNUM_SIZE		3

#define SC_ASN1_PRESENT			0x00000001
#define SC_ASN1_OPTIONAL		0x00000002
#define SC_ASN1_ALLOC			0x00000004
#define SC_ASN1_UNSIGNED		0x00000008
#define SC_ASN1_EMPTY_ALLOWED           0x00000010

#define SC_ASN1_BOOLEAN                 1
#define SC_ASN1_INTEGER                 2
#define SC_ASN1_BIT_STRING              3
#define SC_ASN1_BIT_STRING_NI           128
#define SC_ASN1_OCTET_STRING            4
#define SC_ASN1_NULL                    5
#define SC_ASN1_OBJECT                  6
#define SC_ASN1_ENUMERATED              10
#define SC_ASN1_UTF8STRING              12
#define SC_ASN1_SEQUENCE                16
#define SC_ASN1_SET                     17
#define SC_ASN1_PRINTABLESTRING         19
#define SC_ASN1_UTCTIME                 23
#define SC_ASN1_GENERALIZEDTIME         24

/* internal structures */
#define SC_ASN1_STRUCT			129
#define SC_ASN1_CHOICE			130
#define SC_ASN1_BIT_FIELD		131	/* bit string as integer */

/* 'complex' structures */
#define SC_ASN1_PATH			256
#define SC_ASN1_PKCS15_ID		257
#define SC_ASN1_PKCS15_OBJECT		258
#define SC_ASN1_ALGORITHM_ID		259
#define SC_ASN1_SE_INFO			260

/* use callback function */
#define SC_ASN1_CALLBACK		384

/* use with short one byte tags */
#define SC_ASN1_TAG_CLASS		0xC0
#define SC_ASN1_TAG_UNIVERSAL		0x00
#define SC_ASN1_TAG_APPLICATION		0x40
#define SC_ASN1_TAG_CONTEXT		0x80
#define SC_ASN1_TAG_PRIVATE		0xC0

#define SC_ASN1_TAG_CONSTRUCTED		0x20
#define SC_ASN1_TAG_PRIMITIVE		0x1F
#define SC_ASN1_TAG_CLASS_CONS		0xE0

#define SC_ASN1_TAG_EOC			0
#define SC_ASN1_TAG_BOOLEAN		1
#define SC_ASN1_TAG_INTEGER		2
#define SC_ASN1_TAG_BIT_STRING		3
#define SC_ASN1_TAG_OCTET_STRING	4
#define SC_ASN1_TAG_NULL		5
#define SC_ASN1_TAG_OBJECT		6
#define SC_ASN1_TAG_OBJECT_DESCRIPTOR	7
#define SC_ASN1_TAG_EXTERNAL		8
#define SC_ASN1_TAG_REAL		9
#define SC_ASN1_TAG_ENUMERATED		10
#define SC_ASN1_TAG_UTF8STRING		12
#define SC_ASN1_TAG_SEQUENCE		16
#define SC_ASN1_TAG_SET			17
#define SC_ASN1_TAG_NUMERICSTRING	18
#define SC_ASN1_TAG_PRINTABLESTRING	19
#define SC_ASN1_TAG_T61STRING		20
#define SC_ASN1_TAG_TELETEXSTRING	20
#define SC_ASN1_TAG_VIDEOTEXSTRING	21
#define SC_ASN1_TAG_IA5STRING		22
#define SC_ASN1_TAG_UTCTIME		23
#define SC_ASN1_TAG_GENERALIZEDTIME	24
#define SC_ASN1_TAG_GRAPHICSTRING	25
#define SC_ASN1_TAG_ISO64STRING		26
#define SC_ASN1_TAG_VISIBLESTRING	26
#define SC_ASN1_TAG_GENERALSTRING	27
#define SC_ASN1_TAG_UNIVERSALSTRING	28
#define SC_ASN1_TAG_BMPSTRING		30
#define SC_ASN1_TAG_ESCAPE_MARKER	31

#ifdef __cplusplus
}
#endif

#endif
