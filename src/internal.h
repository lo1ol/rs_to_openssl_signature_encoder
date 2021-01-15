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

#ifndef _INTERNAL_H
#define _INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "asn1.h"

#include "stdio.h"
#include "types.h"

#define SC_PKCS15_PIN_MAGIC             0x31415926
#define SC_PKCS15_MAX_PINS              8
#define SC_PKCS15_MAX_LABEL_SIZE        255
#define SC_PKCS15_MAX_ID_SIZE           255
#define SC_PKCS15_MAX_ACCESS_RULES      8

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


#ifdef __cplusplus
}
#endif

#endif
