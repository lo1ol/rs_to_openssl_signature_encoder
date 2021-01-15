/*
 * asn1.c: ASN.1 decoding functions (DER)
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "asn1.h"
#include "internal.h"
#include "errors.h"
#include "log.h"

#if defined(_WIN32) && !(defined(__MINGW32__) && defined (__MINGW_PRINTF_FORMAT))
#define SC_FORMAT_LEN_SIZE_T "I"
#define SC_FORMAT_LEN_PTRDIFF_T "I"
#else
/* hope SUSv3 ones work */
#define SC_FORMAT_LEN_SIZE_T "z"
#define SC_FORMAT_LEN_PTRDIFF_T "t"
#endif

int sc_valid_oid(const struct sc_object_id *oid)
{
	int ii;

	if (!oid)
		return 0;
	if (oid->value[0] == -1 || oid->value[1] == -1)
		return 0;
	if (oid->value[0] > 2 || oid->value[1] > 39)
		return 0;
	for (ii=0;ii<SC_MAX_OBJECT_ID_OCTETS;ii++)
		if (oid->value[ii])
			break;
	if (ii==SC_MAX_OBJECT_ID_OCTETS)
		return 0;
	return 1;
}

int sc_compare_oid(const struct sc_object_id *oid1, const struct sc_object_id *oid2)
{
	int i;

	if (oid1 == NULL || oid2 == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	for (i = 0; i < SC_MAX_OBJECT_ID_OCTETS; i++)   {
		if (oid1->value[i] != oid2->value[i])
			return 0;
		if (oid1->value[i] == -1)
			break;
	}

	return 1;
}

static struct sc_asn1_pkcs15_algorithm_info algorithm_table[] = {
#ifdef SC_ALGORITHM_SHA1
	/* hmacWithSHA1 */
	{ SC_ALGORITHM_SHA1, {{ 1, 2, 840, 113549, 2, 7, -1}}, NULL, NULL, NULL },
	{ SC_ALGORITHM_SHA1, {{ 1, 3, 6, 1, 5, 5, 8, 1, 2, -1}}, NULL, NULL, NULL },
	/* SHA1 */
	{ SC_ALGORITHM_SHA1, {{ 1, 3, 14, 3, 2, 26, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_MD5
	{ SC_ALGORITHM_MD5, {{ 1, 2, 840, 113549, 2, 5, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_DSA
	{ SC_ALGORITHM_DSA, {{ 1, 2, 840, 10040, 4, 3, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RSA /* really rsaEncryption */
	{ SC_ALGORITHM_RSA, {{ 1, 2, 840, 113549, 1, 1, 1, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_DH
	{ SC_ALGORITHM_DH, {{ 1, 2, 840, 10046, 2, 1, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RC2_WRAP /* from CMS */
	{ SC_ALGORITHM_RC2_WRAP,  {{ 1, 2, 840, 113549, 1, 9, 16, 3, 7, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RC2 /* CBC mode */
	{ SC_ALGORITHM_RC2, {{ 1, 2, 840, 113549, 3, 2, -1}},
			asn1_decode_rc2_params,
			asn1_encode_rc2_params },
#endif
#ifdef SC_ALGORITHM_DES /* CBC mode */
	{ SC_ALGORITHM_DES, {{ 1, 3, 14, 3, 2, 7, -1}},
			asn1_decode_des_params,
			asn1_encode_des_params,
			free },
#endif
#ifdef SC_ALGORITHM_3DES_WRAP /* from CMS */
	{ SC_ALGORITHM_3DES_WRAP, {{ 1, 2, 840, 113549, 1, 9, 16, 3, 6, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_3DES /* EDE CBC mode */
	{ SC_ALGORITHM_3DES, {{ 1, 2, 840, 113549, 3, 7, -1}},
			asn1_decode_des_params,
			asn1_encode_des_params,
			free },
#endif
#ifdef SC_ALGORITHM_GOST /* EDE CBC mode */
	{ SC_ALGORITHM_GOST, {{ 1, 2, 4434, 66565, 3, 7, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_GOSTR3410
	{ SC_ALGORITHM_GOSTR3410, {{ 1, 2, 643, 2, 2, 19, -1}},
			asn1_decode_gostr3410_params,
			asn1_encode_gostr3410_params,
			NULL },
#endif
/* We do not support PBES1 because the encryption is weak */
#ifdef SC_ALGORITHM_PBKDF2
	{ SC_ALGORITHM_PBKDF2, {{ 1, 2, 840, 113549, 1, 5, 12, -1}},
			asn1_decode_pbkdf2_params,
			asn1_encode_pbkdf2_params,
			free },
#endif
#ifdef SC_ALGORITHM_PBES2
	{ SC_ALGORITHM_PBES2, {{ 1, 2, 840, 113549, 1, 5, 13, -1}},
			asn1_decode_pbes2_params,
			asn1_encode_pbes2_params,
			asn1_free_pbes2_params },
#endif

#ifdef SC_ALGORITHM_EC
	{ SC_ALGORITHM_EC, {{ 1, 2, 840, 10045, 2, 1, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
/* TODO: -DEE Not clear if we need the next five or not */
#ifdef SC_ALGORITHM_ECDSA_SHA1
	/* Note RFC 3279 says no ecParameters */
	{ SC_ALGORITHM_ECDSA_SHA1, {{ 1, 2, 840, 10045, 4, 1, -1}}, NULL, NULL, NULL},
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA224
/* These next 4 are defined in RFC 5758 */
	{ SC_ALGORITHM_ECDSA_SHA224, {{ 1, 2, 840, 10045, 4, 3, 1, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA256
	{ SC_ALGORITHM_ECDSA_SHA256, {{ 1, 2, 840, 10045, 4, 3, 2, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA384
	{ SC_ALGORITHM_ECDSA_SHA384, {{ 1, 2, 840, 10045, 4, 3, 3, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA512
	{ SC_ALGORITHM_ECDSA_SHA512, {{ 1, 2, 840, 10045, 4, 3, 4, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
	{ -1, {{ -1 }}, NULL, NULL, NULL }
};


static struct sc_asn1_pkcs15_algorithm_info *
sc_asn1_get_algorithm_info(const struct sc_algorithm_id *id)
{
	struct sc_asn1_pkcs15_algorithm_info *aip = NULL;

	for (aip = algorithm_table; aip->id >= 0; aip++)   {
		if ((int) id->algorithm < 0 && sc_compare_oid(&id->oid, &aip->oid))
			return aip;

		if (aip->id == (int)id->algorithm)
			return aip;
	}

	return NULL;
}

static const struct sc_asn1_entry c_asn1_alg_id[3] = {
	{ "algorithm",  SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL },
	{ "nullParam",  SC_ASN1_NULL, SC_ASN1_TAG_NULL, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int
sc_asn1_encode_algorithm_id(struct sc_context *ctx, u8 **buf, size_t *len,
			    const struct sc_algorithm_id *id,
			    int depth)
{
	struct sc_asn1_pkcs15_algorithm_info *alg_info;
	struct sc_algorithm_id temp_id;
	struct sc_asn1_entry asn1_alg_id[3];
	u8 *obj = NULL;
	size_t obj_len = 0;
	int r;
	u8 *tmp;

	LOG_FUNC_CALLED(ctx);
	alg_info = sc_asn1_get_algorithm_info(id);
	if (alg_info == NULL) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Set the oid if not yet given */
	if (!sc_valid_oid(&id->oid)) {
		temp_id = *id;
		temp_id.oid = alg_info->oid;
		id = &temp_id;
	}

	sc_copy_asn1_entry(c_asn1_alg_id, asn1_alg_id);
	sc_format_asn1_entry(asn1_alg_id + 0, (void *) &id->oid, NULL, 1);

	/* no parameters, write NULL tag */
	if (!id->params || !alg_info->encode)
		asn1_alg_id[1].flags |= SC_ASN1_PRESENT;

	r = _sc_asn1_encode(ctx, asn1_alg_id, buf, len, depth + 1);
	LOG_TEST_RET(ctx, r, "ASN.1 encode of algorithm failed");

	/* Encode any parameters */
	if (id->params && alg_info->encode) {
		r = alg_info->encode(ctx, id->params, &obj, &obj_len, depth+1);
		if (r < 0) {
			if (obj)
				free(obj);
			LOG_FUNC_RETURN(ctx, r);
		}
	}

	if (obj_len) {
		tmp = (u8 *) realloc(*buf, *len + obj_len);
		if (!tmp) {
			free(*buf);
			*buf = NULL;
			free(obj);
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		*buf = tmp;
		memcpy(*buf + *len, obj, obj_len);
		*len += obj_len;
		free(obj);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

void
sc_asn1_clear_algorithm_id(struct sc_algorithm_id *id)
{
	struct sc_asn1_pkcs15_algorithm_info *aip;

	if (id->params && (aip = sc_asn1_get_algorithm_info(id)) && aip->free) {
		aip->free(id->params);
		id->params = NULL;
	}
}

static int asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		       u8 **ptr, size_t *size, int depth);
static int asn1_write_element(sc_context_t *ctx, unsigned int tag,
		const u8 * data, size_t datalen, u8 ** out, size_t * outlen);

static const char *tag2str(unsigned int tag)
{
	static const char *tags[] = {
		"EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING",	/* 0-4 */
		"NULL", "OBJECT IDENTIFIER", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL",	/* 5-9 */
		"ENUMERATED", "Universal 11", "UTF8String", "Universal 13",	/* 10-13 */
		"Universal 14", "Universal 15", "SEQUENCE", "SET",	/* 15-17 */
		"NumericString", "PrintableString", "T61String",	/* 18-20 */
		"VideotexString", "IA5String", "UTCTIME", "GENERALIZEDTIME",	/* 21-24 */
		"GraphicString", "VisibleString", "GeneralString",	/* 25-27 */
		"UniversalString", "Universal 29", "BMPString"	/* 28-30 */
	};

	if (tag > 30)
		return "(unknown)";
	return tags[tag];
}

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
		     unsigned int *tag_out, size_t *taglen)
{
	const u8 *p = *buf;
	size_t left = buflen, len;
	unsigned int cla, tag, i;

	*buf = NULL;

	if (left == 0 || !p)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	if (*p == 0xff || *p == 0) {
		/* end of data reached */
		*taglen = 0;
		*tag_out = SC_ASN1_TAG_EOC;
		return SC_SUCCESS;
	}

	/* parse tag byte(s)
	 * Resulted tag is presented by integer that has not to be
	 * confused with the 'tag number' part of ASN.1 tag.
	 */
	cla = (*p & SC_ASN1_TAG_CLASS) | (*p & SC_ASN1_TAG_CONSTRUCTED);
	tag = *p & SC_ASN1_TAG_PRIMITIVE;
	p++;
	left--;
	if (tag == SC_ASN1_TAG_PRIMITIVE) {
		/* high tag number */
		size_t n = SC_ASN1_TAGNUM_SIZE - 1;
		/* search the last tag octet */
		do {
			if (left == 0 || n == 0)
				/* either an invalid tag or it doesn't fit in
				 * unsigned int */
				return SC_ERROR_INVALID_ASN1_OBJECT;
			tag <<= 8;
			tag |= *p;
			p++;
			left--;
			n--;
		} while (tag & 0x80);
	}

	/* parse length byte(s) */
	if (left == 0)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	len = *p;
	p++;
	left--;
	if (len & 0x80) {
		len &= 0x7f;
		unsigned int a = 0;
		if (len > sizeof a || len > left)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		for (i = 0; i < len; i++) {
			a <<= 8;
			a |= *p;
			p++;
			left--;
		}
		len = a;
	}

	*cla_out = cla;
	*tag_out = tag;
	*taglen = len;
	*buf = p;

	if (len > left)
		return SC_ERROR_ASN1_END_OF_CONTENTS;

	return SC_SUCCESS;
}

void sc_format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg,
			  int set_present)
{
	entry->parm = parm;
	entry->arg  = arg;
	if (set_present)
		entry->flags |= SC_ASN1_PRESENT;
}

void sc_copy_asn1_entry(const struct sc_asn1_entry *src,
			struct sc_asn1_entry *dest)
{
	while (src->name != NULL) {
		*dest = *src;
		dest++;
		src++;
	}
	dest->name = NULL;
}


const u8 *sc_asn1_find_tag(sc_context_t *ctx, const u8 * buf,
	size_t buflen, unsigned int tag_in, size_t *taglen_in)
{
	size_t left = buflen, taglen;
	const u8 *p = buf;

	*taglen_in = 0;
	while (left >= 2) {
		unsigned int cla = 0, tag, mask = 0xff00;

		buf = p;
		/* read a tag */
		if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) != SC_SUCCESS
				|| p == NULL)
			return NULL;

		left -= (p - buf);
		/* we need to shift the class byte to the leftmost
		 * byte of the tag */
		while ((tag & mask) != 0) {
			cla  <<= 8;
			mask <<= 8;
		}
		/* compare the read tag with the given tag */
		if ((tag | cla) == tag_in) {
			/* we have a match => return length and value part */
			if (taglen > left)
				return NULL;
			*taglen_in = taglen;
			return p;
		}
		/* otherwise continue reading tags */
		left -= taglen;
		p += taglen;
	}
	return NULL;
}

const u8 *sc_asn1_skip_tag(sc_context_t *ctx, const u8 ** buf, size_t *buflen,
			   unsigned int tag_in, size_t *taglen_out)
{
	const u8 *p = *buf;
	size_t len = *buflen, taglen;
	unsigned int cla = 0, tag;

	if (sc_asn1_read_tag((const u8 **) &p, len, &cla, &tag, &taglen) != SC_SUCCESS
			|| p == NULL)
		return NULL;
	switch (cla & 0xC0) {
	case SC_ASN1_TAG_UNIVERSAL:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_UNI)
			return NULL;
		break;
	case SC_ASN1_TAG_APPLICATION:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_APP)
			return NULL;
		break;
	case SC_ASN1_TAG_CONTEXT:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_CTX)
			return NULL;
		break;
	case SC_ASN1_TAG_PRIVATE:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_PRV)
			return NULL;
		break;
	}
	if (cla & SC_ASN1_TAG_CONSTRUCTED) {
		if ((tag_in & SC_ASN1_CONS) == 0)
			return NULL;
	} else
		if (tag_in & SC_ASN1_CONS)
			return NULL;
	if ((tag_in & SC_ASN1_TAG_MASK) != tag)
		return NULL;
	len -= (p - *buf);	/* header size */
	if (taglen > len) {
		return NULL;
	}
	*buflen -= (p - *buf) + taglen;
	*buf = p + taglen;	/* point to next tag */
	*taglen_out = taglen;
	return p;
}

const u8 *sc_asn1_verify_tag(sc_context_t *ctx, const u8 * buf, size_t buflen,
			     unsigned int tag_in, size_t *taglen_out)
{
	return sc_asn1_skip_tag(ctx, &buf, &buflen, tag_in, taglen_out);
}

static int encode_bit_string(const u8 * inbuf, size_t bits_left, u8 **outbuf,
			     size_t *outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out;
	size_t bytes;
	int skipped = 0;

	bytes = (bits_left + 7)/8 + 1;
	*outbuf = out = malloc(bytes);
	if (out == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	*outlen = bytes;
	out += 1;
	while (bits_left) {
		int i, bits_to_go = 8;

		*out = 0;
		if (bits_left < 8) {
			bits_to_go = bits_left;
			skipped = 8 - bits_left;
		}
		if (invert) {
			for (i = 0; i < bits_to_go; i++)
				*out |= ((*in >> i) & 1) << (7 - i);
		} else {
			*out = *in;
			if (bits_left < 8)
				return SC_ERROR_NOT_SUPPORTED; /* FIXME */
		}
		bits_left -= bits_to_go;
		out++, in++;
	}
	out = *outbuf;
	out[0] = skipped;
	return 0;
}

static int encode_bit_field(const u8 *inbuf, size_t inlen,
			    u8 **outbuf, size_t *outlen)
{
	u8		data[sizeof(unsigned int)];
	unsigned int	field = 0;
	size_t		i, bits;

	if (inlen != sizeof(data))
		return SC_ERROR_BUFFER_TOO_SMALL;

	/* count the bits */
	memcpy(&field, inbuf, inlen);
	for (bits = 0; field; bits++)
		field >>= 1;

	memcpy(&field, inbuf, inlen);
	for (i = 0; i < bits; i += 8)
		data[i/8] = field >> i;

	return encode_bit_string(data, bits, outbuf, outlen, 1);
}

static int asn1_encode_integer(int in, u8 ** obj, size_t * objsize)
{
	int i = sizeof(in) * 8, skip_zero, skip_sign;
	u8 *p, b;

	if (in < 0)
	{
		skip_sign = 1;
		skip_zero= 0;
	}
	else
	{
		skip_sign = 0;
		skip_zero= 1;
	}
	*obj = p = malloc(sizeof(in)+1);
	if (*obj == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	do {
		i -= 8;
		b = in >> i;
		if (skip_sign)
		{
			if (b != 0xff)
				skip_sign = 0;
			if (b & 0x80)
			{
				*p = b;
				if (0xff == b)
					continue;
			}
			else
			{
				p++;
				skip_sign = 0;
			}
		}
		if (b == 0 && skip_zero)
			continue;
		if (skip_zero) {
			skip_zero = 0;
			/* prepend 0x00 if MSb is 1 and integer positive */
			if ((b & 0x80) != 0 && in > 0)
				*p++ = 0;
		}
		*p++ = b;
	} while (i > 0);
	if (skip_sign)
		p++;
	*objsize = p - *obj;
	if (*objsize == 0) {
		*objsize = 1;
		(*obj)[0] = 0;
	}
	return 0;
}

int
sc_asn1_encode_object_id(u8 **buf, size_t *buflen, const struct sc_object_id *id)
{
	u8 temp[SC_MAX_OBJECT_ID_OCTETS*5], *p = temp;
	int	i;

	if (!buflen || !id)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* an OID must have at least two components */
	if (id->value[0] == -1 || id->value[1] == -1)
		return SC_ERROR_INVALID_ARGUMENTS;

	for (i = 0; i < SC_MAX_OBJECT_ID_OCTETS; i++) {
		unsigned int k, shift;

		if (id->value[i] == -1)
			break;

		k = id->value[i];
		switch (i) {
		case 0:
			if (k > 2)
				return SC_ERROR_INVALID_ARGUMENTS;
			*p = k * 40;
			break;
		case 1:
			if (k > 39 && id->value[0] < 2) {
				return SC_ERROR_INVALID_ARGUMENTS;
			}
			/* We can encode larger IDs to multiple bytes
			 * similarly as the following IDs */
			k += *p;
			/* fall through */
		default:
			shift = 28;
			while (shift && (k >> shift) == 0)
				shift -= 7;
			while (shift) {
				*p++ = 0x80 | ((k >> shift) & 0x7f);
				shift -= 7;
			}
			*p++ = k & 0x7F;
			break;
		}
	}

	*buflen = p - temp;

	if (buf)   {
		*buf = malloc(*buflen);
		if (!*buf)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(*buf, temp, *buflen);
	}
	return 0;
}

/*
 * This assumes the tag is already encoded
 */
int sc_asn1_put_tag(unsigned int tag, const u8 * data, size_t datalen, u8 * out, size_t outlen, u8 **ptr)
{
	size_t c = 0;
	size_t tag_len;
	size_t ii;
	u8 *p = out;
	u8 tag_char[4] = {0, 0, 0, 0};

	/* Check tag */
	if (tag == 0 || tag > 0xFFFFFFFF) {
		/* A tag of 0x00 is not valid and at most 4-byte tag names are supported. */
		return SC_ERROR_INVALID_DATA;
	}
	for (tag_len = 0; tag; tag >>= 8) {
		/* Note: tag char will be reversed order. */
		tag_char[tag_len++] = tag & 0xFF;
	}

	if (tag_len > 1)   {
		if ((tag_char[tag_len - 1] & SC_ASN1_TAG_PRIMITIVE) != SC_ASN1_TAG_ESCAPE_MARKER) {
			/* First byte is not escape marker. */
			return SC_ERROR_INVALID_DATA;
		}
		for (ii = 1; ii < tag_len - 1; ii++) {
			if ((tag_char[ii] & 0x80) != 0x80) {
				/* MS bit is not 'one'. */
				return SC_ERROR_INVALID_DATA;
			}
		}
		if ((tag_char[0] & 0x80) != 0x00) {
			/* MS bit of the last byte is not 'zero'. */
			return SC_ERROR_INVALID_DATA;
		}
	}

	/* Calculate the number of additional bytes necessary to encode the length. */
	/* c+1 is the size of the length field. */
	if (datalen > 127) {
		c = 1;
		while (datalen >> (c << 3))
			c++;
	}
	if (outlen == 0 || out == NULL) {
		/* Caller only asks for the length that would be written. */
		return tag_len + (c+1) + datalen;
	}
	/* We will write the tag, so check the length. */
	if (outlen < tag_len + (c+1) + datalen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	for (ii=0;ii<tag_len;ii++)
		*p++ = tag_char[tag_len - ii - 1];

	if (c > 0) {
		*p++ = 0x80 | c;
		while (c--)
			*p++ = (datalen >> (c << 3)) & 0xFF;
	}
	else {
		*p++ = datalen & 0x7F;
	}
	if(data && datalen > 0) {
		memcpy(p, data, datalen);
		p += datalen;
	}
	if (ptr != NULL)
		*ptr = p;
	return 0;
}

int sc_asn1_write_element(sc_context_t *ctx, unsigned int tag,
	const u8 * data, size_t datalen, u8 ** out, size_t * outlen)
{
	return asn1_write_element(ctx, tag, data, datalen, out, outlen);
}

static int asn1_write_element(sc_context_t *ctx, unsigned int tag,
	const u8 * data, size_t datalen, u8 ** out, size_t * outlen)
{
	unsigned char t;
	unsigned char *buf, *p;
	int c = 0;
	unsigned short_tag;
	unsigned char tag_char[3] = {0, 0, 0};
	size_t tag_len, ii;

	short_tag = tag & SC_ASN1_TAG_MASK;
	for (tag_len = 0; short_tag >> (8 * tag_len); tag_len++)
		tag_char[tag_len] = (short_tag >> (8 * tag_len)) & 0xFF;
	if (!tag_len)
		tag_len = 1;

	if (tag_len > 1)   {
		if ((tag_char[tag_len - 1] & SC_ASN1_TAG_PRIMITIVE) != SC_ASN1_TAG_ESCAPE_MARKER)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "First byte of the long tag is not 'escape marker'");

		for (ii = 1; ii < tag_len - 1; ii++)
			if (!(tag_char[ii] & 0x80))
				SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "MS bit expected to be 'one'");

		if (tag_char[0] & 0x80)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "MS bit of the last byte expected to be 'zero'");
	}

	t = tag_char[tag_len - 1] & 0x1F;

	switch (tag & SC_ASN1_CLASS_MASK) {
	case SC_ASN1_UNI:
		break;
	case SC_ASN1_APP:
		t |= SC_ASN1_TAG_APPLICATION;
		break;
	case SC_ASN1_CTX:
		t |= SC_ASN1_TAG_CONTEXT;
		break;
	case SC_ASN1_PRV:
		t |= SC_ASN1_TAG_PRIVATE;
		break;
	}
	if (tag & SC_ASN1_CONS)
		t |= SC_ASN1_TAG_CONSTRUCTED;
	if (datalen > 127) {
		c = 1;
		while (datalen >> (c << 3))
			c++;
	}

	*outlen = tag_len + 1 + c + datalen;
	buf = malloc(*outlen);
	if (buf == NULL)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_OUT_OF_MEMORY);

	*out = p = buf;
	*p++ = t;
	for (ii=1;ii<tag_len;ii++)
		*p++ = tag_char[tag_len - ii - 1];

	if (c) {
		*p++ = 0x80 | c;
		while (c--)
			*p++ = (datalen >> (c << 3)) & 0xFF;
	}
	else   {
		*p++ = datalen & 0x7F;
	}
	if (datalen && data) {
		memcpy(p, data, datalen);
	}

	return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_path_ext[3] = {
	{ "aid",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x0F, 0, NULL, NULL },
	{ "path", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_path[5] = {
	{ "path",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "index",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "length", SC_ASN1_INTEGER, SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
/* For some multi-applications PKCS#15 card the ODF records can hold the references to
 * the xDF files and objects placed elsewhere then under the application DF of the ODF itself.
 * In such a case the 'path' ASN1 data includes also the ID of the target application (AID).
 * This path extension do not make a part of PKCS#15 standard.
 */
	{ "pathExtended", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_encode_path(sc_context_t *ctx, const sc_path_t *path,
			    u8 **buf, size_t *bufsize, int depth, unsigned int parent_flags)
{
	int r;
 	struct sc_asn1_entry asn1_path[5];
	sc_path_t tpath = *path;

	sc_copy_asn1_entry(c_asn1_path, asn1_path);
	sc_format_asn1_entry(asn1_path + 0, (void *) &tpath.value, (void *) &tpath.len, 1);

	asn1_path[0].flags |= parent_flags;
	if (path->count > 0) {
		sc_format_asn1_entry(asn1_path + 1, (void *) &tpath.index, NULL, 1);
		sc_format_asn1_entry(asn1_path + 2, (void *) &tpath.count, NULL, 1);
	}
	r = asn1_encode(ctx, asn1_path, buf, bufsize, depth + 1);
	return r;
}


static const struct sc_asn1_entry c_asn1_se[2] = {
	{ "seInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_se_info[4] = {
	{ "se",   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "owner",SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "aid",  SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_encode_se_info(sc_context_t *ctx,
		struct sc_pkcs15_sec_env_info **se, size_t se_num,
		unsigned char **buf, size_t *bufsize, int depth)
{
	unsigned char *ptr = NULL, *out = NULL, *p;
	size_t ptrlen = 0, outlen = 0, idx;
	int ret;

	for (idx=0; idx < se_num; idx++)   {
		struct sc_asn1_entry asn1_se[2];
		struct sc_asn1_entry asn1_se_info[4];

		sc_copy_asn1_entry(c_asn1_se, asn1_se);
		sc_copy_asn1_entry(c_asn1_se_info, asn1_se_info);

		sc_format_asn1_entry(asn1_se_info + 0, &se[idx]->se, NULL, 1);
		if (sc_valid_oid(&se[idx]->owner))
			sc_format_asn1_entry(asn1_se_info + 1, &se[idx]->owner, NULL, 1);
		if (se[idx]->aid.len)
			sc_format_asn1_entry(asn1_se_info + 2, &se[idx]->aid.value, &se[idx]->aid.len, 1);
		sc_format_asn1_entry(asn1_se + 0, asn1_se_info, NULL, 1);

		ret = sc_asn1_encode(ctx, asn1_se, &ptr, &ptrlen);
		if (ret != SC_SUCCESS)
			goto err;

		if (!ptrlen)
			continue;
		p = (unsigned char *) realloc(out, outlen + ptrlen);
		if (!p)   {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		out = p;
		memcpy(out + outlen, ptr, ptrlen);
		outlen += ptrlen;
		free(ptr);
		ptr = NULL;
		ptrlen = 0;
	}

	*buf = out;
	*bufsize = outlen;
	ret = SC_SUCCESS;
err:
	if (ret != SC_SUCCESS && out != NULL)
		free(out);
	return ret;
}

/* TODO: According to specification type of 'SecurityCondition' is 'CHOICE'.
 *       Do it at least for SC_ASN1_PKCS15_ID(authId), SC_ASN1_STRUCT(authReference) and NULL(always). */
static const struct sc_asn1_entry c_asn1_access_control_rule[3] = {
	{ "accessMode", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "securityCondition", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * in src/libopensc/pkcs15.h SC_PKCS15_MAX_ACCESS_RULES  defined as 8
 */
static const struct sc_asn1_entry c_asn1_access_control_rules[SC_PKCS15_MAX_ACCESS_RULES + 1] = {
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_com_obj_attr[6] = {
	{ "label", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "flags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "authId", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "userConsent", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRules", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_p15_obj[5] = {
	{ "commonObjectAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "classAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "subClassAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "typeAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_encode_p15_object(sc_context_t *ctx, const struct sc_asn1_pkcs15_object *obj,
				  u8 **buf, size_t *bufsize, int depth)
{
	struct sc_pkcs15_object p15_obj = *obj->p15_obj;
	struct sc_asn1_entry    asn1_c_attr[6], asn1_p15_obj[5];
	struct sc_asn1_entry asn1_ac_rules[SC_PKCS15_MAX_ACCESS_RULES + 1], asn1_ac_rule[SC_PKCS15_MAX_ACCESS_RULES][3];
	size_t label_len = strlen(p15_obj.label);
	size_t flags_len;
	size_t access_mode_len;
	int r, ii;

	if (p15_obj.access_rules[0].access_mode)   {
		for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)   {
			sc_copy_asn1_entry(c_asn1_access_control_rule, asn1_ac_rule[ii]);
			if (p15_obj.access_rules[ii].auth_id.len == 0)   {
				asn1_ac_rule[ii][1].type = SC_ASN1_NULL;
				asn1_ac_rule[ii][1].tag = SC_ASN1_TAG_NULL;
			}
		}
		sc_copy_asn1_entry(c_asn1_access_control_rules, asn1_ac_rules);
	}

	sc_copy_asn1_entry(c_asn1_com_obj_attr, asn1_c_attr);
	sc_copy_asn1_entry(c_asn1_p15_obj, asn1_p15_obj);
	if (label_len != 0)
		sc_format_asn1_entry(asn1_c_attr + 0, (void *) p15_obj.label, &label_len, 1);
	if (p15_obj.flags) {
		flags_len = sizeof(p15_obj.flags);
		sc_format_asn1_entry(asn1_c_attr + 1, (void *) &p15_obj.flags, &flags_len, 1);
	}
	if (p15_obj.auth_id.len)
		sc_format_asn1_entry(asn1_c_attr + 2, (void *) &p15_obj.auth_id, NULL, 1);
	if (p15_obj.user_consent)
		sc_format_asn1_entry(asn1_c_attr + 3, (void *) &p15_obj.user_consent, NULL, 1);

	if (p15_obj.access_rules[0].access_mode)   {
		for (ii=0; p15_obj.access_rules[ii].access_mode; ii++)   {
			access_mode_len = sizeof(p15_obj.access_rules[ii].access_mode);
			sc_format_asn1_entry(asn1_ac_rule[ii] + 0, (void *) &p15_obj.access_rules[ii].access_mode, &access_mode_len, 1);
			sc_format_asn1_entry(asn1_ac_rule[ii] + 1, (void *) &p15_obj.access_rules[ii].auth_id, NULL, 1);
			sc_format_asn1_entry(asn1_ac_rules + ii, asn1_ac_rule[ii], NULL, 1);
		}
		sc_format_asn1_entry(asn1_c_attr + 4, asn1_ac_rules, NULL, 1);
	}

	sc_format_asn1_entry(asn1_p15_obj + 0, asn1_c_attr, NULL, 1);
	sc_format_asn1_entry(asn1_p15_obj + 1, obj->asn1_class_attr, NULL, 1);
	if (obj->asn1_subclass_attr != NULL && obj->asn1_subclass_attr->name)
		sc_format_asn1_entry(asn1_p15_obj + 2, obj->asn1_subclass_attr, NULL, 1);
	sc_format_asn1_entry(asn1_p15_obj + 3, obj->asn1_type_attr, NULL, 1);

	r = asn1_encode(ctx, asn1_p15_obj, buf, bufsize, depth + 1);
	return r;
}

static int asn1_encode_entry(sc_context_t *ctx, const struct sc_asn1_entry *entry,
			     u8 **obj, size_t *objlen, int depth)
{
	void *parm = entry->parm;
	int (*callback_func)(sc_context_t *nctx, void *arg, u8 **nobj,
			     size_t *nobjlen, int ndepth);
	const size_t *len = (const size_t *) entry->arg;
	int r = 0;
	u8 * buf = NULL;
	size_t buflen = 0;

	callback_func = parm;

	if (!(entry->flags & SC_ASN1_PRESENT))
		goto no_object;

	if (entry->type == SC_ASN1_CHOICE) {
		const struct sc_asn1_entry *list, *choice = NULL;

		list = (const struct sc_asn1_entry *) parm;
		while (list->name != NULL) {
			if (list->flags & SC_ASN1_PRESENT) {
				if (choice) {
					return SC_ERROR_INVALID_ASN1_OBJECT;
				}
				choice = list;
			}
			list++;
		}
		if (choice == NULL)
			goto no_object;
		return asn1_encode_entry(ctx, choice, obj, objlen, depth + 1);
	}

	if (entry->type != SC_ASN1_NULL && parm == NULL) {
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	switch (entry->type) {
	case SC_ASN1_STRUCT:
		r = asn1_encode(ctx, (const struct sc_asn1_entry *) parm, &buf,
				&buflen, depth + 1);
		break;
	case SC_ASN1_NULL:
		buf = NULL;
		buflen = 0;
		break;
	case SC_ASN1_BOOLEAN:
		buf = malloc(1);
		if (buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		buf[0] = *((int *) parm) ? 0xFF : 0;
		buflen = 1;
		break;
	case SC_ASN1_INTEGER:
	case SC_ASN1_ENUMERATED:
		r = asn1_encode_integer(*((int *) entry->parm), &buf, &buflen);
		break;
	case SC_ASN1_BIT_STRING_NI:
	case SC_ASN1_BIT_STRING:
		if (len != NULL) {
			if (entry->type == SC_ASN1_BIT_STRING)
				r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 1);
			else
				r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 0);
		} else {
			r = SC_ERROR_INVALID_ARGUMENTS;
		}
		break;
	case SC_ASN1_BIT_FIELD:
		if (len != NULL) {
			r = encode_bit_field((const u8 *) parm, *len, &buf, &buflen);
		} else {
			r = SC_ERROR_INVALID_ARGUMENTS;
		}
		break;
	case SC_ASN1_PRINTABLESTRING:
	case SC_ASN1_OCTET_STRING:
	case SC_ASN1_UTF8STRING:
		if (len != NULL) {
			buf = malloc(*len + 1);
			if (buf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				break;
			}
			buflen = 0;
			/* If the integer is supposed to be unsigned, insert
			 * a padding byte if the MSB is one */
			if ((entry->flags & SC_ASN1_UNSIGNED)
					&& (((u8 *) parm)[0] & 0x80)) {
				buf[buflen++] = 0x00;
			}
			memcpy(buf + buflen, parm, *len);
			buflen += *len;
		} else {
			r = SC_ERROR_INVALID_ARGUMENTS;
		}
		break;
	case SC_ASN1_GENERALIZEDTIME:
		if (len != NULL) {
			buf = malloc(*len);
			if (buf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				break;
			}
			memcpy(buf, parm, *len);
			buflen = *len;
		} else {
			r = SC_ERROR_INVALID_ARGUMENTS;
		}
		break;
	case SC_ASN1_OBJECT:
		r = sc_asn1_encode_object_id(&buf, &buflen, (struct sc_object_id *) parm);
		break;
	case SC_ASN1_PATH:
		r = asn1_encode_path(ctx, (const sc_path_t *) parm, &buf, &buflen, depth, entry->flags);
		break;
	case SC_ASN1_PKCS15_ID:
		{
			const struct sc_pkcs15_id *id = (const struct sc_pkcs15_id *) parm;

			buf = malloc(id->len);
			if (buf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				break;
			}
			memcpy(buf, id->value, id->len);
			buflen = id->len;
		}
		break;
	case SC_ASN1_PKCS15_OBJECT:
		r = asn1_encode_p15_object(ctx, (const struct sc_asn1_pkcs15_object *) parm, &buf, &buflen, depth);
		break;
	case SC_ASN1_ALGORITHM_ID:
		r = sc_asn1_encode_algorithm_id(ctx, &buf, &buflen, (const struct sc_algorithm_id *) parm, depth);
		break;
	case SC_ASN1_SE_INFO:
		if (!len)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		r = asn1_encode_se_info(ctx, (struct sc_pkcs15_sec_env_info **)parm, *len, &buf, &buflen, depth);
		break;
	case SC_ASN1_CALLBACK:
		r = callback_func(ctx, entry->arg, &buf, &buflen, depth);
		break;
	default:
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (r) {
		if (buf)
			free(buf);
		return r;
	}

	/* Treatment of OPTIONAL elements:
	 *  -	if the encoding has 0 length, and the element is OPTIONAL,
	 *	we don't write anything (unless it's an ASN1 NULL and the
	 *      SC_ASN1_PRESENT flag is set).
	 *  -	if the encoding has 0 length, but the element is non-OPTIONAL,
	 *	constructed, we write a empty element (e.g. a SEQUENCE of
	 *      length 0). In case of an ASN1 NULL just write the tag and
	 *      length (i.e. 0x05,0x00).
	 *  -	any other empty objects are considered bogus
	 */
no_object:
	if (!buflen && entry->flags & SC_ASN1_OPTIONAL && !(entry->flags & SC_ASN1_PRESENT)) {
		/* This happens when we try to encode e.g. the
		 * subClassAttributes, which may be empty */
		*obj = NULL;
		*objlen = 0;
		r = 0;
	} else if (!buflen && (entry->flags & SC_ASN1_EMPTY_ALLOWED)) {
		*obj = NULL;
		*objlen = 0;
		r = asn1_write_element(ctx, entry->tag, buf, buflen, obj, objlen);
	} else if (buflen || entry->type == SC_ASN1_NULL || entry->tag & SC_ASN1_CONS) {
		r = asn1_write_element(ctx, entry->tag, buf, buflen, obj, objlen);
	} else if (!(entry->flags & SC_ASN1_PRESENT)) {
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	} else {
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (buf)
		free(buf);
	return r;
}

static int asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		      u8 **ptr, size_t *size, int depth)
{
	int r, idx = 0;
	u8 *obj = NULL, *buf = NULL, *tmp;
	size_t total = 0, objsize;

	for (idx = 0; asn1[idx].name != NULL; idx++) {
		r = asn1_encode_entry(ctx, &asn1[idx], &obj, &objsize, depth);
		if (r) {
			if (obj)
				free(obj);
			if (buf)
				free(buf);
			return r;
		}
		/* in case of an empty (optional) element continue with
		 * the next asn1 element */
		if (!objsize)
			continue;
		tmp = (u8 *) realloc(buf, total + objsize);
		if (!tmp) {
			if (obj)
				free(obj);
			if (buf)
				free(buf);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		buf = tmp;
		memcpy(buf + total, obj, objsize);
		free(obj);
		obj = NULL;
		total += objsize;
	}
	*ptr = buf;
	*size = total;
	return 0;
}

int sc_asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		   u8 **ptr, size_t *size)
{
	return asn1_encode(ctx, asn1, ptr, size, 0);
}

int _sc_asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		    u8 **ptr, size_t *size, int depth)
{
	return asn1_encode(ctx, asn1, ptr, size, depth);
}

int
sc_der_copy(sc_pkcs15_der_t *dst, const sc_pkcs15_der_t *src)
{
	if (!dst)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(dst, 0, sizeof(*dst));
	if (src->len) {
		dst->value = malloc(src->len);
		if (!dst->value)
			return SC_ERROR_OUT_OF_MEMORY;
		dst->len = src->len;
		memcpy(dst->value, src->value, src->len);
	}
	return SC_SUCCESS;
}

int
sc_encode_oid (struct sc_context *ctx, struct sc_object_id *id,
		unsigned char **out, size_t *size)
{
	static const struct sc_asn1_entry c_asn1_object_id[2] = {
		{ "oid", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_object_id[2];
	int rv;

	sc_copy_asn1_entry(c_asn1_object_id, asn1_object_id);
	sc_format_asn1_entry(asn1_object_id + 0, id, NULL, 1);

	rv = _sc_asn1_encode(ctx, asn1_object_id, out, size, 1);
	LOG_TEST_RET(ctx, rv, "Cannot encode object ID");

	return SC_SUCCESS;
}


#define C_ASN1_SIG_VALUE_SIZE 2
static struct sc_asn1_entry c_asn1_sig_value[C_ASN1_SIG_VALUE_SIZE] = {
		{ "ECDSA-Sig-Value", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE 3
static struct sc_asn1_entry c_asn1_sig_value_coefficients[C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE] = {
		{ "r", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ "s", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};


int
sc_asn1_sig_value_rs_to_sequence(unsigned char *in, size_t inlen,
		unsigned char **buf, size_t *buflen)
{
	sc_context_t* ctx;
	struct sc_asn1_entry asn1_sig_value[C_ASN1_SIG_VALUE_SIZE];
	struct sc_asn1_entry asn1_sig_value_coefficients[C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE];
	unsigned char *r = in, *s = in + inlen/2;
	size_t r_len = inlen/2, s_len = inlen/2;
	int rv;

	LOG_FUNC_CALLED(ctx);

	/* R/S are filled up with zeroes, we do not want that in sequence format */
	while(r_len > 1 && *r == 0x00) {
		r++;
		r_len--;
	}
	while(s_len > 1 && *s == 0x00) {
		s++;
		s_len--;
	}

	sc_copy_asn1_entry(c_asn1_sig_value, asn1_sig_value);
	sc_format_asn1_entry(asn1_sig_value + 0, asn1_sig_value_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_sig_value_coefficients, asn1_sig_value_coefficients);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 0, r, &r_len, 1);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 1, s, &s_len, 1);

	rv = sc_asn1_encode(ctx, asn1_sig_value, buf, buflen);
	LOG_TEST_RET(ctx, rv, "ASN.1 encoding ECDSA-SIg-Value failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
