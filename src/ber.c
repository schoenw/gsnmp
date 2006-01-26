/*
 * GNET-SNMP -- glib-based SNMP library
 *
 * Copyright (c) 2003 Juergen Schoenwaelder
 * Copyright (c) 1998 Gregory McLean & Jochen Friedrich
 * Copyright (c) 1990 Dirk Wisse
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

/*
 * MT safe
 */

#include "ber.h"

struct _GNetSnmpBer
{
    guchar    *pointer;		/* octet just encoded or to be decoded */
    guchar    *begin;		/* first octet                         */
    guchar    *end;		/* octet after last octet              */
};


GQuark
gnet_snmp_ber_error_quark(void)
{
    static GQuark quark = 0;
    if (quark == 0) {
	quark = g_quark_from_static_string("gnet-snmp-ber-error-quark");
    }
    return quark;
}


/**
 * gnet_snmp_ber_enc_new:
 * &buf: the address of the buffer to encode into.
 * &buf_len: the length of the buffer which will be filled.
 *
 * Initializes a #GNetSnmpBer buffer for encoding.
 */

GNetSnmpBer *
gnet_snmp_ber_enc_new(guchar *buf, gsize buf_len)
{
    GNetSnmpBer *asn1;

    asn1 = g_new(GNetSnmpBer, 1);
    asn1->begin = buf;
    asn1->end = buf + buf_len;
    asn1->pointer = asn1->end;
    return asn1;
}

/**
 * gnet_snmp_ber_dec_new:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &buf: the address of the buffer to decode.
 * &buf_len: the length of the buffer which will be decoded.
 *
 * Initializes a #GNetSnmpBer buffer for decoding.
 */

GNetSnmpBer*
gnet_snmp_ber_dec_new(guchar *buf, gsize buf_len)
{
    GNetSnmpBer *asn1;

    asn1 = g_new(GNetSnmpBer, 1);
    asn1->begin = buf;
    asn1->end = buf + buf_len;
    asn1->pointer = asn1->begin;
    return asn1;
}

/**
 * gnet_snmp_ber_enc_delete:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &buf: the pointer to store the address of the encoded bytes.
 * &len: the pointer to store the length of the encoded bytes.
 *
 * Delete a #GNetSnmpBer encoding buffer and returns the address
 * and length of the encoded bytes.
 */

void 
gnet_snmp_ber_enc_delete(GNetSnmpBer *asn1, guchar **buf, gsize *len)
{
    if (buf) *buf = asn1->pointer;
    if (len) *len = asn1->end - asn1->pointer;
    g_free(asn1);
}

/**
 * gnet_snmp_ber_dec_delete:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &buf: the pointer to store the address of the decoded bytes.
 * &len: the pointer to store the length of the decoded bytes.
 *
 * Delete a #GNetSnmpBer decoding buffer and returns the address
 * and length of the decoded bytes.
 */

void 
gnet_snmp_ber_dec_delete(GNetSnmpBer *asn1, guchar **buf, gsize *len)
{
    if (buf) *buf = asn1->pointer;
    if (len) *len = asn1->end - asn1->pointer;
    g_free(asn1);
}


/**
 * enc_octet:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @ch: the octet to encode.
 * @error: the error object used to report errors.
 * 
 * Encodes an octet if there is still buffer space to encode.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
enc_octet(GNetSnmpBer *asn1, guchar ch, GError **error)
{
    if (asn1->pointer <= asn1->begin) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_FULL,
			"BER encoding buffer overflow"); 
	}
        return FALSE;
    }
    *--(asn1->pointer) = ch;
    return TRUE;
}

/**
 * dec_octet:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @ch: the pointer used to store the decoded octet.
 * @error: the error object used to report errors.
 *
 * Decodes an octet if there is still buffer space to decode.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
dec_octet(GNetSnmpBer *asn1, guchar *ch, GError **error)
{
    if (asn1->pointer >= asn1->end) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_EMPTY,
			"BER encoding buffer underflow"); 
	}
        return FALSE;
    }
    *ch = *(asn1->pointer)++;
    return TRUE;
}

/**
 * enc_tag:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @tag: the tag to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a tag value.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
enc_tag(GNetSnmpBer *asn1, guint tag, GError **error)
{
    guchar ch;

    ch = (guchar) (tag & 0x7F);
    tag >>= 7;
    if (!enc_octet(asn1, ch, error)) {
        return FALSE;
    }
    while (tag > 0) {
        ch = (guchar) (tag | 0x80);
        tag >>= 7;
        if (!enc_octet(asn1, ch, error)) {
            return FALSE;
	}
    }
    return TRUE;
}

/**
 * dec_tag:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @tag: the pointer used to store the decoded tag value.
 * @error: the error object used to report errors.
 *
 * Decodes a tag value.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
dec_tag(GNetSnmpBer *asn1, guint *tag, GError **error)
{
    guchar ch;

    *tag = 0;
    do {
        if (!dec_octet(asn1, &ch, error)) {
            return FALSE;
	}
        *tag <<= 7;
        *tag |= ch & 0x7F;
    }
    while ((ch & 0x80) == 0x80);
    return TRUE;
}

/**
 * enc_id:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @cls: the ASN.1 class value.
 * @con: the ASN.1 constructed value.
 * @tag: the ASN.1 tag value.
 * @error: the error object used to report errors.
 *
 * Encodes an identifier.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
enc_id(GNetSnmpBer *asn1, guint cls, guint con, guint tag, GError **error)
{
    guint ch;

    if (tag >= 0x1F) {
        if (!enc_tag(asn1, tag, error)) {
            return FALSE;
	}
        tag = 0x1F;
    }
    ch = (guchar) ((cls << 6) | (con << 5) | (tag));
    if (!enc_octet(asn1, ch, error)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * dec_id:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @cls: the pointer used to store the ASN.1 class value.
 * @con: the pointer used to store the ASN.1 constructed value.
 * @tag: the pointer used to store the ASN.1 tag value.
 * @error: the error object used to report errors.
 *
 * Decodes an identifier.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
dec_id(GNetSnmpBer *asn1, guint *cls, guint *con, guint *tag, GError **error)
{
    guchar ch;

    if (!dec_octet(asn1, &ch, error)) {
        return FALSE;
    }
    *cls = (ch & 0xC0) >> 6;
    *con = (ch & 0x20) >> 5;
    *tag = (ch & 0x1F);
    if (*tag == 0x1F) {
        if (!dec_tag(asn1, tag, error)) {
            return FALSE;
	}
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_length:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @def: flag indicating (in)definite encoding.
 * @len: the length to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a definite or indefinite length.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_length(GNetSnmpBer *asn1, guint def, gsize len,
			 GError **error)
{
    guchar ch, cnt;

    g_assert(asn1);
    
    if (!def) {
        ch = 0x80;
    } else {
        if (len < 0x80) {
            ch = (guchar) len;
	} else {
            cnt = 0;
            while (len > 0) {
                ch = (guchar) len;
                len >>= 8;
                if (!enc_octet(asn1, ch, error)) {
		    return FALSE;
		}
                cnt++;
            }
            ch = (guchar) (cnt | 0x80);
        }
    }
    if (!enc_octet(asn1, ch, error)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_length:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @def: the pointer to store a flag indicating (in)definite encoding.
 * @len: the pointer to store the decoded length.
 * @error: the error object used to report errors.
 *
 * Decodes a definite or indefinite length.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_length(GNetSnmpBer *asn1, guint *def, gsize *len,
			 GError **error)
{
    guchar ch, cnt;
    
    g_assert(asn1);
    
    if (!dec_octet(asn1, &ch, error)) {
        return FALSE;
    }
    if (ch == 0x80) {
        *def = 0;
    } else {
        *def = 1;
        if (ch < 0x80) {
            *len = ch;
	} else {
            cnt = (guchar) (ch & 0x7F);
            *len = 0;
            while (cnt > 0) {
                if (!dec_octet(asn1, &ch, error)) {
                    return FALSE;
		}
                *len <<= 8;
                *len |= ch;
                cnt--;
            }
        }
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_header:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding or NULL is indefinite.
 * @cls: the ASN.1 tag class.
 * @con: the primitve/constructed flag.
 * @tag: the ASN.1 tag value.
 * @error: the error object used to report errors.
 *
 * Encodes an ASN1/BER header.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_header(GNetSnmpBer *asn1, guchar *eoc,
			 guint cls, guint con, guint tag,
			 GError **error)
{
    guint def, len;
    
    g_assert(asn1);
    
    if (eoc == 0) {
        def = 0;
        len = 0;
    } else {
        def = 1;
        len = eoc - asn1->pointer;
    }
    if (!gnet_snmp_ber_enc_length(asn1, def, len, error)) {
        return FALSE;
    }
    if (!enc_id(asn1, cls, con, tag, error)) {
        return FALSE;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_header:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to store the end of encoding or NULL is indefinite.
 * @cls: the pointer to store ASN.1 tag class.
 * @con: the pointer to store the primitve/constructed flag.
 * @tag: the pointer to store the ASN.1 tag value.
 * @error: the error object used to report errors.
 *
 * Decodes an ASN1/BER header.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_header(GNetSnmpBer *asn1, guchar **eoc,
			 guint *cls, guint *con, guint *tag,
			 GError **error)
{
    guint def;
    gsize len;

    g_assert(asn1);
    
    if (!dec_id(asn1, cls, con, tag, error)) {
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_length(asn1, &def, &len, error)) {
        return FALSE;
    }
    if (def)
        *eoc = asn1->pointer + len;
    else
        *eoc = 0;
    return TRUE;
}

/**
 * gnet_snmp_ber_is_eoc:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 *
 * Checks if decoding is at end of contents.
 *
 * Returns: a gboolean indicating whether we have reached the end of
 * contents.
 */

gboolean 
gnet_snmp_ber_is_eoc(GNetSnmpBer *asn1, guchar *eoc)
{
    g_assert(asn1);
    
    if (eoc == 0) {
	return (asn1->pointer [0] == 0x00 && asn1->pointer [1] == 0x00);
    } else {
	return (asn1->pointer >= eoc);
    }
}

/**
 * gnet_snmp_ber_enc_eoc:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer used to store the end of encoding pointer.
 * @error: the error object used to report errors.
 *
 * If eoc is 0 it encodes an ASN1 end of contents (0x00 0x00), so it
 * produces an indefinite length encoding. If eoc points to a
 * character pointer, eoc is filled with the pointer to the last
 * encoded octet. This pointer can be used in the next
 * asn1_header_encode to determine the length of the encoding. This
 * produces a definite length encoding.
 *
 * Returns: a gboolean indicating success.
 */

gboolean 
gnet_snmp_ber_enc_eoc(GNetSnmpBer *asn1, guchar **eoc, GError **error)
{
    g_assert(asn1);
    
    if (eoc == 0) {
	if (!enc_octet(asn1, 0x00, error)) {
	    return FALSE;
	}
	if (!enc_octet(asn1, 0x00, error)) {
	    return FALSE;
	}
    } else {
	*eoc = asn1->pointer;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_eoc:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @error: the error object used to report errors.
 *
 * If eoc is 0 it decodes an ASN1 end of contents (0x00 0x00), so it
 * has to be an indefinite length encoding. If eoc is a character
 * pointer, it probably was filled by asn1_header_decode, and should
 * point to the octet after the last of the encoding. It is checked if
 * this pointer points to the octet to be decoded. This only takes
 * place in decoding a definite length encoding.
 *
 * Returns: a gboolean indicating success.
 */

gboolean 
gnet_snmp_ber_dec_eoc(GNetSnmpBer *asn1, guchar *eoc, GError **error)
{
    guchar ch;
    
    g_assert(asn1);
    
    if (eoc == 0) {
	if (!dec_octet(asn1, &ch, error)) {
	    return FALSE;
	}
	if (ch != 0x00) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_EOC_MISMATCH,
			    "BER EOC mismatch"); 
	    }
	    return FALSE;
	}
	if (!dec_octet(asn1, &ch, error)) {
	    return FALSE;
	}
	if (ch != 0x00) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_EOC_MISMATCH,
			    "BER EOC mismatch"); 
	    }
	    return FALSE;
	}
    } else {
	if (asn1->pointer != eoc) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_LENGTH_MISMATCH,
			    "BER length mismatch"); 
	    }
	    return FALSE;
	}
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_null:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @error: the error object used to report errors.
 *
 * Encodes an ASN.1 NULL value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_null(GNetSnmpBer *asn1, guchar **eoc, GError **error)
{
    g_assert(asn1);
    
    *eoc = asn1->pointer;
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_null:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @error: the error object used to report errors.
 *
 * Decodes an ASN.1 NULL value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_null(GNetSnmpBer *asn1, guchar *eoc, GError **error)
{
    g_assert(asn1);
    
    asn1->pointer = eoc;
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_gint32:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @value: the gint32 value to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a gint32 value as an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_gint32(GNetSnmpBer *asn1, guchar **eoc,
			 const gint32 value, GError **error)
{
    guchar ch, sign;
    int    lim;
    gint32 val = value;
    
    g_assert(asn1);
    
    *eoc = asn1->pointer;
    if (val < 0) {
        lim  = -1;
        sign = 0x80;
    } else {
        lim  = 0;
        sign = 0x00;
    }
    do {
        ch = (guchar) val;
        val >>= 8;
        if (!enc_octet(asn1, ch, error)) {
            return FALSE;
	}
    } while ((val != lim) || (guchar) (ch & 0x80) != sign);
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_gint32:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @value: the pointer used to store the gint32 value.
 * @error: the error object used to report errors.
 *
 * Decodes a gint32 value from an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_gint32(GNetSnmpBer *asn1, guchar *eoc,
			 gint32 *value, GError **error)
{
    guchar ch;
    guint  len;
    
    g_assert(asn1);
    
    if (!dec_octet(asn1, &ch, error))
        return FALSE;
    *value = (gchar) ch;
    len = 1;
    while (asn1->pointer < eoc) {
        if (++len > sizeof (gint32)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER gint32 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(asn1, &ch, error))
            return FALSE;
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_gint64:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @value: the gint64 value to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a gint64 value as an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean
gnet_snmp_ber_enc_gint64(GNetSnmpBer *asn1, guchar **eoc,
			 const gint64 value, GError **error)
{
    guchar ch, sign;
    glong  lim;
    gint64 val = value;
    
    g_assert(asn1);
    
    *eoc = asn1->pointer;
    if (val < 0) {
        lim  = -1;
        sign = 0x80;
    } else {
        lim  = 0;
        sign = 0x00;
    }
    do {
        ch = (guchar) val;
        val >>= 8;
        if (!enc_octet(asn1, ch, error)) {
            return FALSE;
	}
    } while ((val != lim) || (guchar) (ch & 0x80) != sign);
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_gint64:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @value: the pointer used to store the gint64 value.
 * @error: the error object used to report errors.
 *
 * Decodes a gint64 value from an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_gint64(GNetSnmpBer *asn1, guchar *eoc,
			 gint64 *value, GError **error)
{
    guchar ch;
    guint  len;

    g_assert(asn1);
    
    if (!dec_octet(asn1, &ch, error)) {
        return FALSE;
    }
    *value = (gchar) ch;
    len = 1;
    while (asn1->pointer < eoc) {
	if (++len > sizeof (gint64)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER gint64 value too big"); 
	    }
	    return FALSE;
	}
	if (!dec_octet(asn1, &ch, error)) {
	    return FALSE;
	}
	*value <<= 8;
	*value |= ch;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_guint32:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @value: the guint32 value to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a guint32 value as an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_guint32(GNetSnmpBer *asn1, guchar **eoc,
			  const guint32 value, GError **error)
{
    guchar ch;
    guint32 val = value;
    
    g_assert(asn1);
    
    *eoc = asn1->pointer;
    do {
	ch = (guchar) val;
	val >>= 8;
	if (!enc_octet(asn1, ch, error)) {
	    return FALSE;
	}
    } while ((val != 0) || (ch & 0x80) != 0x00);
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_guint32:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @value: the pointer used to store the guint32 value.
 * @error: the error object used to report errors.
 *
 * Decodes a guint32 value from an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_guint32(GNetSnmpBer *asn1, guchar *eoc,
			  guint32 *value, GError **error)
{
    guchar ch;
    guint  len;
    
    g_assert(asn1);
    
    if (!dec_octet(asn1, &ch, error)) {
        return FALSE;
    }
    *value = ch;
    len = (ch == 0) ? 0 : 1;
    while (asn1->pointer < eoc) {
        if (++len > sizeof (guint32)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER guint32 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(asn1, &ch, error)) {
            return FALSE;
	}
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_guint64:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @value: the guint64 value to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a guint64 value as an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_guint64(GNetSnmpBer *asn1, guchar **eoc,
			  const guint64 value, GError **error)
{
    guchar ch;
    guint64 val = value;

    g_assert(asn1);
    
    *eoc = asn1->pointer;
    do {
        ch = (guchar) val;
        val >>= 8;
        if (!enc_octet(asn1, ch, error)) {
            return FALSE;
	}
    }
    while ((val != 0) || (ch & 0x80) != 0x00);
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_guint64:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @value: the pointer used to store the guint64 value.
 * @error: the error object used to report errors.
 *
 * Decodes a guint64 value from an ASN.1 INTEGER value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_guint64(GNetSnmpBer *asn1, guchar *eoc,
			  guint64 *value, GError **error)
{
    guchar ch;
    guint  len;

    g_assert(asn1);
    
    if (!dec_octet(asn1, &ch, error)) {
        return FALSE;
    }
    *value = ch;
    len = (ch == 0) ? 0 : 1;
    while (asn1->pointer < eoc) {
        if (++len > sizeof (guint64)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER guint64 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(asn1, &ch, error)) {
            return FALSE;
	}
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_octets:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @octets: the pointer to the octets to encode.
 * @len: the number of octets to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a buffer of octets (bytes) as an ASN.1 OCTET STRING value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_octets(GNetSnmpBer *asn1, guchar **eoc,
			 const guchar *octets, const gsize len, GError **error)
{
    const guchar *ptr;
    gint i;

    g_assert(asn1);
    
    *eoc = asn1->pointer;
    ptr = octets + len;

    for (i = 0; i < len; i++) {
	if (!enc_octet(asn1, *--ptr, error))
	    return FALSE;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_octets:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @octets: pointer to a dynamically allocated buffer holding the value.
 * @len: the pointer used to store the number of octets.
 * @error: the error object used to report errors.
 *
 * Decodes a buffer of octets (bytes) from an ASN.1 OCTET STRING value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_octets(GNetSnmpBer *asn1, guchar *eoc,
			 guchar **octets, gsize *len, GError **error)
{
    guchar *ptr;
    
    g_assert(asn1);
    
    *octets = NULL;
    *len = 0;
    *octets = g_new(guchar, eoc - asn1->pointer + 1);
    ptr = *octets;
    while (asn1->pointer < eoc) {
	if (!dec_octet(asn1, (guchar *)ptr++, error)) {
	    g_free(*octets);
	    *octets = NULL;
	    return FALSE;
	}
	(*len)++;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_oid:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the pointer to the end of encoding pointer.
 * @oid: the sub-identifier vector to encode.
 * @len: the number of sub-identifier to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a sub-identifier vector as an ASN.1 OBJECT IDENTIFIER value.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
enc_subid(GNetSnmpBer *asn1, guint32 subid, GError **error)
{
    guchar ch;
    
    g_assert(asn1);
    
    ch = (guchar) (subid & 0x7F);
    subid >>= 7;
    if (!enc_octet(asn1, ch, error)) {
	return FALSE;
    }
    while (subid > 0) {
	ch = (guchar) (subid | 0x80);
	subid >>= 7;
	if (!enc_octet(asn1, ch, error)) {
	    return FALSE;
	}
    }
    return TRUE;
}

gboolean 
gnet_snmp_ber_enc_oid(GNetSnmpBer *asn1, guchar **eoc,
		      const guint32 *oid, const gsize len, GError **error)
{
    gulong subid;
    guint l = len;
    
    g_assert(asn1);
    
    *eoc = asn1->pointer;
    if (len < 2) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"BER object identifier too short"); 
	}
	return FALSE;
    }
    subid = oid [1] + oid [0] * 40;
    oid += len;
    while (l-- > 2) {
	if (!enc_subid(asn1, *--oid, error)) {
	    return FALSE;
	}
    }
    if (!enc_subid (asn1, subid, error)) {
	return FALSE;
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_oid:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @eoc: the end of encoding pointer.
 * @oid: pointer to a dynamically allocated sub-identifiers vector.
 * @len: the pointer used to store the number of sub-identifier.
 * @error: the error object used to report errors.
 *
 * Decodes a sub-identifier vector from an ASN.1 OBJECT IDENTIFIER value.
 *
 * Returns: a gboolean value indicating success.
 */

static inline gboolean 
dec_subid(GNetSnmpBer *asn1, guint32 *subid, GError **error)
{
    guchar ch;
    
    g_assert(asn1);
    
    *subid = 0;
    do {
        if (!dec_octet(asn1, &ch, error)) {
            return FALSE;
	}
        *subid <<= 7;
        *subid |= ch & 0x7F;
    }
    while ((ch & 0x80) == 0x80);
    return TRUE;
}

gboolean 
gnet_snmp_ber_dec_oid(GNetSnmpBer *asn1, guchar *eoc,
		      guint32 **oid, gsize *len, GError **error)
{
    guint32 subid;
    guint  size;
    guint32 *optr;
    
    g_assert(asn1);
    
    size = eoc - asn1->pointer + 1;
    *oid = g_new(guint32, size);
    optr = *oid;
    
    if (!dec_subid(asn1, &subid, error)) {
	g_free(*oid);
	*oid = NULL;
	return FALSE;
    }
    if (subid < 40) {
	optr [0] = 0;
	optr [1] = subid;
    } else if (subid < 80) {
	optr [0] = 1;
	optr [1] = subid - 40;
    } else {
	optr [0] = 2;
	optr [1] = subid - 80;
    }
    *len = 2;
    optr += 2;
    while (asn1->pointer < eoc) {
	if (++(*len) > size) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER object identifier value too long"); 
	    }
	    g_free(*oid);
	    *oid = NULL;
	    return FALSE;
	}
	if (!dec_subid (asn1, optr++, error)) {
	    g_free(*oid);
	    *oid = NULL;
	    return FALSE;
        }
    }
    
    return TRUE;
}
