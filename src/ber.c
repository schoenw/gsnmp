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

/** Initializes a #GNetSnmpBer buffer for encoding.
 *
 * \param buf the address of the buffer to encode into.
 * \param buf_len: the length of the buffer which will be filled.
 *
 * Initializes a #GNetSnmpBer buffer for encoding. Note that encoding
 * is done backwards, that is we start filling the buffer from the end
 * and work towards the beginning.
 *
 * \return the handle for the encoding buffer.
 */

GNetSnmpBer *
gnet_snmp_ber_enc_new(guchar *buf, gsize buf_len)
{
    GNetSnmpBer *ber;

    ber = g_new(GNetSnmpBer, 1);
    ber->begin = buf;
    ber->end = buf + buf_len;
    ber->pointer = ber->end;
    return ber;
}

/** Initializes a #GNetSnmpBer buffer for decoding.
 *
 * \param buf the address of the buffer to decode.
 * \param buf_len the length of the buffer which will be decoded.
 *
 * Initializes a #GNetSnmpBer buffer for decoding. Note that decoding
 * is done forward, that is we read the buffer from the beginning to
 * the end.
 *
 * \return the handle for the decoding buffer.
 */

GNetSnmpBer*
gnet_snmp_ber_dec_new(guchar *buf, gsize buf_len)
{
    GNetSnmpBer *ber;

    ber = g_new(GNetSnmpBer, 1);
    ber->begin = buf;
    ber->end = buf + buf_len;
    ber->pointer = ber->begin;
    return ber;
}

/** Delete a #GNetSnmpBer encoding buffer.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param buf the pointer to store the address of the encoded bytes.
 * \param len the pointer to store the length of the encoded bytes.
 *
 * Delete a #GNetSnmpBer encoding buffer and returns the address
 * and length of the encoded bytes.
 */

void 
gnet_snmp_ber_enc_delete(GNetSnmpBer *ber, guchar **buf, gsize *len)
{
    if (buf) *buf = ber->pointer;
    if (len) *len = ber->end - ber->pointer;
    g_free(ber);
}

/** Delete a #GNetSnmpBer decoding buffer.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param buf the pointer to store the address of the decoded bytes.
 * \param len the pointer to store the length of the decoded bytes.
 *
 * Delete a #GNetSnmpBer decoding buffer and returns the address
 * and length of the decoded bytes.
 */

void 
gnet_snmp_ber_dec_delete(GNetSnmpBer *ber, guchar **buf, gsize *len)
{
    if (buf) *buf = ber->pointer;
    if (len) *len = ber->end - ber->pointer;
    g_free(ber);
}

/** Encodes an octet if there is still buffer space to encode.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param ch the octet to encode.
 * \param error the error object used to report errors.
 * 
 * Encodes an octet if there is still buffer space to encode.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
enc_octet(GNetSnmpBer *ber, guchar ch, GError **error)
{
    if (ber->pointer <= ber->begin) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_FULL,
			"BER encoding buffer overflow"); 
	}
        return FALSE;
    }
    *--(ber->pointer) = ch;
    return TRUE;
}

/** Decodes an octet if there is still buffer space to decode.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param ch the pointer used to store the decoded octet.
 * \param error the error object used to report errors.
 *
 * Decodes an octet if there is still buffer space to decode.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
dec_octet(GNetSnmpBer *ber, guchar *ch, GError **error)
{
    if (ber->pointer >= ber->end) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_EMPTY,
			"BER encoding buffer underflow"); 
	}
        return FALSE;
    }
    *ch = *(ber->pointer)++;
    return TRUE;
}

/** Encodes a tag value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param tag the tag to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a tag value.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
enc_tag(GNetSnmpBer *ber, guint tag, GError **error)
{
    guchar ch;

    ch = (guchar) (tag & 0x7F);
    tag >>= 7;
    if (!enc_octet(ber, ch, error)) {
        return FALSE;
    }
    while (tag > 0) {
        ch = (guchar) (tag | 0x80);
        tag >>= 7;
        if (!enc_octet(ber, ch, error)) {
            return FALSE;
	}
    }
    return TRUE;
}

/** Decodes a tag value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param tag the pointer used to store the decoded tag value.
 * \param error the error object used to report errors.
 *
 * Decodes a tag value.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
dec_tag(GNetSnmpBer *ber, guint *tag, GError **error)
{
    guchar ch;

    *tag = 0;
    do {
        if (!dec_octet(ber, &ch, error)) {
            return FALSE;
	}
        *tag <<= 7;
        *tag |= ch & 0x7F;
    }
    while ((ch & 0x80) == 0x80);
    return TRUE;
}

/** Encodes an identifier.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param cls the ASN.1 class value.
 * \param con the ASN.1 constructed value.
 * \param tag the ASN.1 tag value.
 * \param error the error object used to report errors.
 *
 * Encodes an identifier.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
enc_id(GNetSnmpBer *ber, guint cls, guint con, guint tag, GError **error)
{
    guint ch;

    if (tag >= 0x1F) {
        if (!enc_tag(ber, tag, error)) {
            return FALSE;
	}
        tag = 0x1F;
    }
    ch = (guchar) ((cls << 6) | (con << 5) | (tag));
    if (!enc_octet(ber, ch, error)) {
        return FALSE;
    }
    return TRUE;
}

/** Decodes an identifier.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param cls the pointer used to store the ASN.1 class value.
 * \param con the pointer used to store the ASN.1 constructed value.
 * \param tag the pointer used to store the ASN.1 tag value.
 * \param error the error object used to report errors.
 *
 * Decodes an identifier.
 *
 * \return a gboolean value indicating success.
 */

static inline gboolean 
dec_id(GNetSnmpBer *ber, guint *cls, guint *con, guint *tag, GError **error)
{
    guchar ch;

    if (!dec_octet(ber, &ch, error)) {
        return FALSE;
    }
    *cls = (ch & 0xC0) >> 6;
    *con = (ch & 0x20) >> 5;
    *tag = (ch & 0x1F);
    if (*tag == 0x1F) {
        if (!dec_tag(ber, tag, error)) {
            return FALSE;
	}
    }
    return TRUE;
}

/** Encodes a definite or indefinite length.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param def flag indicating (in)definite encoding.
 * \param len the length to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a definite or indefinite length.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_length(GNetSnmpBer *ber, guint def, gsize len,
			 GError **error)
{
    guchar ch, cnt;

    g_assert(ber);
    
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
                if (!enc_octet(ber, ch, error)) {
		    return FALSE;
		}
                cnt++;
            }
            ch = (guchar) (cnt | 0x80);
        }
    }
    if (!enc_octet(ber, ch, error)) {
        return FALSE;
    }
    return TRUE;
}

/** Decodes a definite or indefinite length.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param def the pointer to store a flag indicating (in)definite encoding.
 * \param len the pointer to store the decoded length.
 * \param error the error object used to report errors.
 *
 * Decodes a definite or indefinite length.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_length(GNetSnmpBer *ber, guint *def, gsize *len,
			 GError **error)
{
    guchar ch, cnt;
    
    g_assert(ber);
    
    if (!dec_octet(ber, &ch, error)) {
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
                if (!dec_octet(ber, &ch, error)) {
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

/** Encodes an ASN1/BER header.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding or NULL is indefinite.
 * \param cls the ASN.1 tag class.
 * \param con the primitve/constructed flag.
 * \param tag the ASN.1 tag value.
 * \param error the error object used to report errors.
 *
 * Encodes an ASN1/BER header.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_header(GNetSnmpBer *ber, guchar *eoc,
			 guint cls, guint con, guint tag,
			 GError **error)
{
    guint def, len;
    
    g_assert(ber);
    
    if (eoc == 0) {
        def = 0;
        len = 0;
    } else {
        def = 1;
        len = eoc - ber->pointer;
    }
    if (!gnet_snmp_ber_enc_length(ber, def, len, error)) {
        return FALSE;
    }
    if (!enc_id(ber, cls, con, tag, error)) {
        return FALSE;
    }
    return TRUE;
}

/** Decodes an ASN1/BER header.
 * 
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to store the end of encoding or NULL is indefinite.
 * \param cls the pointer to store ASN.1 tag class.
 * \param con the pointer to store the primitve/constructed flag.
 * \param tag the pointer to store the ASN.1 tag value.
 * \param error the error object used to report errors.
 *
 * Decodes an ASN1/BER header.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_header(GNetSnmpBer *ber, guchar **eoc,
			 guint *cls, guint *con, guint *tag,
			 GError **error)
{
    guint def;
    gsize len;

    g_assert(ber);
    
    if (!dec_id(ber, cls, con, tag, error)) {
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_length(ber, &def, &len, error)) {
        return FALSE;
    }
    if (def)
        *eoc = ber->pointer + len;
    else
        *eoc = 0;
    return TRUE;
}

/** Checks if decoding has reached the end-of-contents.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 *
 * Checks if decoding has reached the end-of-contents.
 *
 * \return a gboolean indicating whether we have reached the end of contents.
 */

gboolean 
gnet_snmp_ber_is_eoc(GNetSnmpBer *ber, guchar *eoc)
{
    g_assert(ber);
    
    if (eoc == 0) {
	return (ber->pointer [0] == 0x00 && ber->pointer [1] == 0x00);
    } else {
	return (ber->pointer >= eoc);
    }
}

/** Encodes or sets the end-of-contents (eoc) of a compound type.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer used to store the end of encoding pointer.
 * \param error the error object used to report errors.
 *
 * If eoc is 0 it encodes an ASN1 end of contents (0x00 0x00), so it
 * produces an indefinite length encoding. If eoc points to a
 * character pointer, eoc is filled with the pointer to the last
 * encoded octet. This pointer can be used in the next
 * #gnet_snmp_ber_enc_header to determine the length of the
 * encoding. This produces a definite length encoding.
 *
 * \return a gboolean indicating success.
 */

gboolean 
gnet_snmp_ber_enc_eoc(GNetSnmpBer *ber, guchar **eoc, GError **error)
{
    g_assert(ber);
    
    if (eoc == 0) {
	if (!enc_octet(ber, 0x00, error)) {
	    return FALSE;
	}
	if (!enc_octet(ber, 0x00, error)) {
	    return FALSE;
	}
    } else {
	*eoc = ber->pointer;
    }
    return TRUE;
}

/** Decodes or verifies the end-of-contents (eoc) of a compound type.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param error the error object used to report errors.
 *
 * If eoc is 0 it decodes an ASN1 end of contents (0x00 0x00), so it
 * has to be an indefinite length encoding. If eoc is a character
 * pointer, it probably was filled by asn1_header_decode, and should
 * point to the octet after the last of the encoding. It is checked if
 * this pointer points to the octet to be decoded. This only takes
 * place in decoding a definite length encoding.
 *
 * \return a gboolean indicating success.
 */

gboolean 
gnet_snmp_ber_dec_eoc(GNetSnmpBer *ber, guchar *eoc, GError **error)
{
    guchar ch;
    
    g_assert(ber);
    
    if (eoc == 0) {
	if (!dec_octet(ber, &ch, error)) {
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
	if (!dec_octet(ber, &ch, error)) {
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
	if (ber->pointer != eoc) {
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

/** Encodes an ASN.1 NULL value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param error the error object used to report errors.
 *
 * Encodes an ASN.1 NULL value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_null(GNetSnmpBer *ber, guchar **eoc, GError **error)
{
    g_assert(ber);
    
    *eoc = ber->pointer;
    return TRUE;
}

/** Decodes an ASN.1 NULL value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param error the error object used to report errors.
 *
 * Decodes an ASN.1 NULL value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_null(GNetSnmpBer *ber, guchar *eoc, GError **error)
{
    g_assert(ber);
    
    ber->pointer = eoc;
    return TRUE;
}

/** Encodes a gint32 value as an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param value the gint32 value to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a gint32 value as an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_gint32(GNetSnmpBer *ber, guchar **eoc,
			 const gint32 value, GError **error)
{
    guchar ch, sign;
    int    lim;
    gint32 val = value;
    
    g_assert(ber);
    
    *eoc = ber->pointer;
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
        if (!enc_octet(ber, ch, error)) {
            return FALSE;
	}
    } while ((val != lim) || (guchar) (ch & 0x80) != sign);
    return TRUE;
}

/** Decodes a gint32 value from an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param value the pointer used to store the gint32 value.
 * \param error the error object used to report errors.
 *
 * Decodes a gint32 value from an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_gint32(GNetSnmpBer *ber, guchar *eoc,
			 gint32 *value, GError **error)
{
    guchar ch;
    guint  len;
    
    g_assert(ber);
    
    if (!dec_octet(ber, &ch, error))
        return FALSE;
    *value = (gchar) ch;
    len = 1;
    while (ber->pointer < eoc) {
        if (++len > sizeof (gint32)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER gint32 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(ber, &ch, error))
            return FALSE;
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/** Encodes a gint64 value as an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param value the gint64 value to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a gint64 value as an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean
gnet_snmp_ber_enc_gint64(GNetSnmpBer *ber, guchar **eoc,
			 const gint64 value, GError **error)
{
    guchar ch, sign;
    glong  lim;
    gint64 val = value;
    
    g_assert(ber);
    
    *eoc = ber->pointer;
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
        if (!enc_octet(ber, ch, error)) {
            return FALSE;
	}
    } while ((val != lim) || (guchar) (ch & 0x80) != sign);
    return TRUE;
}

/** Decodes a gint64 value from an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param value the pointer used to store the gint64 value.
 * \param error the error object used to report errors.
 *
 * Decodes a gint64 value from an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_gint64(GNetSnmpBer *ber, guchar *eoc,
			 gint64 *value, GError **error)
{
    guchar ch;
    guint  len;

    g_assert(ber);
    
    if (!dec_octet(ber, &ch, error)) {
        return FALSE;
    }
    *value = (gchar) ch;
    len = 1;
    while (ber->pointer < eoc) {
	if (++len > sizeof (gint64)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER gint64 value too big"); 
	    }
	    return FALSE;
	}
	if (!dec_octet(ber, &ch, error)) {
	    return FALSE;
	}
	*value <<= 8;
	*value |= ch;
    }
    return TRUE;
}

/** Encodes a guint32 value as an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param value the guint32 value to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a guint32 value as an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_guint32(GNetSnmpBer *ber, guchar **eoc,
			  const guint32 value, GError **error)
{
    guchar ch;
    guint32 val = value;
    
    g_assert(ber);
    
    *eoc = ber->pointer;
    do {
	ch = (guchar) val;
	val >>= 8;
	if (!enc_octet(ber, ch, error)) {
	    return FALSE;
	}
    } while ((val != 0) || (ch & 0x80) != 0x00);
    return TRUE;
}

/** Decodes a guint32 value from an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param value the pointer used to store the guint32 value.
 * \param error the error object used to report errors.
 *
 * Decodes a guint32 value from an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_guint32(GNetSnmpBer *ber, guchar *eoc,
			  guint32 *value, GError **error)
{
    guchar ch;
    guint  len;
    
    g_assert(ber);
    
    if (!dec_octet(ber, &ch, error)) {
        return FALSE;
    }
    *value = ch;
    len = (ch == 0) ? 0 : 1;
    while (ber->pointer < eoc) {
        if (++len > sizeof (guint32)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER guint32 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(ber, &ch, error)) {
            return FALSE;
	}
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/** Encodes a guint64 value as an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param value the guint64 value to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a guint64 value as an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_guint64(GNetSnmpBer *ber, guchar **eoc,
			  const guint64 value, GError **error)
{
    guchar ch;
    guint64 val = value;

    g_assert(ber);
    
    *eoc = ber->pointer;
    do {
        ch = (guchar) val;
        val >>= 8;
        if (!enc_octet(ber, ch, error)) {
            return FALSE;
	}
    }
    while ((val != 0) || (ch & 0x80) != 0x00);
    return TRUE;
}

/** Decodes a guint64 value from an ASN.1 INTEGER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param value the pointer used to store the guint64 value.
 * \param error the error object used to report errors.
 *
 * Decodes a guint64 value from an ASN.1 INTEGER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_guint64(GNetSnmpBer *ber, guchar *eoc,
			  guint64 *value, GError **error)
{
    guchar ch;
    guint  len;

    g_assert(ber);
    
    if (!dec_octet(ber, &ch, error)) {
        return FALSE;
    }
    *value = ch;
    len = (ch == 0) ? 0 : 1;
    while (ber->pointer < eoc) {
        if (++len > sizeof (guint64)) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "BER guint64 value too big"); 
	    }
            return FALSE;
	}
        if (!dec_octet(ber, &ch, error)) {
            return FALSE;
	}
        *value <<= 8;
        *value |= ch;
    }
    return TRUE;
}

/** Encodes a buffer of octets (bytes) as an ASN.1 OCTET STRING value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param octets the pointer to the octets to encode.
 * \param len the number of octets to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a buffer of octets (bytes) as an ASN.1 OCTET STRING value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_octets(GNetSnmpBer *ber, guchar **eoc,
			 const guchar *octets, const gsize len, GError **error)
{
    const guchar *ptr;
    gint i;

    g_assert(ber);
    
    *eoc = ber->pointer;
    ptr = octets + len;

    for (i = 0; i < len; i++) {
	if (!enc_octet(ber, *--ptr, error))
	    return FALSE;
    }
    return TRUE;
}

/** Decodes a buffer of octets (bytes) from an ASN.1 OCTET STRING value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param octets pointer to a dynamically allocated buffer holding the value.
 * \param len the pointer used to store the number of octets.
 * \param error the error object used to report errors.
 *
 * Decodes a buffer of octets (bytes) from an ASN.1 OCTET STRING value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_octets(GNetSnmpBer *ber, guchar *eoc,
			 guchar **octets, gsize *len, GError **error)
{
    guchar *ptr;
    
    g_assert(ber);
    
    *octets = NULL;
    *len = 0;
    *octets = g_new(guchar, eoc - ber->pointer + 1);
    ptr = *octets;
    while (ber->pointer < eoc) {
	if (!dec_octet(ber, (guchar *)ptr++, error)) {
	    g_free(*octets);
	    *octets = NULL;
	    return FALSE;
	}
	(*len)++;
    }
    return TRUE;
}

/*
 * Inline helper to encode a single subid. See OID decoding function
 * below.
 */

static inline gboolean 
enc_subid(GNetSnmpBer *ber, guint32 subid, GError **error)
{
    guchar ch;
    
    g_assert(ber);
    
    ch = (guchar) (subid & 0x7F);
    subid >>= 7;
    if (!enc_octet(ber, ch, error)) {
	return FALSE;
    }
    while (subid > 0) {
	ch = (guchar) (subid | 0x80);
	subid >>= 7;
	if (!enc_octet(ber, ch, error)) {
	    return FALSE;
	}
    }
    return TRUE;
}

/** Encodes a sub-identifier vector as an ASN.1 OBJECT IDENTIFIER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the pointer to the end of encoding pointer.
 * \param oid the sub-identifier vector to encode.
 * \param len the number of sub-identifiers to encode.
 * \param error the error object used to report errors.
 *
 * Encodes a sub-identifier vector as an ASN.1 OBJECT IDENTIFIER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_oid(GNetSnmpBer *ber, guchar **eoc,
		      const guint32 *oid, const gsize len, GError **error)
{
    gulong subid;
    guint l = len;
    
    g_assert(ber);
    
    *eoc = ber->pointer;
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
	if (!enc_subid(ber, *--oid, error)) {
	    return FALSE;
	}
    }
    if (!enc_subid (ber, subid, error)) {
	return FALSE;
    }
    return TRUE;
}

/*
 * Inline helper to decode a single subid. See OID decoding function
 * below.
 */

static inline gboolean 
dec_subid(GNetSnmpBer *ber, guint32 *subid, GError **error)
{
    guchar ch;
    
    g_assert(ber);
    
    *subid = 0;
    do {
        if (!dec_octet(ber, &ch, error)) {
            return FALSE;
	}
        *subid <<= 7;
        *subid |= ch & 0x7F;
    }
    while ((ch & 0x80) == 0x80);
    return TRUE;
}

/** Decodes a sub-identifier vector from an ASN.1 OBJECT IDENTIFIER value.
 *
 * \param ber the handle for the #GNetSnmpBer buffer.
 * \param eoc the end of encoding pointer.
 * \param oid pointer to a dynamically allocated sub-identifiers vector.
 * \param len the pointer used to store the number of sub-identifier.
 * \param error the error object used to report errors.
 *
 * Decodes a sub-identifier vector from an ASN.1 OBJECT IDENTIFIER value.
 *
 * \return a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_oid(GNetSnmpBer *ber, guchar *eoc,
		      guint32 **oid, gsize *len, GError **error)
{
    guint32 subid;
    guint  size;
    guint32 *optr;
    
    g_assert(ber);
    
    size = eoc - ber->pointer + 1;
    *oid = g_new(guint32, size);
    optr = *oid;
    
    if (!dec_subid(ber, &subid, error)) {
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
    while (ber->pointer < eoc) {
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
	if (!dec_subid (ber, optr++, error)) {
	    g_free(*oid);
	    *oid = NULL;
	    return FALSE;
        }
    }
    
    return TRUE;
}
