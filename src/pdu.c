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

#include <memory.h>
#include "pdu.h"

/*
 * Constants used internally for encoding/decoding traps.
 */

static const guint32 sysUpTime0[]
	= { 1, 3, 6, 1, 2, 1, 1, 3, 0 }; 
static const guint32 snmpTrapOID0[]
	= { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static const guint32 snmpTrapAddress0[]
	= { 1, 3, 6, 1, 6, 3, 18, 1, 3, 0 };
static const guint32 snmpTrapCommunity0[]
	= { 1, 3, 6, 1, 6, 3, 18, 1, 4, 0 };
static const guint32 snmpTrapEnterprise0[]
	= { 1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0 };
static const guint32 snmpTraps[]
	= { 1, 3, 6, 1, 6, 3, 1, 1, 5 };

/*
 * Application specific ASN.1 tags as defined in RFC 3416.
 */

#define GNET_SNMP_ATAG_IPA    0
#define GNET_SNMP_ATAG_CNT    1
#define GNET_SNMP_ATAG_GGE    2
#define GNET_SNMP_ATAG_TIT    3
#define GNET_SNMP_ATAG_OPQ    4
#define GNET_SNMP_ATAG_C64    6

#define GNET_SNMP_ATAG_NSO    0
#define GNET_SNMP_ATAG_NSI    1
#define GNET_SNMP_ATAG_EOM    2

static struct {
    guint		klass;
    guint		tag;
    GNetSnmpVarBindType type;
} class_tag_type_table[] = {

    { GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_NUL, GNET_SNMP_VARBIND_TYPE_NULL},
    { GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_INT, GNET_SNMP_VARBIND_TYPE_INTEGER32},
    { GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_OTS, GNET_SNMP_VARBIND_TYPE_OCTETSTRING},
    { GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_OJI, GNET_SNMP_VARBIND_TYPE_OBJECTID},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_IPA, GNET_SNMP_VARBIND_TYPE_IPADDRESS},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_CNT, GNET_SNMP_VARBIND_TYPE_COUNTER32},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_GGE, GNET_SNMP_VARBIND_TYPE_UNSIGNED32},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_TIT, GNET_SNMP_VARBIND_TYPE_TIMETICKS},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_OPQ, GNET_SNMP_VARBIND_TYPE_OPAQUE},
    { GNET_SNMP_ASN1_APL, GNET_SNMP_ATAG_C64, GNET_SNMP_VARBIND_TYPE_COUNTER64},
    { GNET_SNMP_ASN1_CTX, GNET_SNMP_ATAG_NSO, GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT},
    { GNET_SNMP_ASN1_CTX, GNET_SNMP_ATAG_NSI, GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE},
    { GNET_SNMP_ASN1_CTX, GNET_SNMP_ATAG_EOM, GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW},
    
    { -1, -1, -1 }
};

static inline gboolean
type_to_tag_and_class(guint *tag, guint *cls, GNetSnmpVarBindType type)
{
    int i;

    for (i = 0; class_tag_type_table[i].klass != -1; i++) {
	if (class_tag_type_table[i].type == type) {
            *tag = class_tag_type_table[i].tag;
            *cls = class_tag_type_table[i].klass;
	    return TRUE;
	}
    }
    return FALSE;
}

static inline gboolean
tag_and_class_to_type(guint tag, guint klass, GNetSnmpVarBindType *type)
{
    int i;
    
    for (i = 0; class_tag_type_table[i].klass != -1; i++) {
	if (class_tag_type_table[i].tag == tag
	    && class_tag_type_table[i].klass == klass) {
            *type = class_tag_type_table[i].type;
            return TRUE;
        }
    }
    return FALSE;
}


/**
 * varbind_new:
 *
 * Internal function to allocate and initialize a new GNetSnmpVarBind.
 *
 * Returns: a pointer to a new GNetSnmpVarBind.
 */

static GNetSnmpVarBind*
varbind_new(const guint32 *oid, const gsize oid_len,
	    const GNetSnmpVarBindType type,
	    const gpointer value, const gsize value_len,
	    const int flags)
{
    GNetSnmpVarBind *vb;

    vb = g_new(GNetSnmpVarBind, 1);
    
    vb->oid_len = oid_len;
    vb->oid = flags ? (guint32 *)oid
	: (guint32 *) g_memdup(oid, oid_len * sizeof(guint32));
    
    vb->type = type;
    
    vb->value_len = 0;
    switch (type) {
    case GNET_SNMP_VARBIND_TYPE_NULL:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE:
    case GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW:
	vb->value.i32 = 0;
        break;
    case GNET_SNMP_VARBIND_TYPE_INTEGER32:
	g_assert(value);    
        vb->value.i32 = *((gint32 *) value);
        break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER32:
    case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
    case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	g_assert(value);    
        vb->value.ui32 = *((guint32 *) value);
        break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	g_assert(value);    
	vb->value.ui64 = *((guint64 *) value);
	break;
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
    case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
    case GNET_SNMP_VARBIND_TYPE_OPAQUE:
        vb->value_len = value_len;
        vb->value.ui8v = flags ? (guchar *) value
	    : (guchar *) g_memdup(value, vb->value_len);
        break;
    case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	vb->value_len = value_len;
        vb->value.ui32v = flags ? (guint32 *) value
	    : (guint32 *) g_memdup(value, vb->value_len * sizeof(guint32));
	break;
    }

    return vb;
}

/**
 * gnet_snmp_varbind_new:
 *
 * Allocate and initialize a new GNetSnmpVarBind.
 *
 * Returns: a pointer to a new GNetSnmpVarBind.
 */

GNetSnmpVarBind*
gnet_snmp_varbind_new(const guint32 *oid, const gsize oid_len,
		      const GNetSnmpVarBindType type,
		      const gpointer value, const gsize value_len)
{
    return varbind_new(oid, oid_len, type, value, value_len, 0);
}

/**
 * gnet_snmp_varbind_delete:
 * @vb: the pointer to the #GNetSnmpVarBind to free
 *
 * Deallocate a GNetSnmpVarBind by freeing all associated memory.
 */

void
gnet_snmp_varbind_delete(GNetSnmpVarBind *vb)
{
    if (vb) {
	g_free(vb->oid);
	switch (vb->type) {
	case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
	case GNET_SNMP_VARBIND_TYPE_OPAQUE:
	    g_free(vb->value.ui8v);
	    break;
	case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	    g_free(vb->value.ui32v);
	    break;
	default:
	    break;
	}
	g_free(vb);
    }
}

/**
 * gnet_snmp_ber_enc_varbind:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vb: the pointer to the #GNetSnmpVarBind to encode
 * @error: the error object used to report errors.
 *
 * Encodes an SNMP varbind as an ASN.1 SEQUENCE.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_varbind(GNetSnmpBer *asn1, GNetSnmpVarBind *vb,
			  GError **error)
{
    guint   cls, tag;
    guchar *eoc, *end;

    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;
    switch (vb->type) {
    case GNET_SNMP_VARBIND_TYPE_INTEGER32:
	if (!gnet_snmp_ber_enc_gint32(asn1, &end, vb->value.i32, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
    case GNET_SNMP_VARBIND_TYPE_OPAQUE:
	if (!gnet_snmp_ber_enc_octets(asn1, &end, vb->value.ui8v, 
				      vb->value_len, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_NULL:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE:
    case GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW:
	if (!gnet_snmp_ber_enc_null(asn1, &end, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	if (!gnet_snmp_ber_enc_oid(asn1, &end, vb->value.ui32v,
				   vb->value_len, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
	if (!gnet_snmp_ber_enc_octets(asn1, &end, vb->value.ui8v, 
				      vb->value_len, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER32:
    case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
    case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	if (!gnet_snmp_ber_enc_guint32(asn1, &end, vb->value.ui32, error))
	    return FALSE;
	break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	if (!gnet_snmp_ber_enc_guint64(asn1, &end, vb->value.ui64, error))
	    return FALSE;
	break;
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"unknown varbind type %d", vb->type);
	}
	return FALSE;
    }

    g_assert(type_to_tag_and_class(&tag, &cls, vb->type));
    
    if (!gnet_snmp_ber_enc_header(asn1, end, cls, GNET_SNMP_ASN1_PRI, tag,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_oid(asn1, &end, vb->oid, vb->oid_len, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OJI,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ,
				  error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_varbind_null:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vb: the pointer to the #GNetSnmpVarBind to encode
 * @error: the error object used to report errors.
 *
 * Encodes an SNMP varbind as an ASN.1 SEQUENCE. This function always
 * encodes an ASN.1 NULL value, regardless what the varbind actually
 * contains.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_varbind_null(GNetSnmpBer *asn1, GNetSnmpVarBind *vb,
			       GError **error)
{
    GNetSnmpVarBindType t;
    gboolean b;

    t = vb->type;
    vb->type = GNET_SNMP_VARBIND_TYPE_NULL;
    b = gnet_snmp_ber_enc_varbind(asn1, vb, error);
    vb->type = t;
    return b;
}

/**
 * gnet_snmp_ber_dec_varbind:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vb: the pointer used to store the new #GNetSnmpVarBind.
 * @error: the error object used to report errors.
 *
 * Decodes an SNMP varbind from an ASN.1 SEQUENCE.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_varbind(GNetSnmpBer *asn1, GNetSnmpVarBind **vb,
			  GError **error)
{
    guint cls, con, tag;
    gsize len, idlen;
    GNetSnmpVarBindType type;
    guchar *eoc, *end, *p = NULL;
    guint32 *lp = NULL;
    guint32 *id;
    gint32 l;
    guint32 ul;
    guint64 ull;
    gpointer value = NULL;
    gsize value_len = 0;
    
    g_assert(vb);

    *vb = NULL;
    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_CON
	|| tag != GNET_SNMP_ASN1_SEQ) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"varbind sequence with unexpected tag %d", tag); 
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_OJI) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"varbind name with unexpected tag %d", tag); 
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_oid(asn1, end, &id, &idlen, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error)) {
	g_free(id);
	return FALSE;
    }
    if (con != GNET_SNMP_ASN1_PRI
	|| ! tag_and_class_to_type(tag, cls, &type)) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"varbind value with unexpected tag %d", tag); 
	}
	g_free(id);
	return FALSE;
    }

    switch (type) {
    case GNET_SNMP_VARBIND_TYPE_INTEGER32:
        if (!gnet_snmp_ber_dec_gint32(asn1, end, &l, error)) {
            g_free(id);
            return FALSE;
	}
	value = &l;
        break;
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
    case GNET_SNMP_VARBIND_TYPE_OPAQUE:
        if (!gnet_snmp_ber_dec_octets(asn1, end, &p, &len, error)) {
            g_free(id);
            return FALSE;
	}
	value = p;
	value_len = len;
        break;
    case GNET_SNMP_VARBIND_TYPE_NULL:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT:
    case GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE:
    case GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW:
        if (!gnet_snmp_ber_dec_null(asn1, end, error)) {
            g_free(id);
            return FALSE;
	}
        break;
    case GNET_SNMP_VARBIND_TYPE_OBJECTID:
        if (!gnet_snmp_ber_dec_oid(asn1, end, (guint32 **)&lp, &len, error)) {
            g_free(id);
            return FALSE;
	}
	value = lp;
	value_len = len;
        break;
    case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
        if (!gnet_snmp_ber_dec_octets(asn1, end, &p, &len, error)) {
            g_free(id);
            return FALSE;
	}
        if (len != 4) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			    "varbind value has unexpected length %d", len); 
	    }
            g_free(p);
            g_free(id);
            return FALSE;
	}
	value = p;
	value_len = len;
        break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER32:
    case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
    case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
        if (!gnet_snmp_ber_dec_guint32(asn1, end, &ul, error)) {
	    g_free(id);
            return FALSE;
	}
	value = &ul;
        break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	if (!gnet_snmp_ber_dec_guint64(asn1, end, &ull, error)) {
	    g_free(id);
	    return FALSE;
	}
	value = &ull;
        break;
    default:
	g_assert_not_reached();
    }
    
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error)) {
        g_free(id);
	return FALSE;
    }
    
    *vb = varbind_new(id, idlen, type, value, value_len, 1);
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_varbind_list:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vbl: the list of #GNetSnmpVarBind to encode
 * @error: the error object used to report errors.
 *
 * Encodes an SNMP varbind list as an ASN.1 SEQUENCE OF.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_varbind_list(GNetSnmpBer *asn1, GList *vbl, GError **error)
{
    guchar *eoc;
    GList *elem;

    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;

    for (elem = g_list_last(vbl); elem; elem = g_list_previous(elem)) {
        if (!gnet_snmp_ber_enc_varbind(asn1,
				       (GNetSnmpVarBind *) elem->data, error))
	    return FALSE;
    }

    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ,
				  error))
        return FALSE;
    
    if (g_snmp_list_encode_hook) {
	g_snmp_list_encode_hook(vbl);
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_varbind_list_null:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vbl: the list of #GNetSnmpVarBind to encode
 * @error: the error object used to report errors.
 *
 * Encodes an SNMP varbind list as an ASN.1 SEQUENCE OF. This function
 * always encodes an ASN.1 NULL values, regardless what the varbinds
 * actually contain.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_varbind_list_null(GNetSnmpBer *asn1, GList *vbl,
				    GError **error)
{
    guchar *eoc;
    GList *elem;

    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;

    for (elem = g_list_last(vbl); elem; elem = g_list_previous(elem)) {
        if (!gnet_snmp_ber_enc_varbind_null(asn1,
				    (GNetSnmpVarBind *) elem->data, error))
	    return FALSE;
    }

    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ,
				  error))
        return FALSE;
    
    if (g_snmp_list_encode_hook) {
	g_snmp_list_encode_hook(vbl);
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_varbind_list:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @vbl: the pointer used to store the new list of #GNetSnmpVarBinds.
 * @error: the error object used to report errors.
 *
 * Decodes an SNMP varbind list from an ASN.1 SEQUENCE OF.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_varbind_list(GNetSnmpBer *asn1, GList **vbl, GError **error)
{
    guint cls, con, tag;
    guchar *eoc;
    GNetSnmpVarBind *vb;

    g_assert(vbl);
    
    *vbl = NULL;
    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_CON
	|| tag != GNET_SNMP_ASN1_SEQ) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"varbind list starts with unexpected tag %d", tag); 
	}
        return FALSE;
    }

    while (!gnet_snmp_ber_is_eoc(asn1, eoc)) {
        if (!gnet_snmp_ber_dec_varbind(asn1, &vb, error)) {
	    g_list_foreach(*vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	    g_list_free(*vbl);
	    *vbl = NULL;
            return FALSE;
	}
	*vbl = g_list_prepend(*vbl, vb);
    }
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error)) {
	g_list_foreach(*vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(*vbl);
	*vbl = NULL;
        return FALSE;
    }
    *vbl = g_list_reverse(*vbl);
    if (g_snmp_list_decode_hook) {
	g_snmp_list_decode_hook(*vbl);
    }
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_standard_pdu:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &pdu: the @GNetSnmpPdu to encode.
 * @error: the error object used to report errors.
 *
 * Encodes a standard SNMP PDU as defined in RFC 3416. Suppresses
 * values on read class PDUs.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_standard_pdu(GNetSnmpBer *asn1, GNetSnmpPdu *pdu,
			       GError **error)
{
    guchar *end;

    if (GNET_SNMP_PDU_CLASS_READ(pdu->type)) {
	if (!gnet_snmp_ber_enc_varbind_list_null(asn1, pdu->varbind_list, error))
	    return FALSE;
    } else {
	if (!gnet_snmp_ber_enc_varbind_list(asn1, pdu->varbind_list, error))
	    return FALSE;
    }
    
    if (!gnet_snmp_ber_enc_gint32(asn1, &end, pdu->error_index, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				  error))
        return FALSE;

    if (!gnet_snmp_ber_enc_gint32(asn1, &end, pdu->error_status, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				  error))
        return FALSE;

    if (!gnet_snmp_ber_enc_gint32(asn1, &end, pdu->request_id, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				  error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_standard_pdu:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &pdu: the @GNetSnmpPdu to decode.
 * @error: the error object used to report errors.
 *
 * Decodes a standard SNMP PDU as defined in RFC 3416.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_standard_pdu(GNetSnmpBer *asn1, GNetSnmpPdu *pdu,
			       GError **error)
{
    guint cls, con, tag;
    guchar *end;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_INT) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"request-id has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_gint32(asn1, end, &pdu->request_id, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_INT) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"error-status has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_gint32(asn1, end, &pdu->error_status, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_INT) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"error-index has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_gint32(asn1, end, &pdu->error_index, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_varbind_list(asn1, &pdu->varbind_list, error))
	return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_trap_pdu:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &pdu: the @GNetSnmpPdu to encode.
 * @error: the error object used to report errors.
 *
 * Encodes an SNMPv1 trap PDU as defined in RFC 1157. This function
 * also implements the notification parameter translation defined in
 * RFC 2576 section 3.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_trap_pdu(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guchar *end;

    const guint32 *enterprise = NULL;
    gsize enterprise_len = 0;
    guchar  ip_address[] = { 0x00, 0x00, 0x00, 0x00 };
    gsize   ip_address_len = 4;
    gint32  generic = 0;
    gint32  specific = 0;
    guint32 timestamp = 0;
    guint32 last = 0;

    GNetSnmpVarBind *vb, *vb_address = NULL,
	*vb_community = NULL, *vb_enterprise = NULL;
    GList *elem, *new_varbind_list = NULL;

    /* The first varbind has to be sysUpTime.0 ... */

    vb = g_list_nth_data(pdu->varbind_list, 0);
    if (! vb || vb->type != GNET_SNMP_VARBIND_TYPE_TIMETICKS
	|| gnet_snmp_compare_oids(sysUpTime0, G_N_ELEMENTS(sysUpTime0),
				  vb->oid, vb->oid_len) != 0) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"first trap varbind must be sysUpTime.0");
	}
	return FALSE;
    }
    timestamp = vb->value.ui32;

    /* ... and the following varbind must be snmpTrapOID.0. */

    vb = g_list_nth_data(pdu->varbind_list, 1);
    if (!vb || !pdu->varbind_list->data) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"second trap varbind must be snmpTrapOID.0");
	}
	return FALSE;
    }

    if (! vb || vb->type != GNET_SNMP_VARBIND_TYPE_OBJECTID
	|| gnet_snmp_compare_oids(snmpTrapOID0, G_N_ELEMENTS(snmpTrapOID0),
				  vb->oid, vb->oid_len) != 0) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"second trap varbind must be snmpTrapOID.0");
	}
	return FALSE;
    }

    /* Next, see whether we can extract essential trap parameters if
       the prefix conforms to SNMPv2-MIB::snmpTraps. */

    last = vb->value.ui32v[G_N_ELEMENTS(snmpTraps)];
    generic = 6;
    specific = last;
    if (vb->value_len > G_N_ELEMENTS(snmpTraps)
	&& memcmp(vb->value.ui32v, snmpTraps, sizeof(snmpTraps)) == 0
	&& (last > 0 || last < 7)) {
	generic = last - 1;
	specific = 0;
	enterprise = snmpTraps;
	enterprise_len = G_N_ELEMENTS(snmpTraps);
    }

    /* Skip the first two varbinds and build a new varbind list which
     * excludes any magic proxy varbinds. */

    for (elem = g_list_nth(pdu->varbind_list, 2);
	 elem; elem = g_list_next(elem)) {
	vb = elem->data;
	if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapAddress0, G_N_ELEMENTS(snmpTrapAddress0))) {
	    vb_address = vb;
	    continue;
	} else if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapCommunity0, G_N_ELEMENTS(snmpTrapCommunity0))) {
	    vb_community = vb;
	    continue;
	} else if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapEnterprise0, G_N_ELEMENTS(snmpTrapEnterprise0))) {
	    vb_enterprise = vb;
	    continue;
	}
	new_varbind_list = g_list_append(new_varbind_list, vb);
    }

    if (!gnet_snmp_ber_enc_varbind_list(asn1, new_varbind_list, error)) {
	g_list_free(new_varbind_list);
	return FALSE;
    }
    g_list_free(new_varbind_list);

    if (!gnet_snmp_ber_enc_guint32(asn1, &end, timestamp, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_APL,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ATAG_TIT,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_gint32(asn1, &end, specific, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_gint32(asn1, &end, generic, error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_octets(asn1, &end, ip_address, ip_address_len,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_APL,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ATAG_IPA,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_oid(asn1, &end, enterprise, enterprise_len,
			       error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OJI,
				  error))
        return FALSE;

    return TRUE;
}

/**
 * gnet_snmp_ber_dec_trap_pdu:
 * &asn1: the handle for the #GNetSnmpBer buffer.
 * &pdu: the @GNetSnmpPdu to decode.
 * @error: the error object used to report errors.
 *
 * Decodes an SNMPv1 trap PDU as defined in RFC 1157. This function
 * also implements the notification parameter translation defined in
 * RFC 2576 section 3.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_trap_pdu(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guint cls, con, tag;
    guchar *end;
    GNetSnmpVarBind *vb, *vb_address = NULL,
	*vb_community = NULL, *vb_enterprise = NULL;
    GList *elem;
    
    guint32 *enterprise = NULL;
    gsize   enterprise_len;
    guchar  *ip_address = NULL;
    gsize   ip_address_len;
    gint32  generic;
    gint32  specific;
    guint32 timestamp;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_OJI) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"enterprise has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_oid(asn1, end, &enterprise, &enterprise_len, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (!((cls == GNET_SNMP_ASN1_APL
	   && con == GNET_SNMP_ASN1_PRI
	   && tag == GNET_SNMP_ATAG_IPA)
	  || (cls == GNET_SNMP_ASN1_UNI
	      && con == GNET_SNMP_ASN1_PRI
	      && tag == GNET_SNMP_ASN1_OTS))) {	/* needed for Banyan */
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"ip-address has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_octets(asn1, end, &ip_address, &ip_address_len,
				  error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_INT) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"generic trap number has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_gint32(asn1, end, &generic, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_INT) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"specific trap number has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_gint32(asn1, end, &specific, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
        return FALSE;
    if (!((cls == GNET_SNMP_ASN1_APL
	   && con == GNET_SNMP_ASN1_PRI
	   && tag == GNET_SNMP_ATAG_TIT)
	  || (cls == GNET_SNMP_ASN1_UNI
	      && con == GNET_SNMP_ASN1_PRI
	      && tag == GNET_SNMP_ASN1_INT))) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"timestamp has unexpected tag %d", tag); 
	}
        return FALSE;
    }
    if (!gnet_snmp_ber_dec_guint32(asn1, end, &timestamp, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_varbind_list(asn1, &pdu->varbind_list, error))
	return FALSE;
    
    /*
     * Add varbinds as described in RFC 2576 section 3.1.
     */

    if (generic >= 0 && generic < 6) {
	guint32 base[] = { 1, 3, 6, 1, 6, 3, 1, 1, 0, 1 };
	base[8] = generic + 1;
	vb = gnet_snmp_varbind_new(snmpTrapOID0, G_N_ELEMENTS(snmpTrapOID0),
				   GNET_SNMP_VARBIND_TYPE_OBJECTID,
				   base, G_N_ELEMENTS(base));
	pdu->varbind_list = g_list_prepend(pdu->varbind_list, vb);
    } else if (generic == 6) {
	guint32 *base = g_new0(guint32, enterprise_len + 2);
	g_memmove(base, enterprise, enterprise_len * sizeof(guint32));
	base[enterprise_len + 1] = specific;
	vb = gnet_snmp_varbind_new(snmpTrapOID0, G_N_ELEMENTS(snmpTrapOID0),
				   GNET_SNMP_VARBIND_TYPE_OBJECTID,
				   base, G_N_ELEMENTS(base));
	pdu->varbind_list = g_list_prepend(pdu->varbind_list, vb);
    } else {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"illegal generic value %d", generic); 
	}
	return FALSE;
    }

    vb = gnet_snmp_varbind_new(sysUpTime0, G_N_ELEMENTS(sysUpTime0),
			       GNET_SNMP_VARBIND_TYPE_TIMETICKS,
			       &timestamp, 0);
    pdu->varbind_list = g_list_prepend(pdu->varbind_list, vb);

    /* Search for any magic varbinds potentially inserted by a proxy
     * as described in RFC 2576 section 3. If the proxy varbinds are
     * not present, we claim to be proxy and insert them according to
     * RFC 2576 section 3.1 paragraph (4). */

    for (elem = pdu->varbind_list; elem; elem = g_list_next(elem)) {
	vb = elem->data;
	if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapAddress0, G_N_ELEMENTS(snmpTrapAddress0))) {
	    vb_address = vb;
	} else if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapCommunity0, G_N_ELEMENTS(snmpTrapCommunity0))) {
	    vb_community = vb;
	} else if (0 == gnet_snmp_compare_oids(vb->oid, vb->oid_len,
		   snmpTrapEnterprise0, G_N_ELEMENTS(snmpTrapEnterprise0))) {
	    vb_enterprise = vb;
	}
    }

    if (! vb_address) {
	vb = gnet_snmp_varbind_new(snmpTrapAddress0,
				   G_N_ELEMENTS(snmpTrapAddress0),
				   GNET_SNMP_VARBIND_TYPE_IPADDRESS,
				   ip_address, ip_address_len);
	pdu->varbind_list = g_list_append(pdu->varbind_list, vb);
    }

    if (! vb_community) {
	/* xxx gee, we do not have the community handy - solve this via
	 * context pdu field? does not really work - any other ideas? */
	vb = gnet_snmp_varbind_new(snmpTrapCommunity0,
				   G_N_ELEMENTS(snmpTrapCommunity0),
				   GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
				   NULL, 0);
	pdu->varbind_list = g_list_append(pdu->varbind_list, vb);
    }

    if (! vb_enterprise) {
	vb = gnet_snmp_varbind_new(snmpTrapEnterprise0,
				   G_N_ELEMENTS(snmpTrapEnterprise0),
				   GNET_SNMP_VARBIND_TYPE_OBJECTID,
				   enterprise, enterprise_len);
	pdu->varbind_list = g_list_append(pdu->varbind_list, vb);
    }

    if (enterprise) g_free(enterprise);
    if (ip_address) g_free(ip_address);
    
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_pdu_v1:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 1157 SNMP PDU to encode.
 * @error: the error object used to report errors.
 *
 * Encodes an RFC 1157 SNMP PDU as an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean
gnet_snmp_ber_enc_pdu_v1(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guchar *eoc;
    GList *elem;
    
    /* xxx need to ensure that non SNMPv1 types in the varbind cause
     * an error and that exceptions are treated as errors and NULL
     * values */

    for (elem = pdu->varbind_list; elem; elem = g_list_next(elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	/* better be explicit ... */
	switch (vb->type) {
	case GNET_SNMP_VARBIND_TYPE_NULL:
	case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
	case GNET_SNMP_VARBIND_TYPE_INTEGER32:
	case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
	case GNET_SNMP_VARBIND_TYPE_COUNTER32:
	case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	case GNET_SNMP_VARBIND_TYPE_OPAQUE:
	    break;
	case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			    "PDU does not support Counter64"); 
	    }
	    return FALSE;
	case GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT:
	case GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE:
	case GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW:
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_BER_ERROR,
			    GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			    "PDU does not support exceptions"); 
	    }
	    return FALSE;
	}
    }

    /* xxx check for a valid message type, converting silently (?)
     * where possible */

    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;
    switch (pdu->type) {
    case GNET_SNMP_PDU_GET:
    case GNET_SNMP_PDU_NEXT:
    case GNET_SNMP_PDU_RESPONSE:
    case GNET_SNMP_PDU_SET:
	if (!gnet_snmp_ber_enc_standard_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    case GNET_SNMP_PDU_TRAP:
	if (!gnet_snmp_ber_enc_trap_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"illegal PDU type %d", pdu->type);
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_CTX,
				  GNET_SNMP_ASN1_CON, pdu->type, error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_pdu_v1:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 1157 SNMP PDU to encode.
 * @error: the error object used to report errors.
 *
 * Decodes an RFC 1157 SNMP PDU from an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_pdu_v1(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guint cls, con;
    guchar *eoc;

    /* xxx need to ensure that non SNMPv1 types in the varbind cause
     * an error and that exceptions are treated as errors and NULL
     * values */
    
    if (!gnet_snmp_ber_dec_header(asn1, &eoc,
				  &cls, &con, (guint32 *) &pdu->type, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_CTX || con != GNET_SNMP_ASN1_CON) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"PDU starts with unexpected tag %d", pdu->type); 
	}
        return FALSE;
    }
    switch (pdu->type) {
    case GNET_SNMP_PDU_GET:
    case GNET_SNMP_PDU_NEXT:
    case GNET_SNMP_PDU_RESPONSE:
    case GNET_SNMP_PDU_SET:
	if (!gnet_snmp_ber_dec_standard_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    case GNET_SNMP_PDU_TRAP:
	if (!gnet_snmp_ber_dec_trap_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"illegal PDU type %d", pdu->type);
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_pdu_v2:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 3416 SNMP PDU to encode.
 * @error: the error object used to report errors.
 *
 * Encodes an RFC 3416 SNMP PDU as an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_pdu_v2(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guchar *eoc;
    
    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;
    switch (pdu->type) {
    case GNET_SNMP_PDU_GET:
    case GNET_SNMP_PDU_NEXT:
    case GNET_SNMP_PDU_RESPONSE:
    case GNET_SNMP_PDU_SET:
    case GNET_SNMP_PDU_BULK:
    case GNET_SNMP_PDU_INFORM:
    case GNET_SNMP_PDU_TRAP:
	if (!gnet_snmp_ber_enc_standard_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_ENC_BADVALUE,
			"illegal PDU type %d", pdu->type);
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_CTX,
				  GNET_SNMP_ASN1_CON, pdu->type, error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_pdu_v2:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 3416 SNMP PDU to encode.
 * @error: the error object used to report errors.
 *
 * Decodes an RFC 3416 SNMP PDU from an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_pdu_v2(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guint cls, con;
    guchar *eoc;
    
    if (!gnet_snmp_ber_dec_header(asn1, &eoc,
				  &cls, &con, (guint32 *) &pdu->type, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_CTX || con != GNET_SNMP_ASN1_CON) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"PDU starts with unexpected tag %d", pdu->type); 
	}
        return FALSE;
    }
    switch (pdu->type) {
    case GNET_SNMP_PDU_GET:
    case GNET_SNMP_PDU_NEXT:
    case GNET_SNMP_PDU_RESPONSE:
    case GNET_SNMP_PDU_SET:
    case GNET_SNMP_PDU_BULK:
    case GNET_SNMP_PDU_INFORM:
    case GNET_SNMP_PDU_TRAP:
	if (!gnet_snmp_ber_dec_standard_pdu(asn1, pdu, error))
	    return FALSE;
	break;
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"illegal PDU type %d", pdu->type);
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_enc_pdu_v3:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 3416 SNMP PDU to encode.
 * @error: the error object used to report errors.
 *
 * Encodes an RFC 3412 scoped PDU as an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_enc_pdu_v3(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guchar *eoc, *end;

    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
        return FALSE;

    if (!gnet_snmp_ber_enc_pdu_v2(asn1, pdu, error))
	return FALSE;

    if (!gnet_snmp_ber_enc_octets(asn1, &end,
				  pdu->context_name, pdu->context_name_len,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_octets(asn1, &end,
			  pdu->context_engineid, pdu->context_engineid_len,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS,
				  error))
        return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI,
				  GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ,
				  error))
        return FALSE;
    return TRUE;
}

/**
 * gnet_snmp_ber_dec_pdu_v3:
 * @asn1: the handle for the #GNetSnmpBer buffer.
 * @pdu: the RFC 3416 SNMP PDU to decode.
 * @error: the error object used to report errors.
 *
 * Decodes an RFC 3412 scoped PDU from an ASN.1 value.
 *
 * Returns: a gboolean value indicating success.
 */

gboolean 
gnet_snmp_ber_dec_pdu_v3(GNetSnmpBer *asn1, GNetSnmpPdu *pdu, GError **error)
{
    guint cls, con, tag;
    guchar *eoc, *end;

    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
        return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_CON
	|| tag != GNET_SNMP_ASN1_SEQ) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"Scoped PDU starts with unexpected tag %d", tag); 
	}
        return FALSE;
    }

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_OTS) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"contextEngineID starts with unexpected tag %d", tag); 
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_octets(asn1, end, &pdu->context_engineid,
				  &pdu->context_engineid_len, error))
        return FALSE;

    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI
	|| con != GNET_SNMP_ASN1_PRI
	|| tag != GNET_SNMP_ASN1_OTS) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_BER_ERROR,
			GNET_SNMP_BER_ERROR_DEC_BADVALUE,
			"contextName starts with unexpected tag %d", tag); 
	}
	return FALSE;
    }
    if (!gnet_snmp_ber_dec_octets(asn1, end, &pdu->context_name,
				  &pdu->context_name_len, error))
        return FALSE;
    
    if (!gnet_snmp_ber_dec_pdu_v2(asn1, pdu, error))
	return FALSE;

    return TRUE;
}



/* ------------------------ stuff we should get rid off ----------------- */

void (*g_snmp_list_decode_hook)(GList *list) = NULL;
void (*g_snmp_list_encode_hook)(GList *list) = NULL;
