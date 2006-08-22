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

#ifndef __GNET_SNMP_PDU_H__
#define __GNET_SNMP_PDU_H__

#include "ber.h"

#define GNET_SNMP_SIZE_OBJECTID		(128)

/*
 * Distinguished SNMP varbind types as defined in RFC 3416.
 */

typedef enum {
    GNET_SNMP_VARBIND_TYPE_NULL		  = 0,
    GNET_SNMP_VARBIND_TYPE_OCTETSTRING	  = 1,
    GNET_SNMP_VARBIND_TYPE_OBJECTID	  = 2,
    GNET_SNMP_VARBIND_TYPE_IPADDRESS	  = 3,
    GNET_SNMP_VARBIND_TYPE_INTEGER32	  = 4,
    GNET_SNMP_VARBIND_TYPE_UNSIGNED32	  = 5,	/* also Gauge32 */
    GNET_SNMP_VARBIND_TYPE_COUNTER32	  = 6,
    GNET_SNMP_VARBIND_TYPE_TIMETICKS	  = 7,
    GNET_SNMP_VARBIND_TYPE_OPAQUE	  = 8,
    GNET_SNMP_VARBIND_TYPE_COUNTER64	  = 9,
    GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT   = 10,
    GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE = 11,
    GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW   = 12
} GNetSnmpVarBindType;

typedef struct  _GNetSnmpVarBind	GNetSnmpVarBind;

struct _GNetSnmpVarBind
{
    guint32		*oid;		/* name of the variable */
    gsize		oid_len;	/* length of the name */
    GNetSnmpVarBindType	type;		/* variable type / exception */
    union {
	gint32   i32;			/* 32 bit signed   */
	guint32  ui32;			/* 32 bit unsigned */
	gint64   i64;			/* 64 bit signed   */
	guint64  ui64;			/* 64 bit unsigned */
	guint8  *ui8v;			/*  8 bit unsigned vector */
	guint32 *ui32v;			/* 32 bit unsigned vector */
    }			value;		/* value of the variable */
    gsize		value_len;	/* length of a vector in bytes */
};

GNetSnmpVarBind* gnet_snmp_varbind_new	(const guint32 *oid,
					 const gsize oid_len,
					 const GNetSnmpVarBindType type,
					 const gpointer value,
					 const gsize value_len);
void     gnet_snmp_varbind_delete	(GNetSnmpVarBind *vb);

gboolean gnet_snmp_ber_enc_varbind	(GNetSnmpBer *ber,
					 GNetSnmpVarBind *vb,
					 GError **error);
gboolean gnet_snmp_ber_enc_varbind_null	(GNetSnmpBer *ber,
					 GNetSnmpVarBind *vb,
					 GError **error);
gboolean gnet_snmp_ber_dec_varbind	(GNetSnmpBer *ber,
					 GNetSnmpVarBind **vb,
					 GError **error);

/*
 * SNMP VarBindLists are represented as GLists of GNetSnmpVarBinds.
 * This allows us to use all the nice GList functions to manipulate
 * and navigate SNMP VarBindLists.
 */

gboolean gnet_snmp_ber_enc_varbind_list	(GNetSnmpBer *ber,
					 GList *list,
					 GError **error);

gboolean gnet_snmp_ber_enc_varbind_list_null(GNetSnmpBer *ber,
					     GList *list,
					     GError **error);

gboolean gnet_snmp_ber_dec_varbind_list	(GNetSnmpBer *ber,
					 GList **list,
					 GError **error);

/*
 * SNMP protocol operations as defined in RFC 3416.
 */

typedef enum {
    GNET_SNMP_PDU_GET		= 0,
    GNET_SNMP_PDU_NEXT		= 1,
    GNET_SNMP_PDU_RESPONSE	= 2,
    GNET_SNMP_PDU_SET		= 3,
    GNET_SNMP_PDU_TRAP		= 4,
    GNET_SNMP_PDU_BULK		= 5,
    GNET_SNMP_PDU_INFORM	= 6
} GNetSnmpPduType;

/*
 * SNMP protocol operation classes as defined in RFC 3411.
 */

#define GNET_SNMP_PDU_CLASS_READ(p) \
	(p == GNET_SNMP_PDU_GET || \
         p == GNET_SNMP_PDU_NEXT || \
         p == GNET_SNMP_PDU_BULK)

#define GNET_SNMP_PDU_CLASS_WRITE(p) \
	(p == GNET_SNMP_PDU_SET)

#define GNET_SNMP_PDU_CLASS_RESPONSE(p) \
	(p == GNET_SNMP_PDU_RESPONSE)

#define GNET_SNMP_PDU_CLASS_NOTIFICATION(p) \
	(p == GNET_SNMP_PDU_TRAP || p == GNET_SNMP_PDU_INFORM)

/*
 * SNMP protocol error codes as defined in RFC 3416.
 * Negative error codes are GNET-SNMP internal codes.
 */

typedef enum {
    GNET_SNMP_PDU_ERR_DONE		    = -4,
    GNET_SNMP_PDU_ERR_PROCEDURE		    = -3,
    GNET_SNMP_PDU_ERR_INTERNAL		    = -2,
    GNET_SNMP_PDU_ERR_NORESPONSE	    = -1,
    GNET_SNMP_PDU_ERR_NOERROR		    = 0,
    GNET_SNMP_PDU_ERR_TOOBIG                = 1,
    GNET_SNMP_PDU_ERR_NOSUCHNAME            = 2,
    GNET_SNMP_PDU_ERR_BADVALUE              = 3,
    GNET_SNMP_PDU_ERR_READONLY              = 4,
    GNET_SNMP_PDU_ERR_GENERROR              = 5,
    GNET_SNMP_PDU_ERR_NOACCESS              = 6,
    GNET_SNMP_PDU_ERR_WRONGTYPE             = 7,
    GNET_SNMP_PDU_ERR_WRONGLENGTH           = 8,
    GNET_SNMP_PDU_ERR_WRONGENCODING         = 9,
    GNET_SNMP_PDU_ERR_WRONGVALUE            = 10,
    GNET_SNMP_PDU_ERR_NOCREATION            = 11,
    GNET_SNMP_PDU_ERR_INCONSISTENTVALUE     = 12,
    GNET_SNMP_PDU_ERR_RESOURCEUNAVAILABLE   = 13,
    GNET_SNMP_PDU_ERR_COMMITFAILED          = 14,
    GNET_SNMP_PDU_ERR_UNDOFAILED            = 15,
    GNET_SNMP_PDU_ERR_AUTHORIZATIONERROR    = 16,
    GNET_SNMP_PDU_ERR_NOTWRITABLE           = 17,
    GNET_SNMP_PDU_ERR_INCONSISTENTNAME      = 18
} GNetSnmpPduError;

/*
 * SNMPv1 trap PDUs have a slightly different format. This library
 * implements the notification mappings defined in RFC 2576 so that
 * applications will always see the SNMPv2c/SNMPv3 notification PDU
 * format. Also note that the GNetSnmpPdu represents a scoped PDU as
 * defined in RFC 3411 and RFC 3412.
 */

typedef struct _GNetSnmpPdu	GNetSnmpPdu;

struct _GNetSnmpPdu {
    guchar	   *context_engineid;
    gsize	    context_engineid_len;
    guchar         *context_name;
    gsize           context_name_len;
    GNetSnmpPduType type;
    gint32          request_id;
    gint32          error_status;	/* holds a GNetSnmpError */
    gint32          error_index;
    GList          *varbind_list;
};

/*
 * The following encoding/decoding functions are for the different SNMP
 * protocol versions supported by this library.
 */

gboolean gnet_snmp_ber_enc_pdu_v1	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);
gboolean gnet_snmp_ber_dec_pdu_v1	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);
gboolean gnet_snmp_ber_enc_pdu_v2	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);
gboolean gnet_snmp_ber_dec_pdu_v2	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);
gboolean gnet_snmp_ber_enc_pdu_v3	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);
gboolean gnet_snmp_ber_dec_pdu_v3	(GNetSnmpBer *ber, GNetSnmpPdu *pdu,
					 GError **error);

/* ------------------------ stuff we should get rid off ----------------- */


/* SNMP hooks for debugging, profiling, statistics, ... */

extern void (*g_snmp_list_decode_hook)(GList *list);
extern void (*g_snmp_list_encode_hook)(GList *list);

#endif /* __GNET_SNMP_PDU_H__ */
