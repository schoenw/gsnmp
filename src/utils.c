/*
 * GNET-SNMP -- glib-based SNMP implementation
 *
 * Copyright (C) 2003 Juergen Schoenwaelder
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Copyright (C) 1993 DNPAP Beholder Group
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
 * Foundation, Inc.,  59 Temple Place - Suite 330, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

#include "gsnmp.h"

#include <stdlib.h>


GNetSnmpEnum const gnet_snmp_enum_version_table[] = {
    { GNET_SNMP_V1,	"SNMPv1" },
    { GNET_SNMP_V2C,	"SNMPv2c" },
    { GNET_SNMP_V3,	"SNMPv3" },
    { 0, 0 }
};



GNetSnmpEnum const gnet_snmp_enum_error_table[] = {
    { GNET_SNMP_ERR_DONE,		"done" },
    { GNET_SNMP_ERR_PROCEDURE,		"procedureError" },
    { GNET_SNMP_ERR_INTERNAL,		"internalError" },
    { GNET_SNMP_ERR_NORESPONSE,		"noResponse" },
    { GNET_SNMP_ERR_NOERROR,		"noError" },
    { GNET_SNMP_ERR_TOOBIG,		"tooBig" },
    { GNET_SNMP_ERR_NOSUCHNAME,		"noSuchName"},
    { GNET_SNMP_ERR_BADVALUE,		"badValue" },
    { GNET_SNMP_ERR_READONLY,		"readOnly" },
    { GNET_SNMP_ERR_GENERROR,		"genErr" },
    { GNET_SNMP_ERR_NOACCESS,		"noAccess" },
    { GNET_SNMP_ERR_WRONGTYPE,		"wrongType" },
    { GNET_SNMP_ERR_WRONGLENGTH,	"wrongLength" },
    { GNET_SNMP_ERR_WRONGENCODING,	"wrongEncoding" },
    { GNET_SNMP_ERR_WRONGVALUE,		"wrongValue" },
    { GNET_SNMP_ERR_NOCREATION,		"noCreation" },
    { GNET_SNMP_ERR_INCONSISTENTVALUE,	"inconsistentValue" },
    { GNET_SNMP_ERR_RESOURCEUNAVAILABLE,"resourceUnavailable" },
    { GNET_SNMP_ERR_COMMITFAILED,	"commitFailed" },
    { GNET_SNMP_ERR_UNDOFAILED,		"undoFailed" },
    { GNET_SNMP_ERR_AUTHORIZATIONERROR,	"authorizationError" },
    { GNET_SNMP_ERR_NOTWRITABLE,	"notWritable" },
    { GNET_SNMP_ERR_INCONSISTENTNAME,	"inconsistentName" },
    { 0, 0 }
};



GNetSnmpEnum const gnet_snmp_enum_type_table[] = {
    { GNET_SNMP_VARBIND_TYPE_NULL,		"NULL" },
    { GNET_SNMP_VARBIND_TYPE_OCTETSTRING,	"OctetString" },
    { GNET_SNMP_VARBIND_TYPE_OBJECTID,		"ObjectIdentifier" },
    { GNET_SNMP_VARBIND_TYPE_IPADDRESS,		"IpAddress" },
    { GNET_SNMP_VARBIND_TYPE_INTEGER32,		"Integer32" },
    { GNET_SNMP_VARBIND_TYPE_UNSIGNED32,	"Unsigned32" },
    { GNET_SNMP_VARBIND_TYPE_COUNTER32,		"Counter32" },
    { GNET_SNMP_VARBIND_TYPE_TIMETICKS,		"TimeTicks" },
    { GNET_SNMP_VARBIND_TYPE_OPAQUE,		"Opaque" },
    { GNET_SNMP_VARBIND_TYPE_COUNTER64,		"Counter64" },
    { GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT,	"NoSuchObject" },
    { GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE,	"NoSuchInstance" },
    { GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW,	"EndOfMibView" },
    { 0, 0 }
};



GNetSnmpEnum const gnet_snmp_enum_pdu_table[] = {
    { GNET_SNMP_PDU_GET,	"get" },
    { GNET_SNMP_PDU_NEXT,	"getnext" },
    { GNET_SNMP_PDU_RESPONSE,	"response" },
    { GNET_SNMP_PDU_SET,	"set" },
    { GNET_SNMP_PDU_TRAP,	"trap" },
    { GNET_SNMP_PDU_BULK,	"getbulk" },
    { GNET_SNMP_PDU_INFORM,	"inform" },
    { 0, 0 }
};



GNetSnmpEnum const gnet_snmp_enum_debug_table[] = {
    { GNET_SNMP_DEBUG_REQUESTS,	"request" },
    { GNET_SNMP_DEBUG_SESSION,	"session" },
    { GNET_SNMP_DEBUG_TRANSPORT,"transport" },
    { GNET_SNMP_DEBUG_PACKET,	"packet" },
    { GNET_SNMP_DEBUG_BER,	"ber" },
    { 0, 0 }
};



GNetSnmpEnum const gnet_snmp_enum_tdomain_table[] = {
    { GNET_SNMP_TDOMAIN_NONE,	"none" },
    { GNET_SNMP_TDOMAIN_UDP_IPV4,	"udp/ipv4" },
    { GNET_SNMP_TDOMAIN_UDP_IPV6,	"udp/ipv6" },
    { GNET_SNMP_TDOMAIN_IPX,		"ipx" },
    { GNET_SNMP_TDOMAIN_TCP_IPV4,	"tcp/ipv4" },
    { GNET_SNMP_TDOMAIN_TCP_IPV6,	"tcp/ipv6" },
    { 0, 0 }
};



gchar const *
gnet_snmp_enum_get_label(GNetSnmpEnum const *table, gint32 const id)
{
    int i;

    for (i = 0; table[i].label; i++) {
	if (id == table[i].number) {
	    return table[i].label;
	}
    }

    return NULL;
}



gboolean
gnet_snmp_enum_get_number(GNetSnmpEnum const *table,
			  gchar const *str, gint32 *number)
{
    int i;

    for (i = 0; table[i].label; i++) {
	if (strcmp(str, table[i].label) == 0) {
	    if (number) *number = table[i].number;
	    return TRUE;
	}
    }

    return FALSE;
}



gchar const *
gnet_snmp_identity_get_label(GNetSnmpIdentity const *table,
			 guint32 const *oid, gsize oidlen)
{
    int i;

    if (! oid || oidlen <= 0) {
	return NULL;
    }

    for (i = 0; table[i].label; i++) {
	if (table[i].oidlen == oidlen
	    && memcmp(table[i].oid, oid, oidlen * sizeof(guint32)) == 0) {
	    return table[i].label;
	}
    }

    return NULL;
}



int
gnet_snmp_attr_assign(GList *vbl,
		      guint32 const *base, size_t const len,
		      const GNetSnmpAttribute *attributes,
		      const gpointer p)
{
    GList *elem;
    int i, n = 0;
    gpointer **gp;

    if (!p) {
	return 0;
    }

    for (elem = vbl; elem; elem = g_list_next(elem)) {
	 GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;

	 if (vb->type == GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW
	     || (vb->type == GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT)
	     || (vb->type == GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE)) {
	      continue;
	 }
    
	 if (memcmp(vb->oid, base, len * sizeof(guint32)) != 0) {
	      continue;
	 }

	 for (i = 0; attributes[i].label; i++) {
	      if (vb->oid_len > len && vb->oid[len] == attributes[i].subid) {
		   break;
	      }
	 }

	 if (! attributes[i].label) {
	      continue;
	 }

#define CLASS_INT(x) (x == GNET_SNMP_VARBIND_TYPE_INTEGER32 || x == GNET_SNMP_VARBIND_TYPE_UNSIGNED32 || x == GNET_SNMP_VARBIND_TYPE_COUNTER32 || x == GNET_SNMP_VARBIND_TYPE_TIMETICKS)

 #define CLASS_STRING(x) (x == GNET_SNMP_VARBIND_TYPE_OCTETSTRING || x == GNET_SNMP_VARBIND_TYPE_IPADDRESS || x == GNET_SNMP_VARBIND_TYPE_OPAQUE)

	 if (vb->type != attributes[i].type) {
	      const char *a = gnet_snmp_enum_get_label(gnet_snmp_enum_type_table,
						   vb->type);
	      const char *b = gnet_snmp_enum_get_label(gnet_snmp_enum_type_table,
						   attributes[i].type);
	      if ((a && b)
		  && ((CLASS_INT(vb->type)
		       && CLASS_INT(attributes[i].type))
		      || (CLASS_STRING(vb->type)
			  && CLASS_STRING(attributes[i].type)))) {
		  g_warning("%s: type mismatch: converting %s to %s",
			    attributes[i].label, a, b);
	      } else {
		  if (a && b) {
		      g_warning("%s: type mismatch: cannot convert %s to %s",
				attributes[i].label, a, b);
		  } else {
		      g_warning("%s: type mismatch", attributes[i].label);
		  }
		  continue;
	      }
	 }

	 if (attributes[i].val_offset < 0) {
	     continue;
	 }
	 gp = G_STRUCT_MEMBER_P(p, attributes[i].val_offset);
	 switch (vb->type) {
	 case GNET_SNMP_VARBIND_TYPE_INTEGER32:
	     if (attributes[i].constraints) {
		 gint32 *range = (gint32 *) attributes[i].constraints;
		 while (range[0] != 0 || range[1] != 0) {
		     if (vb->value.i32 >= range[0]
			 && vb->value.i32 <= range[1]) {
			 break;
		     }
		     range += 2;
		 }
		 if (range[0] == 0 && range[1] == 0) {
		     g_warning("%s: value not within range contraints",
			       attributes[i].label);
		     gp = NULL;
		 }
	     }
	     if (gp) *gp = (gpointer) &(vb->value.i32);
	     break;
	 case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
	 case GNET_SNMP_VARBIND_TYPE_COUNTER32:
	 case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	     if (attributes[i].constraints) {
		 guint32 *range = (guint32 *) attributes[i].constraints;
		 while (range[0] != 0 || range[1] != 0) {
		     if (vb->value.i32 >= range[0]
			 && vb->value.i32 <= range[1]) {
			 break;
		     }
		     range += 2;
		 }
		 if (range[0] == 0 && range[1] == 0) {
		     g_warning("%s: value not within range contraints",
			       attributes[i].label);
		     gp = NULL;
		 }
	     }
	     if (gp) *gp = (gpointer) &(vb->value.ui32);
	     break;
	 case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	     if (attributes[i].constraints) {
		 guint16 *size = (guint16 *) attributes[i].constraints;
		 while (size[0] != 0 || size[1] != 0) {
		     if (vb->value_len >= size[0]
			 && vb->value_len <= size[1]) {
			 break;
		     }
		     size += 2;
		 }
		 if (size[0] == 0 && size[1] == 0) {
		     g_warning("%s: value not within size contraints",
			       attributes[i].label);
		     gp = NULL;
		 }
	     }
	     if (gp) *gp = (gpointer) vb->value.ui8v;
	     break;
	 case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	 case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
	 case GNET_SNMP_VARBIND_TYPE_OPAQUE:
	     *gp = (gpointer) vb->value.ui32;
	     break;
	 case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	     if (gp) *gp = (gpointer) &(vb->value.ui64);
	     break;
	 default:
	     break;
	 }
	 if (gp && attributes[i].len_offset) {
	     guint16 *lp;
	     lp = (guint16 *) G_STRUCT_MEMBER_P(p, attributes[i].len_offset);
	     *lp = vb->value_len;
	 }
	 n++;
    }

    return n;
}



void
gnet_snmp_attr_get(const GNetSnmp *s, GList **vbl,
		   guint32 *base, size_t const len,
		   guint const idx,
		   const GNetSnmpAttribute *attributes,
		   const gint64 mask)
{
    GNetSnmpVarBind *vb;
    int i;
    
    for (i = 0; attributes[i].label; i++) {
	if (mask && !(mask & attributes[i].tag)) {
	    continue;
	}
	if (attributes[i].type == GNET_SNMP_VARBIND_TYPE_COUNTER64
	    && s->version == GNET_SNMP_V1) {
	    continue;
	}
	base[idx] = attributes[i].subid;
	vb = gnet_snmp_varbind_new(base, len,
				   GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
	*vbl = g_list_prepend(*vbl, vb);
    }
    *vbl = g_list_reverse(*vbl);
}



void
gnet_snmp_attr_set(const GNetSnmp *s, GList **vbl,
		   guint32 *base, size_t const len,
		   guint const idx,
		   const GNetSnmpAttribute *attributes,
		   const gint64 mask,
		   const gpointer p)
{
    GNetSnmpVarBind *vb;
    gpointer **gp;
    guint16 *lp;
    int i;

    if (!p) {
	return;
    }

    for (i = 0; attributes[i].label; i++) {
	if (mask && !(mask & attributes[i].tag)) {
	    continue;
	}
	if ((attributes[i].type == GNET_SNMP_VARBIND_TYPE_COUNTER64
	     && s->version == GNET_SNMP_V1)) {
	    continue;
	}
	if (! (attributes[i].flags & GSNMP_ATTR_FLAG_WRITABLE)) {
	    continue;
	}
	gp = G_STRUCT_MEMBER_P(p, attributes[i].val_offset);
	if (attributes[i].len_offset) {
	    lp = (guint16 *) G_STRUCT_MEMBER_P(p, attributes[i].len_offset);
	} else {
	    lp = 0;
	}
	base[idx] = attributes[i].subid;
	vb = gnet_snmp_varbind_new(base, len, attributes[i].type,
				   *gp, lp ? *lp : 0);
	*vbl = g_list_prepend(*vbl, vb);
    }
    *vbl = g_list_reverse(*vbl);
}

gint
gnet_snmp_compare_oids(guint32 *oid1, gsize len1, guint32 *oid2, gsize len2)
{
    int i, j, len;

    /* implement lexicographic ordering */
    len = len1 < len2 ? len1 : len2;
    for (i = 0, j = 0; i < len; i++, j++) {
	if (oid1[i] < oid2[i]) return -1;
	if (oid1[i] > oid2[i]) return 1;
    }

    if (len1 < len2) return -1;
    if (len2 < len1) return 1;
    return 0;
    
}
    
GURI*
gnet_snmp_parse_uri(const gchar *string)
{
    GURI *uri;
    
    g_return_val_if_fail(string, NULL);

    string = g_strdup(string);

    /* First, try to treat the string as a fully specified SNMP
       URI. If that fails, try to treat the string as something
       that looks like [name@]host. Note that simply prepending
       "snmp://" does not work well with IPv6 addresses such as "::1"
       (which still would have to be written as "[::1]"). */
    
    uri = gnet_uri_new(string);
    if (uri && !uri->scheme && !uri->hostname) {
	gnet_uri_delete(uri);
	uri = NULL;
    }
    if (uri && strcmp(uri->scheme, "snmp") != 0) {
	if (uri->hostname) {
	    gnet_uri_delete(uri);
	    goto done;
	} else {
	    gnet_uri_delete(uri);
	    uri = NULL;
	}
    }
    
    if (! uri) {
	gchar *hostname = NULL, *userinfo = NULL, *port = NULL;
	
	hostname = strchr(string, '@');
	if (hostname) {
	    userinfo = string;
	    *hostname = 0;
	    hostname++;
	} else {
	    hostname = string;
	}
	port = strchr(hostname, ':');
	if (port) {
	    *port = 0;
	    port++;
	    /* check that port is numeric? */
	}
	
	uri = gnet_uri_new_fields_all("snmp", userinfo, hostname,
				      port ? atoi(port) : 161,
				      "", NULL, NULL);
    }

    if (uri && !uri->userinfo) {
	gnet_uri_set_userinfo(uri, "public");
    }

    if (uri && uri->port == 0) {
	gnet_uri_set_port(uri, 161);
    }

 done:
    g_free(string);
    return uri;
}
