/*
 * GNET-SNMP -- glib-based SNMP library
 *
 * Copyright (c) 2003 Juergen Schoenwaelder
 * Copyright (c) 1998 Gregory McLean & Jochen Friedrich
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

#ifndef __GNET_SNMP_USM_H__
#define __GNET_SNMP_USM_H__

#include "gsnmp.h"

typedef enum {
    GNET_SNMP_SECMODEL_ANY	= 0,
    GNET_SNMP_SECMODEL_SNMPV1	= 1,
    GNET_SNMP_SECMODEL_SNMPV2C	= 2,
    GNET_SNMP_SECMODEL_SNMPV3	= 3
} GNetSnmpSecModel;

typedef enum {
    GNET_SNMP_SECLEVEL_NANP	= 0,
    GNET_SNMP_SECLEVEL_ANP	= 1,
    GNET_SNMP_SECLEVEL_AP	= 2
} GNetSnmpSecLevel;

/* Security models as in RFC2271, page 39 */

#define SMODEL_ANY     0
#define SMODEL_SNMPV1  1
#define SMODEL_SNMPV2C 2
#define SMODEL_USM     3

#define SLEVEL_NANP    0
#define SLEVEL_ANP     1
#define SLEVEL_AP      3

struct g_security
  {
    gboolean (*generateRequestMsg) ();
    gboolean (*processIncomingMsg) ();
    gboolean (*generateResponseMsg) ();
  };

/* Authentification types */
#define AUTH_COMMUNITY           1
#define AUTH_USEC                2

#define AUTH_COMLEN              255

/* Typedefs */

typedef struct  _SNMP_AUTH       SNMP_AUTH;

/* Authentication */

struct _SNMP_AUTH
{
    guint           type;
    guchar          name[AUTH_COMLEN];
    guint           nlen;
    guchar          ahash[20];
    guint           alen;
    guchar          phash[20];
    guint           plen;
};


void gnet_snmp_password_to_key_md5	(guchar *password, gsize password_len,
					 guchar *key, gsize *keylen);
void gnet_snmp_localize_key_md5		(guchar *key, gsize *keylen,
					 guchar *engineID, gsize engineID_len);

void gnet_snmp_password_to_key_sha	(guchar *password, gsize password_len,
					 guchar *key, gsize *keylen);
void gnet_snmp_localize_key_sha		(guchar *key, gsize *keylen,
					 guchar *engineID, gsize engineID_len);

#endif /* __GNET_SNMP_USM_H__ */
