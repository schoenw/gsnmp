/*
 * GSNMP -- glib-based SNMP library
 *
 * Copyright (C) 2003 Juergen Schoenwaelder
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
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

#ifndef __GNET_SNMP_MSG_H__
#define __GNET_SNMP_MSG_H__

#include "gsnmp.h"

typedef enum {
    GNET_SNMP_V1    = 0,
    GNET_SNMP_V2C   = 1,
    GNET_SNMP_V2P   = 2,	/* historic, not supported */
    GNET_SNMP_V3    = 3
} GNetSnmpVersion;


typedef struct _GNetSnmpMsg GNetSnmpMsg;

struct _GNetSnmpMsg {
    gint32	version;		/** version (RFC 1157, RFC 1901, RFC 3412) */
    guchar	*community;		/** community (RFC 1157, RFC 1901) */
    gsize	community_len;		/** community (RFC 1157, RFC 1901) */
    gint32	msgid;			/** msgID (RFC 3412) */
    gint32	msg_max_size;		/** msgMaxSize (RFC 3412) */
    guint8	msg_flags;		/** msgFlags (RFC 3412) */
    gint32	msg_security_model;	/** msgMaxSize (RFC 3412) */
    gpointer	data;			/** typically an SNMP PDU */
};

gboolean gnet_snmp_ber_enc_msg	(GNetSnmpBer *ber, GNetSnmpMsg *msg,
				 GError **error);
gboolean gnet_snmp_ber_dec_msg	(GNetSnmpBer *ber, GNetSnmpMsg *msg,
				 GError **error);


/* Processing Models as in RFC2271, page 40 */

#define PMODEL_SNMPV1  0
#define PMODEL_SNMPV2C 1
#define PMODEL_SNMPV2  2
#define PMODEL_SNMPV3  3

struct g_message
  {
     gboolean (*prepareOutgoingMessage) (
                         GNetSnmpTAddress *transportAddress,
                         guint messageProcessingModel, 
                         guint securityModel,
                         GString *securityName, 
                         int securityLevel,
                         GString *contextEngineID, 
                         GString *contextName,
                         guint pduVersion, 
                         GNetSnmpPdu *PDU,
                         gboolean expectResponse, 
                         int sendPduHandle,
                         GNetSnmpTAddress **outTransportAddress,
                         gpointer *outgoingMessage,
                         gsize *outgoingMessageLength,
			 GError **error);
     gboolean (*prepareResponseMessage) (
                         guint messageProcessingModel,
                         guint securityModel, 
                         GString *securityName,
                         int securityLevel, 
                         GString *contextEngineID,
                         GString *contextName, 
                         guint pduVersion, 
                         GNetSnmpPdu *PDU,
                         guint maxSizeResponseScopedPDU,
                         gpointer stateReference, 
                         guint statusInformation,
                         GNetSnmpTAddress **outTransportAddress,
                         gpointer *outgoingMessage,
                         gsize *outgoingMessageLength);
     gboolean (*prepareDataElements) (
                         GNetSnmpTAddress *transportAddress,
                         gpointer wholeMsg, 
                         gsize wholeMsgLength,
                         guint *messageProcessingModel, 
                         guint *securityModel,
                         GString **securityName, 
                         int *securityLevel,
                         GString **contextEngineID, 
                         GString **contextName,
                         guint *pduVersion, 
                         GNetSnmpPdu *PDU, 
                         guint *pduType,
                         int *sendPduHandle,
                         guint *maxSizeResponseScopedPDU,
                         guint *statusInformation, 
                         gpointer *stateReference,
			 GError **error);
     gboolean (*releaseState) (
                         gpointer stateReference);
  };


#endif /* __GNET_SNMP_MSG_H__ */
