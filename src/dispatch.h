/*
 * $Id$
 * GXSNMP -- An snmp management application
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
 * Implementation of a SNMP dispatcher as of RFC2271
 */

#ifndef __GNET_SNMP_DISPATCH_H__
#define __GNET_SNMP_DISPATCH_H__

#include "gsnmp.h"

gboolean gnet_snmp_dispatcher_send_pdu	(GNetSnmpTAddress *tAddress,
					 GNetSnmpVersion version,
					 GNetSnmpSecModel sec_model,
					 GString *sec_name,
					 GNetSnmpSecLevel sec_level,
					 GNetSnmpPdu *pdu,
					 gboolean expect_response,
					 GError **error);

gboolean gnet_snmp_dispatcher_recv_msg	(GNetSnmpTAddress *tAddress,
					 guchar *msg,
					 gsize msg_len,
					 GError **error);

#if 0
/* This module defines the API to the SNMP RFC layer. Requests are routed
 * to the appropriate transport (e.g. IPv4 or IPv6 or IPX) by using the
 * message processing compatible with the given PDU version (V1, V2C,
 * or V3). Applications will prefer to use the sync or async event loop
 * API presented by the g_session layer.
 */

typedef void (*GXINITCB) (guint r_socket, void (*receiveMessage) ());

int sendPdu(GNetSnmpTAddress *transportAddress,
            guint messageProcessingModel, guint securityModel,
            GString *securityName, int securityLevel,
            GString *contextEngineID, GString *contextName,
            guint pduVersion, GNetSnmpPdu *PDU, gboolean expectResponse,
	    GError **error);

gboolean returnResponsePdu(guint messageProcessingModel, guint securityModel,
            GString *securityName, int securityLevel, 
            GString *contextEngineID, GString *contextName, 
            guint pduVersion, GNetSnmpPdu *PDU, int maxSizeResponseScopedPDU,
            gpointer stateReference, int statusInformation, GError **error);

void g_receive_message(GNetSnmpTAddress *transportAddress,
            gpointer wholeMsg, guint wholeMsgLength);

gboolean g_register_message   (guint model_nr, struct g_message *msg);
gboolean g_register_security  (guint model_nr, struct g_security *sec);

#define PDUV1 1
#define PDUV2 2
#endif

#endif /* __GNET_SNMP_DISPATCH_H__ */
