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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

#include "gsnmp.h"

#include <stdio.h>	/* for printf xxx should not be used here xxx */

/* This module defines the API to the SNMP RFC layer. Requests are routed
 * to the appropriate transport (e.g. IPv4 or IPv6 or IPX) by using the
 * message processing compatible with the given PDU version (V1, V2C,
 * or V3). Applications will prefer to use the sync or async event loop
 * API presented by the gnet_snmp_session layer.
 */

/**
 *
 */

gboolean
gnet_snmp_dispatcher_send_pdu(GNetSnmpTDomain tDomain,
			      GInetAddr *tAddress,
			      GNetSnmpVersion version,
			      GNetSnmpSecModel sec_model,
			      GString *sec_name,
			      GNetSnmpSecLevel sec_level,
			      GNetSnmpPdu *pdu,
			      gboolean expect_response,
			      GError **error)
{
    GNetSnmpBer *ber;
    GNetSnmpMsg _msg, *msg = &_msg;
    guchar buffer[65536], *start;
    gsize len;
    gchar *community = NULL;
    gsize community_len = 0;

    /* construct community strings of the form 'name@context' for
       snmpv1/snmpv2c messages */

    if (pdu->context_name && pdu->context_name_len) {
	community = g_strdup_printf("%s@%s",
				    sec_name->str, pdu->context_name);
	community_len = strlen(community);
    } else {
	community = g_strdup(sec_name->str);
	community_len = strlen(community);
    }

    switch (version) {
    case GNET_SNMP_V1:
	g_assert(sec_model == GNET_SNMP_SECMODEL_SNMPV1
		|| sec_model == GNET_SNMP_SECMODEL_ANY);
	g_assert(sec_level == GNET_SNMP_SECLEVEL_NANP);
	msg->version = version;
	msg->community = (guchar *) community;
	msg->community_len = community_len;
	msg->data = (gpointer) pdu;
	break;
    case GNET_SNMP_V2C:
	g_assert(sec_model == GNET_SNMP_SECMODEL_SNMPV2C
		 || sec_model == GNET_SNMP_SECMODEL_ANY);
	g_assert(sec_level == GNET_SNMP_SECLEVEL_NANP);
	msg->version = version;
	msg->community = (guchar *) community;
	msg->community_len = community_len;
	msg->data = (gpointer) pdu;
	break;
    case GNET_SNMP_V3:
	/* xxx */
	break;
    default:
	g_assert_not_reached();
    }

    ber = gnet_snmp_ber_enc_new(buffer, sizeof(buffer));
    if (!gnet_snmp_ber_enc_msg(ber, msg, error)) {
	if (community) g_free(community);
	gnet_snmp_ber_enc_delete(ber, NULL, NULL);
	return FALSE;
    }
    if (community) g_free(community);
    gnet_snmp_ber_enc_delete(ber, &start, &len);
    
    if (!gnet_snmp_transport_send(tDomain, tAddress, start, len, error))
	return FALSE;

    return TRUE;
}

/**
 *
 */

gboolean
gnet_snmp_dispatcher_recv_msg(GNetSnmpTDomain tDomain,
			      GInetAddr *tAddress,
			      guchar *buffer,
			      gsize buffer_len,
			      GError **error)
{
    GNetSnmpBer *ber;
    GNetSnmpMsg _msg, *msg = &_msg;

    msg->data = NULL;

    ber = gnet_snmp_ber_dec_new(buffer, buffer_len);
    if (! ber) {
	return FALSE;
    }
    if (! gnet_snmp_ber_dec_msg(ber, msg, error)) {
	gnet_snmp_ber_dec_delete(ber, NULL, NULL);
	return FALSE;
    }
    gnet_snmp_ber_dec_delete(ber, NULL, NULL);

    if (msg->data) {
	GNetSnmpPdu *pdu = (GNetSnmpPdu *) msg->data;
	if (pdu->type == GNET_SNMP_PDU_RESPONSE) {
	    g_session_response_pdu(msg);
	} else {
	    /* xxx no command responder support yet */
	}
    }
   
    return TRUE;
}

/* RFC2271 defines some dispatcher primitives as standard SNMPv3 API.
 * These names do not match GNU conventions. RFC2272 defines what exactly
 * these primitives are supposed to do.
 *
 * It appears to me these primitives are mainly designed to describe
 * interfaces between objects. I.e. the "modules" of RFC2271 translate
 * to "objects" and the "primitives" translate to "public methods".
 * In this case there should be a global registry (IR?) which keeps track
 * of all known "modules" and loads them at init time. The dispatcher
 * "module" (which should be guaranteed to exist only once -> singleton)
 * must be constructed first, so the other "modules" can register themselves.
 *
 * statusInformation =
 * sendPdu(
 *         IN   transportDomain                 (guint)
 *         IN   transportAddress                (struct sockaddr *)
 *         IN   messageProcessingModel          INTEGER (0..2147483647)
 *         IN   securityModel                   INTEGER (0..2147483647)
 *         IN   securityName                    (gpointer)
 *         IN   securityLevel                   INTEGER (1,2,3)
 *         IN   contextEngineID                 OCTET STRING (SIZE(1..32))
 *         IN   contextName                     SnmpAdminString (SIZE(0..32))
 *         IN   pduVersion                      (guint)
 *         IN   PDU                             (SNMP_PDU *)
 *         IN   expectResponse                  (gboolean)
 * )
 *
 * returnResponsePdu(
 *              messageProcessingModel          INTEGER (0..2147483647)
 *              securityModel                   INTEGER (0..2147483647)
 *              securityName                    (gpointer)
 *              securityLevel                   INTEGER (1,2,3)
 *              contextEngineID                 OCTET STRING (SIZE(1..32))
 *              contextName                     SnmpAdminString (SIZE(0..32))
 *              pduVersion                      (guint)
 *              PDU                             (SNMP_PDU *)
 *              maxSizeResponseScopedPDU        INTEGER (0..2147483647)
 *              stateReference                  (gpointer)
 *              statusInformation               (gint)
 * )
 *
 * statusInformation =
 * registerContextEngineID(
 *              contextEngineID                 OCTET STRING (SIZE(1..32))
 *              pduType                         INTEGER (1,2,3,4,5,6,7)
 * )
 *
 * unregisterContextID(
 *              contextEngineID                 OCTET STRING (SIZE(1..32))
 *              pduType                         INTEGER (1,2,3,4,5,6,7)
 * )
 *
 * Callback Functions. These must be provided by the application:
 *
 * processPdu(
 *              messageProcessingModel          INTEGER (0..2147483647)
 *              securityModel                   INTEGER (0..2147483647)
 *              securityName                    (gpointer)
 *              securityLevel                   INTEGER (1,2,3)
 *              contextEngineID                 OCTET STRING (SIZE(1..32))
 *              contextName                     SnmpAdminString (SIZE(0..32))
 *              pduVersion                      (guint)
 *              PDU                             (SNMP_PDU *)
 *              maxSizeResponseScopedPDU        INTEGER (0..2147483647)
 *              stateReference                  (gpointer)
 * )
 *
 * processResponsePdu(
 *              messageProcessingModel          INTEGER (0..2147483647)
 *              securityModel                   INTEGER (0..2147483647)
 *              securityName                    (gpointer)
 *              securityLevel                   INTEGER (1,2,3)
 *              contextEngineID                 OCTET STRING (SIZE(1..32))
 *              contextName                     SnmpAdminString (SIZE(0..32))
 *              pduVersion                      (guint)
 *              PDU                             (SNMP_PDU *)
 *              statusInformation               (gint)
 *              sendPduHandle                   (int)
 * )
 */

/* 4.1.1.  Sending a Request or Notification 
 *
 * The following procedures are followed by the Dispatcher when an
 * application wants to send an SNMP PDU to another (remote)
 * application, i.e., to initiate a communication by originating a
 * message, such as one containing a request or a trap.
 *
 * 1) The application requests this using the abstract service
 *    primitive:
 *
 *     statusInformation =              -- sendPduHandle if success
 *                                      -- errorIndication if failure
 *       sendPdu(
 *       IN   transportDomain           -- transport domain to be used
 *       IN   transportAddress          -- destination network address
 *       IN   messageProcessingModel    -- typically, SNMP version
 *       IN   securityModel             -- Security Model to use
 *       IN   securityName              -- on behalf of this principal
 *       IN   securityLevel             -- Level of Security requested
 *       IN   contextEngineID           -- data from/at this entity
 *       IN   contextName               -- data from/in this context
 *       IN   pduVersion                -- the version of the PDU
 *       IN   PDU                       -- SNMP Protocol Data Unit
 *       IN   expectResponse            -- TRUE or FALSE
 *            )
 *
 * 2) If the messageProcessingModel value does not represent a Message
 *    Processing Model known to the Dispatcher, then an errorIndication
 *    (implementation-dependent) is returned to the calling application.
 *    No further processing is performed.
 *
 * 3) The Dispatcher generates a sendPduHandle to coordinate
 *    subsequent processing.
 *
 * 4) The Message Dispatcher sends the request to the version-specific
 *    Message Processing module identified by messageProcessingModel
 *    using the abstract service primitive:
 *
 *    statusInformation =              - success or error indication
 *      prepareOutgoingMessage(
 *      IN   transportDomain           -- as specified by application
 *      IN   transportAddress          -- as specified by application
 *      IN   messageProcessingModel    -- as specified by application
 *      IN   securityModel             -- as specified by application
 *      IN   securityName              -- as specified by application
 *      IN   securityLevel             -- as specified by application
 *      IN   contextEngineID           -- as specified by application
 *      IN   contextName               -- as specified by application
 *      IN   pduVersion                -- the version of the PDU
 *      IN   PDU                       -- as specified by application
 *      IN   expectResponse            -- as specified by application
 *      IN   sendPduHandle             -- as determined in step 3.
 *      OUT  destTransportDomain       -- destination transport domain
 *      OUT  destTransportAddress      -- destination transport address
 *      OUT  outgoingMessage           -- the message to send
 *      OUT  outgoingMessageLength     -- the message length
 *           )
 *
 * 5) If the statusInformation indicates an error, the errorIndication
 *    is returned to the calling application.  No further processing is
 *    performed.
 *
 * 6) If the statusInformation indicates success, the sendPduHandle is
 *    returned to the application, and the outgoingMessage is sent via
 *    the transport specified by the transportDomain to the address
 *    specified by the transportAddress.
 *
 * Outgoing Message Processing is complete.
 */

#if 0
int 
sendPdu(GNetSnmpTDomain transportDomain, GInetAddr *transportAddress,
        guint messageProcessingModel, guint securityModel,
        GString *securityName, int securityLevel,
        GString *contextEngineID, GString *contextName,
        guint pduVersion, GNetSnmpPdu *PDU, gboolean expectResponse,
	GError **error)
{
  gboolean            result;
  GNetSnmpTDomain     destTransportDomain;
  GInetAddr          *destTransportAddress;  
  gpointer            outgoingMessage;
  gsize               outgoingMessageLength;
  guint               sendPduHandle;
  struct g_message   *msg_model;

/* Currently, we return 0 for error and the handle if everything worked OK.
   It might be a bit better to make the return code a struct to return a
   better error code */

/* Search for message processing model */

  if (!message_models || !(msg_model = g_hash_table_lookup(message_models, 
      &messageProcessingModel)))
    {
      printf("No message model found!\n");
      return 0;
      /* Error reason: message processing model unknown */
    }

/* Generate a handle of -1, if SNMPv1 or SNMPv2 is used. This way, the 
   application knows there might be duplicate responses. 
   TODO: Check interop draft/RFC, if this is allowed. */

  if (messageProcessingModel < PMODEL_SNMPV3) sendPduHandle=-1;
  else sendPduHandle=id++;

  result = msg_model->prepareOutgoingMessage(transportDomain, transportAddress,
             messageProcessingModel, securityModel, securityName, 
             securityLevel, contextEngineID, contextName,
             pduVersion, PDU, expectResponse, sendPduHandle,
             &destTransportDomain, &destTransportAddress,
             &outgoingMessage, &outgoingMessageLength, error);

  if (!result)
    {
      return -1;
    }

    gnet_snmp_transport_send(destTransportDomain, destTransportAddress,
			     outgoingMessage, outgoingMessageLength, error);
    if (error) {
	g_free(outgoingMessage);
	return 0;
    }
    
    g_free(outgoingMessage);
    return sendPduHandle;
}
#endif

/* 4.1.2.  Sending a Response to the Network
 *
 * The following procedure is followed when an application wants to
 * return a response back to the originator of an SNMP Request.
 *
 * 1) An application can request this using the abstract service
 *    primitive:
 *
 *    returnResponsePDU(
 *     IN   messageProcessingModel   -- typically, SNMP version
 *     IN   securityModel            -- Security Model in use
 *     IN   securityName             -- on behalf of this principal
 *     IN   securityLevel            -- same as on incoming request
 *     IN   contextEngineID          -- data from/at this SNMP entity
 *     IN   contextName              -- data from/in this context
 *     IN   pduVersion               -- the version of the PDU
 *     IN   PDU                      -- SNMP Protocol Data Unit
 *     IN   maxSizeResponseScopedPDU -- maximum size of Response PDU
 *     IN   stateReference           -- reference to state information
 *                                   -- as presented with the request
 *     IN   statusInformation        -- success or errorIndication
 *     )                             -- (error counter OID and value
 *                                   -- when errorIndication)
 *
 * 2) The Message Dispatcher sends the request to the appropriate
 *    Message Processing Model indicated by the received value of
 *    messageProcessingModel using the abstract service primitive:
 *
 *    result =                        -- SUCCESS or errorIndication
 *     prepareResponseMessage(
 *     IN   messageProcessingModel   -- specified by application
 *     IN   securityModel            -- specified by application
 *     IN   securityName             -- specified by application
 *     IN   securityLevel            -- specified by application
 *     IN   contextEngineID          -- specified by application
 *     IN   contextName              -- specified by application
 *     IN   pduVersion               -- specified by application
 *     IN   PDU                      -- specified by application
 *     IN   maxSizeResponseScopedPDU -- specified by application
 *     IN   stateReference           -- specified by application
 *     IN   statusInformation        -- specified by application
 *     OUT  destTransportDomain      -- destination transport domain
 *     OUT  destTransportAddress     -- destination transport address
 *     OUT  outgoingMessage          -- the message to send
 *     OUT  outgoingMessageLength    -- the message length
 *          )
 *
 * 3) If the result is an errorIndication, the errorIndication is
 *    returned to the calling application.  No further processing is
 *    performed.
 *
 * 4) If the result is success, the outgoingMessage is sent over the
 *    transport specified by the transportDomain to the address
 *    specified by the transportAddress.
 *
 * Message Processing is complete.
 */

#if 0
gboolean
returnResponsePdu(guint messageProcessingModel, guint securityModel,
                  GString *securityName, int securityLevel, 
                  GString *contextEngineID, GString *contextName, 
                  guint pduVersion, GNetSnmpPdu *PDU, int maxSizeResponseScopedPDU,
                  gpointer stateReference, int statusInformation,
		  GError **error)
{
  gboolean            result;
  GNetSnmpTDomain     destTransportDomain;
  GInetAddr          *destTransportAddress;
  gpointer            outgoingMessage;
  gsize               outgoingMessageLength;
  struct g_message   *msg_model;

  if (!message_models || !(msg_model = g_hash_table_lookup(message_models,
      &messageProcessingModel)))
    return FALSE;

  result = msg_model->prepareResponseMessage(messageProcessingModel, 
             securityModel, securityName, securityLevel, contextEngineID, 
             contextName, pduVersion, PDU, maxSizeResponseScopedPDU,
             stateReference, statusInformation,
             &destTransportDomain, &destTransportAddress,
             &outgoingMessage, &outgoingMessageLength);

  if (!result) return FALSE;

    gnet_snmp_transport_send(destTransportDomain, destTransportAddress,
			     outgoingMessage, outgoingMessageLength, error);
    if (error) {
	g_free(outgoingMessage);
	return FALSE;
    }

  g_free(outgoingMessage);
  return TRUE;
}
#endif

#if 0
gboolean
g_register_message(guint model_nr, struct g_message *msg)
{
  guint *ptr;

  if (g_hash_table_lookup(message_models, &model_nr)) return FALSE;
  ptr = g_malloc(sizeof(guint));
  *ptr = model_nr;
  g_hash_table_insert(message_models, ptr, msg);
  return TRUE;
}

gboolean
g_register_security(guint model_nr, struct g_security *sec)
{
  guint *ptr;

  if (g_hash_table_lookup(security_models, &model_nr)) return FALSE;
  ptr = g_malloc(sizeof(guint));
  *ptr = model_nr;
  g_hash_table_insert(security_models, ptr, sec);
  return TRUE;
}
#endif

/* 4.2.1.  Message Dispatching of received SNMP Messages
 *
 * 1) The snmpInPkts counter [RFC1907] is incremented.
 *
 * 2) The version of the SNMP message is determined in an
 *    implementation-dependent manner.  If the packet cannot be
 *    sufficiently parsed to determine the version of the SNMP message,
 *    then the snmpInASNParseErrs [RFC1907] counter is incremented, and
 *    the message is discarded without further processing.  If the
 *    version is not supported, then the snmpInBadVersions [RFC1907]
 *    counter is incremented, and the message is discarded without
 *    further processing.
 *
 * 3) The origin transportDomain and origin transportAddress are
 *    determined.
 *
 * 4) The message is passed to the version-specific Message Processing
 *    Model which returns the abstract data elements required by the
 *    Dispatcher.  This is performed using the abstract service
 *    primitive:
 *
 *    result =                        -- SUCCESS or errorIndication
 *      prepareDataElements(
 *      IN   transportDomain          -- origin as determined in step 3.
 *      IN   transportAddress         -- origin as determined in step 3.
 *      IN   wholeMsg                 -- as received from the network
 *      IN   wholeMsgLength           -- as received from the network
 *      OUT  messageProcessingModel   -- typically, SNMP version
 *      OUT  securityModel            -- Security Model to use
 *      OUT  securityName             -- on behalf of this principal
 *      OUT  securityLevel            -- Level of Security requested
 *      OUT  contextEngineID          -- data from/at this entity
 *      OUT  contextName              -- data from/in this context
 *      OUT  pduVersion               -- the version of the PDU
 *      OUT  PDU                      -- SNMP Protocol Data Unit
 *      OUT  pduType                  -- SNMP PDU type
 *      OUT  sendPduHandle            -- handle for a matched request
 *      OUT  maxSizeResponseScopedPDU -- maximum size of Response PDU
 *      OUT  statusInformation        -- success or errorIndication
 *                                    -- (error counter OID and value
 *                                    -- when errorIndication)
 *      OUT  stateReference           -- reference to state information
 *                                    -- to be used for a possible
 *           )                        -- Response
 *
 * 5) If the result is a FAILURE errorIndication, the message is
 *    discarded without further processing.
 *
 * 6) At this point, the abstract data elements have been prepared and
 *    processing continues as described in Section 4.2.2, PDU
 *    Dispatching for Incoming Messages.
 */

#if 0
void
g_receive_message(GNetSnmpTDomain transportDomain, GInetAddr *transportAddress,
                  gpointer wholeMsg, guint wholeMsgLength)
{
  GNetSnmpBer *asn1;
  guint cls, con, tag;
  gint32 version;
  guchar *eoc, *end;
  struct g_message *msg_model;
  guint messageProcessingModel;
  guint securityModel;
  GString *securityName;
  int securityLevel;
  GString *contextEngineID;
  GString *contextName;
  guint pduVersion;
  GNetSnmpPdu PDU;
  guint pduType;
  int sendPduHandle;
  guint maxSizeResponseScopedPDU;
  guint statusInformation;
  gpointer stateReference;
  gint result;

  GError *error = NULL;

/* 
 * snmpInPkts ++;
 */

  asn1 = gnet_snmp_ber_dec_new(wholeMsg, wholeMsgLength);
  if (! asn1) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, NULL)) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_CON || tag != GNET_SNMP_ASN1_SEQ) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, NULL)) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_INT) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  if (!gnet_snmp_ber_dec_gint32(asn1, end, &version, NULL)) {
      gnet_snmp_ber_dec_delete(asn1, NULL, NULL);
      return;
  }
  gnet_snmp_ber_dec_delete(asn1, NULL, NULL);

  if (!message_models)
    return;

  if (!(msg_model = g_hash_table_lookup(message_models, 
      &version))) 
    return;

  result = msg_model->prepareDataElements(transportDomain, transportAddress, 
             wholeMsg, wholeMsgLength, &messageProcessingModel, &securityModel,
             &securityName, &securityLevel, &contextEngineID, &contextName,
             &pduVersion, &PDU, &pduType, &sendPduHandle, 
             &maxSizeResponseScopedPDU, &statusInformation, &stateReference,
	     &error);
  if (!result) {
      g_warning("message processing failed: %s", error->message);
      return;
  }

/* 4.2.2.  PDU Dispatching for Incoming Messages
 *
 * The elements of procedure for the dispatching of PDUs depends on the
 * value of sendPduHandle.  If the value of sendPduHandle is <none>,
 * then this is a request or notification and the procedures specified
 * in Section 4.2.2.1 apply.  If the value of snmpPduHandle is not
 * <none>, then this is a response and the procedures specified in
 * Section 4.2.2.2 apply.
 */

  if (sendPduHandle)
    {

/* 4.2.2.2.  Incoming Responses
 *
 * The following procedures are followed for the dispatching of PDUs
 * when the value of sendPduHandle is not <none>, indicating this is a
 * response.
 *
 *    1) The value of sendPduHandle is used to determine, in an
 *       implementation-defined manner, which application is waiting for
 *       a response PDU associated with this sendPduHandle.
 *
 *    2) If no waiting application is found, the message is discarded
 *       without further processing, and the stateReference is released.
 *       The snmpUnknownPDUHandlers counter is incremented.  Message
 *       Processing is complete for this message.
 *
 *    3) Any cached information, including stateReference, about the
 *       message is discarded.
 *
 *    4) The response is dispatched to the application using the
 *       abstract service primitive:
 *
 *       processResponsePdu(              -- process Response PDU
 *         IN   messageProcessingModel    -- provided by the MP module
 *         IN   securityModel             -- provided by the MP module
 *         IN   securityName              -- provided by the MP module
 *         IN   securityLevel             -- provided by the MP module
 *         IN   contextEngineID           -- provided by the MP module
 *         IN   contextName               -- provided by the MP module
 *         IN   pduVersion                -- provided by the MP module
 *         IN   PDU                       -- provided by the MP module
 *         IN   statusInformation         -- provided by the MP module
 *         IN   sendPduHandle             -- provided by the MP module
 *              )
 *
 *       Message Processing is complete for this message.
 */

/* FIXME: This should be handled through a hash table instead of sending 
          all to g_session_response_pdu */
 
      g_session_response_pdu(messageProcessingModel, securityModel,
        securityName, securityLevel, contextEngineID, contextName, 
        pduVersion, &PDU);
      g_free(securityName->str);
      g_free(securityName);
    }
  else
    {

/* 4.2.2.1.  Incoming Requests and Notifications
 * 
 * The following procedures are followed for the dispatching of PDUs
 * when the value of sendPduHandle is <none>, indicating this is a
 * request or notification.
 *
 * 1) The combination of contextEngineID and pduType is used to
 *    determine which application has registered for this request or
 *    notification.
 *
 * 2) If no application has registered for the combination, then
 *
 *    a) The snmpUnknownPDUHandlers counter is incremented.
 *
 *    b) A Response message is generated using the abstract service
 *       primitive:
 *
 *       result =                         -- SUCCESS or FAILURE
 *       prepareResponseMessage(
 *       IN   messageProcessingModel    -- as provided by MP module
 *       IN   securityModel             -- as provided by MP module
 *       IN   securityName              -- as provided by MP module
 *       IN   securityLevel             -- as provided by MP module
 *       IN   contextEngineID           -- as provided by MP module
 *       IN   contextName               -- as provided by MP module
 *       IN   pduVersion                -- as provided by MP module
 *       IN   PDU                       -- as provided by MP module
 *       IN   maxSizeResponseScopedPDU  -- as provided by MP module
 *       IN   stateReference            -- as provided by MP module
 *       IN   statusInformation         -- errorIndication plus
 *                                      -- snmpUnknownPDUHandlers OID
 *                                      -- value pair.
 *       OUT  transportDomain           -- destination transportDomain
 *       OUT  transportAddress          -- destination transportAddress
 *       OUT  outgoingMessage           -- the message to send
 *       OUT  outgoingMessageLength     -- its length
 *       )
 *
 *    c) If the result is SUCCESS, then the prepared message is sent to
 *       the originator of the request as identified by the
 *       transportDomain and transportAddress.
 *
 *    d) The incoming message is discarded without further processing.
 *       Message Processing for this message is complete.
 *
 * 3) The PDU is dispatched to the application, using the abstract
 *    service primitive:
 *
 *    processPdu(                     -- process Request/Notification
 *      IN   messageProcessingModel   -- as provided by MP module
 *      IN   securityModel            -- as provided by MP module
 *      IN   securityName             -- as provided by MP module
 *      IN   securityLevel            -- as provided by MP module
 *      IN   contextEngineID          -- as provided by MP module
 *      IN   contextName              -- as provided by MP module
 *      IN   pduVersion               -- as provided by MP module
 *      IN   PDU                      -- as provided by MP module
 *      IN   maxSizeResponseScopedPDU -- as provided by MP module
 *      IN   stateReference           -- as provided by MP module
 *                                    -- needed when sending response
 *           )
 *
 *    Message processing for this message is complete.
 */

      /*
       * snmpUnknownPDUHandlers ++;
       */

      /*
      result = prepareResponseMessage(messageProcessingModel, securityModel,
                 securityName, securityLevel, contextEngineID, contextName,
                 pduVersion, PDU, maxSizeResponseScopedPDU, stateReference,
                 ERROR-???, &transportDomain, &transportAddress, 
                 &outgoingMessage, &outgoingMessageLength);
      if (result)
        {
          if (!transport_models)
            return;

          if (!(trp_model = g_hash_table_lookup(transport_models,
            &destTransportDomain)))
            return;

          trp_model->sendMessage(destTransportAddress, outgoingMessage, 
                                 outgoingMessageLength);
          g_free(outgoingMessage);
        }
      return;
      */;
    }
}
#endif

/* 4.3.  Application Registration for Handling PDU types
 *
 * Applications that want to process certain PDUs must register with the
 * PDU Dispatcher. Applications specify the combination of
 * contextEngineID and pduType(s) for which they want to take
 * responsibility
 *
 * 1) An application registers according to the abstract interface
 *    primitive:
 *
 *    statusInformation =           -- success or errorIndication
 *      registerContextEngineID(
 *      IN   contextEngineID        -- take responsibility for this one
 *      IN   pduType                -- the pduType(s) to be registered
 *           )
 *
 *    Note: implementations may provide a means of requesting
 *    registration for simultaneous multiple contextEngineID values,
 *    e.g., all contextEngineID values, and may also provide means for
 *    requesting simultaneous registration for multiple values of
 *    pduType.
 *
 * 2) The parameters may be checked for validity; if they are not, then
 *    an errorIndication (invalidParameter) is returned to the
 *    application.
 *
 * 3) Each combination of contextEngineID and pduType can be registered
 *    only once.  If another application has already registered for the
 *    specified combination, then an errorIndication (alreadyRegistered)
 *    is returned to the application.
 *
 * 4) Otherwise, the registration is saved so that SNMP PDUs can be
 *    dispatched to this application.
 */

/* 4.4.  Application Unregistration for Handling PDU Types
 *
 * Applications that no longer want to process certain PDUs must
 * unregister with the PDU Dispatcher.
 *
 * 1) An application unregisters using the abstract service primitive:
 *
 *    unregisterContextEngineID(
 *     IN   contextEngineID        -- give up responsibility for this
 *     IN   pduType                -- the pduType(s) to be unregistered
 *           )
 *    Note: implementations may provide means for requesting
 *    unregistration for simultaneous multiple contextEngineID values,
 *    e.g., all contextEngineID values, and may also provide means for
 *    requesting simultaneous unregistration for multiple values of
 *    pduType.
 *
 * 2) If the contextEngineID and pduType combination has been
 *    registered, then the registration is deleted.
 *
 *    If no such registration exists, then the request is ignored.
 */

/* EOF */
