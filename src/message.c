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
 */

#include "gsnmp.h"

GNetSnmpDebugFlags gnet_snmp_debug_flags = 0;

/* This modules implements the formatting of the different SNMP versions. 
 * The interface is documented in RFC2271. 
 */

/* RFC2271 defines some message processing primitives as standard SNMPv3 API.
 * These names do not match GNU conventions. RFC2272 defines what exactly
 * these primitives are supposed to do.
 *
 * Application Interface:
 *
 * statusInformation = 
 * prepareOutgoingMessage(
 *         IN   transportDomain                 (guint)
 *         IN   transportAddress                (struct sockaddr *)
 *         IN   messageProcessingModel          INTEGER (0..2147483647)
 *         IN   securityModel                   INTEGER (0..2147483647)
 *         IN   securityName                    (GString *)
 *         IN   securityLevel                   INTEGER (1,2,3)
 *         IN   contextEngineID                 OCTET STRING (SIZE(1..32))
 *         IN   contextName                     SnmpAdminString (SIZE(0..32))
 *         IN   pduVersion                      (guint)
 *         IN   PDU                             (SNMP_PDU *)
 *         IN   expectResponse                  (gboolean)
 *         IN   sendPduHandle                   (int)
 *         OUT  destTransportDomain             (guint)
 *         OUT  destTransportAddress            (struct sockaddr)
 *         OUT  outgoingMessage                 (gpointer)
 *         OUT  outgoingMessageLength           (int)
 * )
 *
 * result =
 * prepareResponseMessage(
 *         IN   messageProcessingModel          INTEGER (0..2147483647)
 *         IN   securityModel                   INTEGER (0..2147483647)
 *         IN   securityName                    (GString *)
 *         IN   securityLevel                   INTEGER (1,2,3)
 *         IN   contextEngineID                 OCTET STRING (SIZE(1..32))
 *         IN   contextName                     SnmpAdminString (SIZE(0..32))
 *         IN   pduVersion                      (guint)
 *         IN   PDU                             (SNMP_PDU *)
 *         IN   maxSizeResponseScopedPDU        (guint)
 *         IN   stateReference                  (gpointer)
 *         IN   statusInformation               (guint)
 *         OUT  destTransportDomain             (guint)
 *         OUT  destTransportAddress            (struct sockaddr)
 *         OUT  outgoingMessage                 (gpointer)
 *         OUT  outgoingMessageLength           (int)
 * )
 *
 * prepareDataElements(
 *         IN   transportDomain                 (guint)
 *         IN   transportAddress                (struct sockaddr *)
 *         IN   wholeMsg                        (gpointer)
 *         IN   wholeMsgLength                  (int)
 *         OUT  messageProcessingModel          INTEGER (0..2147483647)
 *         OUT  securityModel                   INTEGER (0..2147483647)
 *         OUT  securityName                    (GString *)
 *         OUT  securityLevel                   INTEGER (1,2,3)
 *         OUT  contextEngineID                 OCTET STRING (SIZE(1..32))
 *         OUT  contextName                     SnmpAdminString (SIZE(0..32))
 *         OUT  pduVersion                      (guint)
 *         OUT  PDU                             (SNMP_PDU *)
 *         OUT  pduType                         (guint)
 *         OUT  sendPduHandle                   (int)
 *         OUT  maxSizeResponseScopedPDU        (guint)
 *         OUT  statusInformation               (guint)
 *         OUT  stateReference                  (gpointer)
 * )
 *
 * releaseState(
 *         IN   stateReference                  (gpointer)
 * )
 */

/* ----------------------------------------------------------------------------
 *                          SNMP V1 Message Processing Model
 * ----------------------------------------------------------------------------
 */

static gboolean
snmpv1_prepare_outgoing_message(GNetSnmpTDomain transportDomain, 
                         GInetAddr *transportAddress,
                         guint messageProcessingModel, guint securityModel,
                         GString *securityName, int securityLevel,
                         GString *contextEngineID, GString *contextName,
                         guint pduVersion, GNetSnmpPdu *PDU, 
                         gboolean expectResponse, int sendPduHandle,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage, 
                         guint *outgoingMessageLength,
		 	 GError **error)
{
    GNetSnmpBer *asn1;
    guchar *eoc, *end;
    guchar buffer[65536], *ptr;
    
    ptr    = buffer;
    *outgoingMessageLength = 65536;

    if (messageProcessingModel != PMODEL_SNMPV1)
	return FALSE; /* This should never happen. Something fishy going on? */
    if ((securityModel != SMODEL_ANY) && (securityModel != SMODEL_SNMPV1))
	return FALSE;
    if (securityLevel != SLEVEL_NANP)
	return FALSE;
    if (pduVersion != PDUV1)
	return FALSE;
    
/* FIXME: Currently, i'm pretty much cheating here. I probably *should* call
 *        the community security model to map the security name (principal)
 *        to the community name he has configured for a given router/PDU
 *        type (might be different for PUT, GET(NEXT) and TRAP). Should also
 *        check for invalid PDU, however, this should as well never happen as
 *        the PDU version matches with what we expect.
 * 
 *        Depending on the meaning of PDU (struct or ANS.1 encoded), the
 *        security model might have to decode the PDU again to get to the
 *        PDU type (PUT/GET/TRAP). This seems very odd and backward to me
 *        in some way.
 */

/* RFC1157
 * Message ::= SEQUENCE {
 *               version    INTEGER { version(0) },
 *               community  OCTET STRING,
 *               data       ANY
 *                      }
 */
    
    asn1 = gnet_snmp_ber_enc_new(ptr, *outgoingMessageLength);
    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
	return FALSE;
    
    
    if (!gnet_snmp_ber_enc_pdu_v1(asn1, PDU, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_octets (asn1, &end, (guchar *) securityName->str, securityName->len, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_guint32(asn1, &end, 0, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ, error))
	return FALSE;
    
    gnet_snmp_ber_enc_delete(asn1, &ptr, outgoingMessageLength);
    
/* FIXME: we currently don't implement proxy support. In this case 
 *        outTransportDomain and outTransportAddress are always
 *        the same as transportAddress and transportDomain.
 *
 * "Rule #1: If there's something you don't understand, it must be
 *  related to proxies" -- Juergen Schoenwaelder
 */
    
    *outTransportDomain = transportDomain;
    *outTransportAddress = transportAddress;
    
    *outgoingMessage = g_malloc(*outgoingMessageLength);
    g_memmove(*outgoingMessage, ptr, *outgoingMessageLength);
    
    return TRUE;
}

static gboolean
snmpv1_prepare_response_message(guint messageProcessingModel, 
                         guint securityModel, GString *securityName, 
                         int securityLevel, GString *contextEngineID, 
                         GString *contextName, guint pduVersion, GNetSnmpPdu *PDU,
                         guint maxSizeResponseScopedPDU,
                         gpointer stateReference, guint statusInformation,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage,
                         guint *outgoingMessageLength)
{
    if (messageProcessingModel != PMODEL_SNMPV1)
	return FALSE; /* This should never happen. Something fishy going on? */
    
    return FALSE;
}

static gboolean
snmpv1_prepare_data_elements(GNetSnmpTDomain transportDomain,
                         GInetAddr *transportAddress,
                         gpointer wholeMsg, int wholeMsgLength,
                         guint *messageProcessingModel, guint *securityModel,
                         GString **securityName, int *securityLevel,
                         GString **contextEngineID, GString **contextName,
                         guint *pduVersion, GNetSnmpPdu *PDU, guint *pduType,
                         int *sendPduHandle, guint *maxSizeResponseScopedPDU,
                         guint *statusInformation, gpointer *stateReference,
			 GError **error)
{
    GNetSnmpBer *asn1;
    guint cls, con, tag;
    guchar *eoc, *end;

    *securityModel   = SMODEL_SNMPV1;
    *securityLevel   = SLEVEL_NANP;
    *contextEngineID = NULL;
    *contextName     = NULL;
    *pduVersion      = PDUV1;
    
    *securityName = g_malloc(sizeof(GString));
    
    asn1 = gnet_snmp_ber_dec_new(wholeMsg, wholeMsgLength);
    
    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_CON || tag != GNET_SNMP_ASN1_SEQ)
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_INT)
	return FALSE;
    if (!gnet_snmp_ber_dec_guint32(asn1, end, messageProcessingModel, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_OTS)
	return FALSE;
    if (!gnet_snmp_ber_dec_octets(asn1, end, (guchar **)&((*securityName)->str), 
				  (guint *) &((*securityName)->len), error))
	return FALSE;
    if (!gnet_snmp_ber_dec_pdu_v1(asn1, PDU, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error))
	return FALSE;
    gnet_snmp_ber_dec_delete(asn1, wholeMsg, (guint *) &wholeMsgLength);
    
    if (PDU->type == GNET_SNMP_PDU_RESPONSE) 
	*sendPduHandle = -1;
    else
	*sendPduHandle = 0;
    return TRUE;
}

static gboolean
snmpv1_release_state( gpointer stateReference)
{
/* free whatever structures are in stateReference */
    if (stateReference) g_free(stateReference);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 *                          SNMP V2c Message Processing Model
 * ----------------------------------------------------------------------------
 */

static gboolean
snmpv2c_prepare_outgoing_message(GNetSnmpTDomain transportDomain, 
                         GInetAddr *transportAddress,
                         guint messageProcessingModel, guint securityModel,
                         GString *securityName, int securityLevel,
                         GString *contextEngineID, GString *contextName,
                         guint pduVersion, GNetSnmpPdu *PDU, 
                         gboolean expectResponse, int sendPduHandle,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage, 
                         guint *outgoingMessageLength,
			 GError **error)
{
    GNetSnmpBer *asn1;
    guchar *eoc, *end;
    guchar buffer[65536], *ptr;

    ptr    = buffer;
    *outgoingMessageLength = 65536;
    
    
    if (messageProcessingModel != PMODEL_SNMPV2C)
	return FALSE; /* This should never happen. Something fishy going on? */

/* We allow both SNMPV1 and SNMPV2C security models here. There currently
 * is a discussion in the SNMPv3 mailing list to rename SNMPV1 security to
 * SNMP_COMMUNITY and dump the SNMPV2C model (declaring it reserved).
 * Allowing both SNMPV1 and SNMPV2C here should make this library compatible
 * with both cases.
 */
    
    if ((securityModel != SMODEL_ANY) && (securityModel != SMODEL_SNMPV1)
	&& (securityModel != SMODEL_SNMPV2C))
	return FALSE;
    if (securityLevel != SLEVEL_NANP)
	return FALSE;
    if (pduVersion != PDUV2)
	return FALSE;
    
/* FIXME: Currently, i'm pretty much cheating here. I probably *should* call
 *        the community security model to map the security name (principal)
 *        to the community name he has configured for a given router/PDU
 *        type (might be different for PUT, GET(NEXT) and TRAP). Should also
 *        check for invalid PDU, however, this should as well never happen as
 *        the PDU version matches with what we expect.
 */

/* RFC1901
 * Message ::= SEQUENCE {
 *               version    INTEGER { version(1) },
 *               community  OCTET STRING,
 *               data       ANY
 *                      }
 */

    asn1 = gnet_snmp_ber_enc_new(ptr, *outgoingMessageLength);
    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_pdu_v2(asn1, PDU, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_octets (asn1, &end, (guchar *) securityName->str, securityName->len, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_guint32(asn1, &end, 1, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ, error))
	return FALSE;
    
    gnet_snmp_ber_enc_delete(asn1, &ptr, outgoingMessageLength);
    
/* FIXME: we currently don't implement proxy support. In this case 
 *        outTransportDomain and outTransportAddress are always
 *        the same as transportAddress and transportDomain.
 *
 * "Rule #1: If there's something you don't understand, it must be
 *  related to proxies" -- Juergen Schoenwaelder
 */
    
    *outTransportDomain = transportDomain;
    *outTransportAddress = transportAddress;
    
    *outgoingMessage = g_malloc(*outgoingMessageLength);
    g_memmove(*outgoingMessage, ptr, *outgoingMessageLength);
    
    return TRUE;
}

static gboolean
snmpv2c_prepare_response_message(guint messageProcessingModel,
                         guint securityModel, GString *securityName,
                         int securityLevel, GString *contextEngineID,
                         GString *contextName, guint pduVersion, GNetSnmpPdu *PDU,
                         guint maxSizeResponseScopedPDU,
                         gpointer stateReference, guint statusInformation,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage,
                         guint *outgoingMessageLength)
{
    return FALSE;
}

static gboolean
snmpv2c_prepare_data_elements(GNetSnmpTDomain transportDomain,
                         GInetAddr *transportAddress,
                         gpointer wholeMsg, int wholeMsgLength,
                         guint *messageProcessingModel, guint *securityModel,
                         GString **securityName, int *securityLevel,
                         GString **contextEngineID, GString **contextName,
                         guint *pduVersion, GNetSnmpPdu *PDU, guint *pduType,
                         int *sendPduHandle, guint *maxSizeResponseScopedPDU,
                         guint *statusInformation, gpointer *stateReference,
			 GError **error)
{
    GNetSnmpBer *asn1;
    guint cls, con, tag;
    guchar *eoc, *end;

    *securityModel   = SMODEL_SNMPV2C; /* might combine with SMODEL_SNMPV1 */
    *securityLevel   = SLEVEL_NANP;
    *contextEngineID = NULL;
    *contextName     = NULL;
    *pduVersion      = PDUV2;
    
    *securityName = g_malloc(sizeof(GString));
    
    asn1 = gnet_snmp_ber_dec_new(wholeMsg, wholeMsgLength);
    
    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_CON || tag != GNET_SNMP_ASN1_SEQ)
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_INT)
	return FALSE;
    if (!gnet_snmp_ber_dec_guint32(asn1, end, messageProcessingModel, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_OTS)
	return FALSE;
    if (!gnet_snmp_ber_dec_octets (asn1, end, (guchar **)&((*securityName)->str), 
				   (guint *) &((*securityName)->len), error))
	return FALSE;
    if (!gnet_snmp_ber_dec_pdu_v2(asn1, PDU, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error))
	return FALSE;
    gnet_snmp_ber_dec_delete(asn1, wholeMsg, (guint *) &wholeMsgLength);
    
    if (PDU->type == GNET_SNMP_PDU_RESPONSE) 
	*sendPduHandle = -1;
    else
	*sendPduHandle = 0;
    return TRUE;
}

static gboolean
snmpv2c_release_state( gpointer stateReference)
{
    return TRUE;
}

/* ----------------------------------------------------------------------------
 *                          SNMP V3 Message Processing Model
 * ----------------------------------------------------------------------------
 */

static gboolean
snmpv3_prepare_outgoing_message(GNetSnmpTDomain transportDomain, 
                         GInetAddr *transportAddress,
                         guint messageProcessingModel, guint securityModel,
                         GString *securityName, int securityLevel,
                         GString *contextEngineID, GString *contextName,
                         guint pduVersion, GNetSnmpPdu *PDU, 
                         gboolean expectResponse, int sendPduHandle,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage, 
                         guint *outgoingMessageLength,
			 GError **error)
{
    GNetSnmpBer *asn1;
    guchar *eoc, *eoc1, *end, flags;
    guchar buffer[65536], *ptr;
    
    ptr    = buffer;
    *outgoingMessageLength = 65536;
    flags = expectResponse?4+securityLevel:securityLevel;
    
    if (messageProcessingModel != PMODEL_SNMPV3)
	return FALSE; /* This should never happen. Something fishy going on? */
    
    if ((securityModel == SMODEL_SNMPV1) || (securityModel == SMODEL_SNMPV2C))
	return FALSE;
    if (pduVersion != PDUV2)
	return FALSE;
    
    if (securityModel == SMODEL_ANY)
	securityModel = SMODEL_USM;
    
/* RFC2272
 *     SNMPv3Message ::= SEQUENCE {
 *         -- identify the layout of the SNMPv3Message
 *         -- this element is in same position as in SNMPv1
 *         -- and SNMPv2c, allowing recognition
 *         msgVersion INTEGER { snmpv3 (3) },
 *         -- administrative parameters
 *         msgGlobalData HeaderData,
 *         -- security model-specific parameters
 *         -- format defined by Security Model
 *         msgSecurityParameters OCTET STRING,
 *         msgData  ScopedPduData
 *     }
 */

    asn1 = gnet_snmp_ber_enc_new(ptr, *outgoingMessageLength);
    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc, error))
	return FALSE;

    if (contextEngineID) {
	PDU->context_engineid = contextEngineID->str;
	PDU->context_engineid_len = contextEngineID->len;
    }
    if (contextName) {
	PDU->context_name = contextName->str;
	PDU->context_name_len = contextName->len;
    }
    
    if (!gnet_snmp_ber_enc_pdu_v3(asn1, PDU, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_octets(asn1, &end, (guchar *) securityName->str, securityName->len, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_eoc(asn1, &eoc1, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_guint32(asn1, &end, securityModel, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_octets(asn1, &end, &flags, 1, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_guint32(asn1,  &end, 65536, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_guint32(asn1,  &end, sendPduHandle, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, eoc1, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_guint32(asn1, &end, 3, error))
	return FALSE;
    if (!gnet_snmp_ber_enc_header(asn1, end, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT, error))
	return FALSE;
    
    if (!gnet_snmp_ber_enc_header(asn1, eoc, GNET_SNMP_ASN1_UNI, GNET_SNMP_ASN1_CON, GNET_SNMP_ASN1_SEQ, error))
	return FALSE;
    
    gnet_snmp_ber_enc_delete(asn1, &ptr, outgoingMessageLength);
    
/* FIXME: we currently don't implement proxy support. In this case 
 *        outTransportDomain and outTransportAddress are always
 *        the same as transportAddress and transportDomain.
 *
 * "Rule #1: If there's something you don't understand, it must be
 *  related to proxies" -- Juergen Schoenwaelder
 */
    
    *outTransportDomain = transportDomain;
    *outTransportAddress = transportAddress;
    
    *outgoingMessage = g_malloc(*outgoingMessageLength);
    g_memmove(*outgoingMessage, ptr, *outgoingMessageLength);
    g_free(buffer);
    
    return TRUE;
}

static gboolean
snmpv3_prepare_response_message(guint messageProcessingModel,
                         guint securityModel, GString *securityName,
                         int securityLevel, GString *contextEngineID,
                         GString *contextName, guint pduVersion, GNetSnmpPdu *PDU,
                         guint maxSizeResponseScopedPDU,
                         gpointer stateReference, guint statusInformation,
                         GNetSnmpTDomain *outTransportDomain,
                         GInetAddr **outTransportAddress,
                         gpointer *outgoingMessage,
                         guint *outgoingMessageLength)
{
    return FALSE;
}

static gboolean
snmpv3_prepare_data_elements(GNetSnmpTDomain transportDomain,
                         GInetAddr *transportAddress,
                         gpointer wholeMsg, int wholeMsgLength,
                         guint *messageProcessingModel, guint *securityModel,
                         GString **securityName, int *securityLevel,
                         GString **contextEngineID, GString **contextName,
                         guint *pduVersion, GNetSnmpPdu *PDU, guint *pduType,
                         int *sendPduHandle, guint *maxSizeResponseScopedPDU,
                         guint *statusInformation, gpointer *stateReference,
			 GError **error)
{
    GNetSnmpBer *asn1;
    guint cls, con, tag;
    guchar *eoc, *end;
    
    /* FIXME: This is horribly broken */

    *securityName = g_malloc(sizeof(GString));
    
    asn1 = gnet_snmp_ber_dec_new(wholeMsg, wholeMsgLength);
    
    if (!gnet_snmp_ber_dec_header(asn1, &eoc, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_CON || tag != GNET_SNMP_ASN1_SEQ)
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_INT)
	return FALSE;
    if (!gnet_snmp_ber_dec_guint32(asn1, end, messageProcessingModel, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_header(asn1, &end, &cls, &con, &tag, error))
	return FALSE;
    if (cls != GNET_SNMP_ASN1_UNI || con != GNET_SNMP_ASN1_PRI || tag != GNET_SNMP_ASN1_OTS)
	return FALSE;
    if (!gnet_snmp_ber_dec_octets(asn1, end, (guchar **)&((*securityName)->str), 
				  (guint *) &((*securityName)->len), error))
	return FALSE;
    if (!gnet_snmp_ber_dec_pdu_v2(asn1, PDU, error))
	return FALSE;
    if (!gnet_snmp_ber_dec_eoc(asn1, eoc, error))
	return FALSE;
    gnet_snmp_ber_dec_delete(asn1, wholeMsg, (guint *) &wholeMsgLength);
    
    if (PDU->type == GNET_SNMP_PDU_RESPONSE) 
	*sendPduHandle = -1;
    else
	*sendPduHandle = 0;
    return TRUE;
}

static gboolean
snmpv3_release_state( gpointer stateReference)
{
    return TRUE;
}


gboolean
g_message_init()
{
    struct g_message *my_message;
    
    my_message = g_malloc(sizeof(struct g_message));
    
    my_message->prepareOutgoingMessage = snmpv1_prepare_outgoing_message;
    my_message->prepareResponseMessage = snmpv1_prepare_response_message;
    my_message->prepareDataElements    = snmpv1_prepare_data_elements;
    my_message->releaseState           = snmpv1_release_state;
    
    g_register_message(PMODEL_SNMPV1, my_message);
    
    my_message = g_malloc(sizeof(struct g_message));
    
    my_message->prepareOutgoingMessage = snmpv2c_prepare_outgoing_message;
    my_message->prepareResponseMessage = snmpv2c_prepare_response_message;
    my_message->prepareDataElements    = snmpv2c_prepare_data_elements;
    my_message->releaseState           = snmpv2c_release_state;
    
    g_register_message(PMODEL_SNMPV2C, my_message);
    
    my_message = g_malloc(sizeof(struct g_message));
    
    my_message->prepareOutgoingMessage = snmpv3_prepare_outgoing_message;
    my_message->prepareResponseMessage = snmpv3_prepare_response_message;
    my_message->prepareDataElements    = snmpv3_prepare_data_elements;
    my_message->releaseState           = snmpv3_release_state;
    
    g_register_message(PMODEL_SNMPV3, my_message);
    return TRUE;
}