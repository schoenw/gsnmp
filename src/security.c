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

#include "gsnmp.h"

#include <string.h>

/* This module defines the API to the SNMP RFC layer. Requests are routed
 * to the appropriate transport (e.g. IPv4 or IPv6 or IPX) by using the
 * message processing compatible with the given PDU version (V1, V2C,
 * or V3). Applications will prefer to use the sync or async event loop
 * API presented by the g_session layer.
 */

/*
   statusInformation =
     authenticateOutgoingMsg(
     IN   authKey                   -- secret key for authentication
     IN   wholeMsg                  -- unauthenticated complete message
     OUT  authenticatedWholeMsg     -- complete authenticated message
          )

   statusInformation =
     authenticateIncomingMsg(
     IN   authKey                   -- secret key for authentication
     IN   authParameters            -- as received on the wire
     IN   wholeMsg                  -- as received on the wire
     OUT  authenticatedWholeMsg     -- complete authenticated message
          )

   statusInformation =
     encryptData(
     IN    encryptKey               -- secret key for encryption
     IN    dataToEncrypt            -- data to encrypt (scopedPDU)
     OUT   encryptedData            -- encrypted data (encryptedPDU)
     OUT   privParameters           -- filled in by service provider
           )

   statusInformation =
     decryptData(
     IN    decryptKey               -- secret key for decrypting
     IN    privParameters           -- as received on the wire
     IN    encryptedData            -- encrypted data (encryptedPDU)
     OUT   decryptedData            -- decrypted data (scopedPDU)
              )

   statusInformation =            -- success or errorIndication
     generateRequestMsg(
     IN   messageProcessingModel  -- typically, SNMP version
     IN   globalData              -- message header, admin data
     IN   maxMessageSize          -- of the sending SNMP entity
     IN   securityModel           -- for the outgoing message
     IN   securityEngineID        -- authoritative SNMP entity
     IN   securityName            -- on behalf of this principal
     IN   securityLevel           -- Level of Security requested
     IN   scopedPDU               -- message (plaintext) payload
     OUT  securityParameters      -- filled in by Security Module
     OUT  wholeMsg                -- complete generated message
     OUT  wholeMsgLength          -- length of generated message
          )

   statusInformation =            -- success or errorIndication
     generateResponseMsg(
     IN   messageProcessingModel  -- typically, SNMP version
     IN   globalData              -- message header, admin data
     IN   maxMessageSize          -- of the sending SNMP entity
     IN   securityModel           -- for the outgoing message
     IN   securityEngineID        -- authoritative SNMP entity
     IN   securityName            -- on behalf of this principal
     IN   securityLevel           -- Level of Security requested
     IN   scopedPDU               -- message (plaintext) payload
     IN   securityStateReference  -- reference to security state
                                  -- information from original
                                  -- request
     OUT  securityParameters      -- filled in by Security Module
     OUT  wholeMsg                -- complete generated message
     OUT  wholeMsgLength          -- length of generated message
           )

   statusInformation =             -- errorIndication or success
                                   -- error counter OID/value if error
     processIncomingMsg(
     IN   messageProcessingModel   -- typically, SNMP version
     IN   maxMessageSize           -- of the sending SNMP entity
     IN   securityParameters       -- for the received message
     IN   securityModel            -- for the received message
     IN   securityLevel            -- Level of Security
     IN   wholeMsg                 -- as received on the wire
     IN   wholeMsgLength           -- length as received on the wire
     OUT  securityEngineID         -- authoritative SNMP entity
     OUT  securityName             -- identification of the principal
     OUT  scopedPDU,               -- message (plaintext) payload
     OUT  maxSizeResponseScopedPDU -- maximum size of the Response PDU
     OUT  securityStateReference   -- reference to security state
          )                        -- information, needed for response

*/

/*
 * USMSecurityParametersSyntax DEFINITIONS IMPLICIT TAGS ::= BEGIN
 *
 *    UsmSecurityParameters ::=
 *        SEQUENCE {
 *         -- global User-based security parameters
 *            msgAuthoritativeEngineID     OCTET STRING,
 *            msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
 *            msgAuthoritativeEngineTime   INTEGER (0..2147483647),
 *            msgUserName                  OCTET STRING (SIZE(1..32)),
 *         -- authentication protocol specific parameters
 *            msgAuthenticationParameters  OCTET STRING,
 *         -- privacy protocol specific parameters
 *            msgPrivacyParameters         OCTET STRING
 *        }
 * END
 */

/* ******************************* */

/** Convert password into a key using MD5.
 *
 * \param password password (not necessarily NUL terminated).
 * \param password_len length of the password (must be positive).
 * \param key pointer to memory large enough to hold the key.
 *
 * Convert the password into a key by implementing the algorithm
 * defined in RFC 3414 appendix A.2.1 using MD5 as the oneway hash
 * function.
 */

void
gnet_snmp_password_to_key_md5(guchar *password, gsize password_len,
			      guchar *key)
{
    GMD5   *gmd5;
    guchar *cp, password_buf[64];
    gulong password_index = 0;
    gulong count = 0, i;

    g_assert(password_len);
    
    gmd5 = gnet_md5_new_incremental();

    /**********************************************/
    /* Use while loop until we've done 1 Megabyte */
    /**********************************************/
    
    while (count < 1048576) {
	cp = password_buf;
	for(i = 0; i < 64; i++) {
	    /*************************************************/
	    /* Take the next octet of the password, wrapping */
	    /* to the beginning of the password as necessary.*/
	    /*************************************************/
	    *cp++ = password[ password_index++ % password_len ];
        }
	gnet_md5_update(gmd5, (gchar *) password_buf, 64);
	count += 64;
    }
    gnet_md5_final(gmd5);

    g_memmove(key, gnet_md5_get_digest(gmd5), GNET_MD5_HASH_LENGTH);
    gnet_md5_delete(gmd5);
}

/** Localize a key using MD5.
 *
 * \param key pointer to memory which holds a key.
 * \param engineID pointer to memory which holds an SNMP engine ID.
 * \param engineID_len length of the engine ID (between 5 and 32 inclusive).
 *
 * Localize a key for a specific engine by implementing the algorithm
 * defined in RFC 3414 appendix A.2.1 using MD5 as the oneway hash
 * function.
 */

void
gnet_snmp_localize_key_md5(guchar *key, guchar *engineID, gsize engineID_len)
{
    GMD5   *gmd5;
    guchar password_buf[64];

    g_assert(engineID_len > 4 && engineID_len < 33);

    g_memmove(password_buf, key, 16);
    g_memmove(password_buf+16, engineID, engineID_len);
    g_memmove(password_buf+16+engineID_len, key, 16);

    gmd5 = gnet_md5_new((gchar *) password_buf, 32+engineID_len);
    g_memmove(key, gnet_md5_get_digest(gmd5), GNET_MD5_HASH_LENGTH);
    gnet_md5_delete(gmd5);
}

/** Convert password into a key using SHA.
 *
 * \param password password (not necessarily NUL terminated)
 * \param password_len length of the password (must be positive)
 * \param key pointer to memory large enough to hold the key
 *
 * Convert the password into a key by implementing the algorithm
 * defined in RFC 3414 appendix A.2.1 using SHA as the oneway hash
 * function.
 */

void
gnet_snmp_password_to_key_sha(guchar *password, gsize password_len,
			      guchar *key)
{
    GSHA   *gsha;
    guchar *cp, password_buf[64];
    gulong password_index = 0;
    gulong count = 0, i;

    g_assert(password_len);
    
    gsha = gnet_sha_new_incremental();

    /**********************************************/
    /* Use while loop until we've done 1 Megabyte */
    /**********************************************/
    
    while (count < 1048576) {
	cp = password_buf;
	for(i = 0; i < 64; i++) {
	    /*************************************************/
	    /* Take the next octet of the password, wrapping */
	    /* to the beginning of the password as necessary.*/
	    /*************************************************/
	    *cp++ = password[ password_index++ % password_len ];
        }
	gnet_sha_update(gsha, (gchar *) password_buf, 64);
	count += 64;
    }
    gnet_sha_final(gsha);

    g_memmove(key, gnet_sha_get_digest(gsha), GNET_SHA_HASH_LENGTH);
    gnet_sha_delete(gsha);
}

/** Localize a key using SHA.
 *
 * \param key pointer to memory which holds a key
 * \param engineID pointer to memory which holds an SNMP engine ID
 * \param engineID_len length of the engine ID (between 5 and 32 inclusive)
 *
 * Localize a key for a specific engine by implementing the algorithm
 * defined in RFC 3414 appendix A.2.1 using SHA as the oneway hash
 * function.
 */

void
gnet_snmp_localize_key_sha(guchar *key, guchar *engineID, gsize engineID_len)
{
    GSHA   *gsha;
    guchar password_buf[72];

    g_assert(engineID_len > 4 && engineID_len < 33);

    g_memmove(password_buf, key, 20);
    g_memmove(password_buf+20, engineID, engineID_len);
    g_memmove(password_buf+20+engineID_len, key, 20);

    gsha = gnet_sha_new((gchar *) password_buf, 40+engineID_len);
    g_memmove(key, gnet_sha_get_digest(gsha), GNET_SHA_HASH_LENGTH);
    gnet_sha_delete(gsha);
}
