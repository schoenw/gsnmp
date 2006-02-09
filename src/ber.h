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

#ifndef __GNET_SNMP_BER_H__
#define __GNET_SNMP_BER_H__

#include <glib.h>

/* This module implements a subset of an ASN.1/BER encoder/decoder.
 * Encoding takes place from the end to the beginning in order to
 * provide compact encodings without memory copies. Note that reverse
 * encoding may not work for other protocols.
 *
 * The encoding and decoding API functions are also tailored to handle
 * just the subset of ASN.1 data types actually used by SNMP. Note
 * that ASN.1 for example allows unconstrained INTEGER values while
 * this library has several API functions for various concrete size
 * constrained types of INTEGER values.
 */

/* ASN.1 classes */

#define GNET_SNMP_ASN1_UNI	0     /* Universal   */
#define GNET_SNMP_ASN1_APL	1     /* Application */
#define GNET_SNMP_ASN1_CTX	2     /* Context     */
#define GNET_SNMP_ASN1_PRV	3     /* Private     */

/* ASN.1 tags */

#define GNET_SNMP_ASN1_EOC	0     /* End Of Contents    */
#define GNET_SNMP_ASN1_BOL	1     /* Boolean            */
#define GNET_SNMP_ASN1_INT	2     /* Integer            */
#define GNET_SNMP_ASN1_BTS	3     /* Bit String         */
#define GNET_SNMP_ASN1_OTS	4     /* Octet String       */
#define GNET_SNMP_ASN1_NUL	5     /* Null               */
#define GNET_SNMP_ASN1_OJI	6     /* Object Identifier  */
#define GNET_SNMP_ASN1_OJD	7     /* Object Description */
#define GNET_SNMP_ASN1_EXT	8     /* External           */
#define GNET_SNMP_ASN1_SEQ	16    /* Sequence           */
#define GNET_SNMP_ASN1_SET	17    /* Set                */
#define GNET_SNMP_ASN1_NUMSTR	18    /* Numerical String   */
#define GNET_SNMP_ASN1_PRNSTR	19    /* Printable String   */
#define GNET_SNMP_ASN1_TEXSTR	20    /* Teletext String    */
#define GNET_SNMP_ASN1_VIDSTR	21    /* Video String       */
#define GNET_SNMP_ASN1_IA5STR	22    /* IA5 String         */
#define GNET_SNMP_ASN1_UNITIM	23    /* Universal Time     */
#define GNET_SNMP_ASN1_GENTIM	24    /* General Time       */
#define GNET_SNMP_ASN1_GRASTR	25    /* Graphical String   */
#define GNET_SNMP_ASN1_VISSTR	26    /* Visible String     */
#define GNET_SNMP_ASN1_GENSTR	27    /* General String     */

/* ASN.1 primitive / constructed */

#define GNET_SNMP_ASN1_PRI     0       /* Primitive              */
#define GNET_SNMP_ASN1_CON     1       /* Constructed            */

/* BER encoding / decoding error codes */

typedef enum
{
    GNET_SNMP_BER_ERROR_ENC_FULL,
    GNET_SNMP_BER_ERROR_DEC_EMPTY,
    GNET_SNMP_BER_ERROR_DEC_EOC_MISMATCH,
    GNET_SNMP_BER_ERROR_DEC_LENGTH_MISMATCH,
    GNET_SNMP_BER_ERROR_DEC_BADVALUE,
    GNET_SNMP_BER_ERROR_ENC_BADVALUE
} GNetSnmpBerError;

#define GNET_SNMP_BER_ERROR gnet_snmp_ber_error_quark()

typedef struct _GNetSnmpBer GNetSnmpBer;

GQuark	 gnet_snmp_ber_error_quark();

GNetSnmpBer* gnet_snmp_ber_enc_new	(guchar *buf, gsize buf_len);

GNetSnmpBer* gnet_snmp_ber_dec_new	(guchar *buf, gsize buf_len);

void     gnet_snmp_ber_enc_delete	(GNetSnmpBer *asn1, guchar **buf,
					 gsize *buf_len);
void     gnet_snmp_ber_dec_delete	(GNetSnmpBer *asn1, guchar **buf,
					 gsize *buf_len);
gboolean gnet_snmp_ber_enc_length	(GNetSnmpBer *asn1, guint def,
					 gsize len, GError **error);
gboolean gnet_snmp_ber_dec_length	(GNetSnmpBer *asn1, guint *def,
					 gsize *len, GError **error);
gboolean gnet_snmp_ber_enc_header	(GNetSnmpBer *asn1, guchar *eoc,
					 guint cls, guint con, guint tag,
					 GError **error);
gboolean gnet_snmp_ber_dec_header	(GNetSnmpBer *asn1, guchar **eoc,
					 guint *cls, guint *con, guint *tag,
					 GError **error);
gboolean gnet_snmp_ber_is_eoc		(GNetSnmpBer *asn1, guchar *eoc);

gboolean gnet_snmp_ber_enc_eoc		(GNetSnmpBer *asn1, guchar **eoc,
					 GError **error);
gboolean gnet_snmp_ber_dec_eoc		(GNetSnmpBer *asn1, guchar *eoc,
					 GError **error);
gboolean gnet_snmp_ber_enc_null		(GNetSnmpBer *asn1, guchar **eoc,
					 GError **error);
gboolean gnet_snmp_ber_dec_null		(GNetSnmpBer *asn1, guchar *eoc,
					 GError **error);
gboolean gnet_snmp_ber_enc_gint32	(GNetSnmpBer *asn1, guchar **eoc,
					 const gint32 value, GError **error);
gboolean gnet_snmp_ber_dec_gint32	(GNetSnmpBer *asn1, guchar *eoc,
					 gint32 *value, GError **error);
gboolean gnet_snmp_ber_enc_gint64	(GNetSnmpBer *asn1, guchar **eoc,
					 const gint64 value, GError **error);
gboolean gnet_snmp_ber_dec_gint64	(GNetSnmpBer *asn1, guchar *eoc,
					 gint64 *value, GError **error);
gboolean gnet_snmp_ber_enc_guint32	(GNetSnmpBer *asn1, guchar **eoc,
					 const guint32 value, GError **error);
gboolean gnet_snmp_ber_dec_guint32	(GNetSnmpBer *asn1, guchar *eoc,
					 guint32 *value, GError **error);
gboolean gnet_snmp_ber_enc_guint64	(GNetSnmpBer *asn1, guchar **eoc,
					 const guint64 value, GError **error);
gboolean gnet_snmp_ber_dec_guint64	(GNetSnmpBer *asn1, guchar *eoc,
					 guint64 *integer, GError **error);
gboolean gnet_snmp_ber_enc_octets	(GNetSnmpBer *asn1, guchar **eoc,
					 const guchar *octs, const gsize len,
					 GError **error);
gboolean gnet_snmp_ber_dec_octets	(GNetSnmpBer *asn1, guchar *eoc,
					 guchar **octs, gsize *len,
					 GError **error);
gboolean gnet_snmp_ber_enc_oid		(GNetSnmpBer *asn1, guchar **eoc, 
					 const guint32 *oid, const gsize len,
					 GError **error);
gboolean gnet_snmp_ber_dec_oid		(GNetSnmpBer *asn1, guchar *eoc, 
					 guint32 **oid, gsize *len,
					 GError **error);

#endif /* __GNET_SNMP_BER_H__ */
