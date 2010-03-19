#include "gsnmp.h"

static void
dump(guchar *bytes, gsize len)
{
    int i;

    for (i = 0; i < len; i++) {
	g_print("%02x%c", bytes[i], (i % 16) == 15 ? '\n': ':');
    }
}

/*
 * Check the password to key algorithm and the key localization as
 * described in RFC 3414 section A.3.1.
 */

static void
test_md5_key_localization()
{
    char *password = "maplesyrup";
    guchar key[GNET_MD5_HASH_LENGTH];
    gsize keylen = GNET_MD5_HASH_LENGTH;
    
    guchar engineid[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

    guchar digest1[] =
	{ 0x9f, 0xaf, 0x32, 0x83, 0x88, 0x4e, 0x92, 0x83,
	  0x4e, 0xbc, 0x98, 0x47, 0xd8, 0xed, 0xd9, 0x63 };

    guchar digest2[] =
	{ 0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f,
	  0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8, 0x2b };

    gnet_snmp_password_to_key_md5((guchar *) password, strlen(password),
				  key, &keylen);
    g_assert(memcmp(key, digest1, GNET_MD5_HASH_LENGTH) == 0);

    gnet_snmp_localize_key_md5(key, &keylen, engineid, G_N_ELEMENTS(engineid));
    g_assert(memcmp(key, digest2, GNET_MD5_HASH_LENGTH) == 0);
}

/*
 * Check the password to key algorithm and the key localization as
 * described in RFC 3414 section A.3.2.
 */

static void
test_sha_key_localization()
{
    char *password = "maplesyrup";
    guchar key[GNET_SHA_HASH_LENGTH];
    gsize keylen = GNET_SHA_HASH_LENGTH;
    
    guchar engineid[] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

    guchar digest1[] =
	{ 0x9f, 0xb5, 0xcc, 0x03, 0x81, 0x49, 0x7b, 0x37, 0x93, 0x52,
	  0x89, 0x39, 0xff, 0x78, 0x8d, 0x5d, 0x79, 0x14, 0x52, 0x11 };

    guchar digest2[] =
	{ 0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23,
	  0x5f, 0xc7, 0x15, 0x1f, 0x12, 0x84, 0x97, 0xb3, 0x8f, 0x3f };

    gnet_snmp_password_to_key_sha((guchar *) password, strlen(password),
				  key, &keylen);
    g_assert(memcmp(key, digest1, GNET_SHA_HASH_LENGTH) == 0);

    gnet_snmp_localize_key_sha(key, &keylen, engineid, G_N_ELEMENTS(engineid));
    g_assert(memcmp(key, digest2, GNET_SHA_HASH_LENGTH) == 0);
}

/*
 *
 */

static void
test_ber_std_msg()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    GNetSnmpMsg msg1, msg2;
    guchar buf[1234], *start;
    gsize len;

    static const guchar x[] = {
	0x30, 0x0b,
	      0x02, 0x01, 0x00,
	      0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63
    };

    memset(&msg1, 0, sizeof(msg1));
    msg1.version = GNET_SNMP_V1;
    msg1.community = (guchar *) "public";
    msg1.community_len = strlen((gchar *) msg1.community);

    memset(&msg2, 0, sizeof(msg2));

    /* SNMPv1 message */
    
    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_msg(asn1, &msg1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_msg(asn1, &msg2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(msg2.version == msg1.version);
    g_assert(msg2.community_len == msg1.community_len);
    g_assert(memcmp(msg2.community, msg1.community,
		    msg1.community_len) == 0);
    g_assert(msg2.community_len == msg1.community_len); 
}

/*
 *
 */

static void
test_ber_std_pdu()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    GNetSnmpPdu pdu1, pdu2;
    guchar buf[1234], *start;
    gsize len;

    static const guchar x[] = {
	0xa1, 0x0b,
	      0x02, 0x01, 0x00,
	      0x02, 0x01, 0x00,
	      0x02, 0x01, 0x00,
	      0x30, 0x00
    };

    static const guchar y[] = {
	0x30, 0x1c,
	      0x04, 0x08, 0x80, 0x00, 0x02, 0xb8, 0x04, 0x61, 0x62, 0x63,
	      0x04, 0x03, 0x64, 0x65, 0x66,
	      0xa1, 0x0b,
	            0x02, 0x01, 0x00,
	            0x02, 0x01, 0x00,
	            0x02, 0x01, 0x00,
	            0x30, 0x00,
    };

    guchar eid[] = {
	0x80, 0x00, 0x02, 0xb8, 0x04, 0x61, 0x62, 0x63,
    };

    memset(&pdu1, 0, sizeof(pdu1));
    pdu1.type = GNET_SNMP_PDU_NEXT;
    pdu1.context_name = (guchar *) "def";
    pdu1.context_name_len = strlen((gchar *) pdu1.context_name);
    pdu1.context_engineid = eid;
    pdu1.context_engineid_len = sizeof(eid);

    memset(&pdu2, 0, sizeof(pdu2));

    /* SNMPv1 PDU */

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_pdu_v1(asn1, &pdu1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_pdu_v1(asn1, &pdu2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(pdu2.type == pdu1.type);
    g_assert(pdu2.request_id == pdu1.request_id); 
    g_assert(pdu2.error_status == pdu1.error_status);
    g_assert(pdu2.error_index == pdu1.error_index);

    /* SNMPv2 PDU */

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_pdu_v2(asn1, &pdu1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_pdu_v2(asn1, &pdu2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(pdu2.type == pdu1.type);
    g_assert(pdu2.request_id == pdu1.request_id); 
    g_assert(pdu2.error_status == pdu1.error_status);
    g_assert(pdu2.error_index == pdu1.error_index);

    /* SNMPv3 PDU */

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_pdu_v3(asn1, &pdu1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(y));
    g_assert(memcmp(start, y, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_pdu_v3(asn1, &pdu2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(pdu2.type == pdu1.type);
    g_assert(pdu2.request_id == pdu1.request_id); 
    g_assert(pdu2.error_status == pdu1.error_status);
    g_assert(pdu2.error_index == pdu1.error_index);
    g_assert(pdu2.context_name_len == pdu1.context_name_len);
    g_assert(memcmp(pdu2.context_name, pdu1.context_name,
		    pdu1.context_name_len) == 0);
    g_assert(pdu2.context_engineid_len == pdu1.context_engineid_len);
    g_assert(memcmp(pdu2.context_engineid, pdu1.context_engineid,
		    pdu1.context_engineid_len) == 0);
}

/*
 *
 */

static void
test_ber_trap_pdu()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    GNetSnmpPdu pdu1, pdu2;
    GNetSnmpVarBind *vb;
    guchar buf[1234], *start;
    gsize len;
    guint32 time = 42;

    static const guchar x[] = {
	0xa4, 0x1b,
	      0x06, 0x08, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05,
              0x40, 0x04, 0x00, 0x00, 0x00, 0x00,
 	      0x02, 0x01, 0x00,
  	      0x02, 0x01, 0x00,
              0x43, 0x01, 0x2a,
	      0x30, 0x00
    };

    static const guchar y[] = {
	0xa4, 0x33,
	      0x02, 0x01, 0x00,
	      0x02, 0x01, 0x00,
	      0x02, 0x01, 0x00,
	      0x30, 0x28,
	            0x30, 0x0d,
                          0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00,
	                  0x43, 0x01, 0x2a,
                    0x30, 0x17,
                          0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x04, 0x01, 0x00,
                          0x06, 0x09, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x05, 0x01
    };

    static const guint32 sysUpTime0[]
	= { 1, 3, 6, 1, 2, 1, 1, 3, 0 }; 

    static const guint32 snmpTrapOID0[]
	= { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

    static guint32 coldStart[]
	= { 1, 3, 6, 1, 6, 3, 1, 1, 5, 1 };

    memset(&pdu1, 0, sizeof(pdu1));
    pdu1.type = GNET_SNMP_PDU_TRAP;

    vb = gnet_snmp_varbind_new(sysUpTime0, G_N_ELEMENTS(sysUpTime0),
			       GNET_SNMP_VARBIND_TYPE_TIMETICKS,
			       &time, 0);
    pdu1.varbind_list = g_list_append(pdu1.varbind_list, vb);

    vb = gnet_snmp_varbind_new(snmpTrapOID0, G_N_ELEMENTS(snmpTrapOID0),
			       GNET_SNMP_VARBIND_TYPE_OBJECTID,
			       coldStart, G_N_ELEMENTS(coldStart));
    pdu1.varbind_list = g_list_append(pdu1.varbind_list, vb);

    /* encode and decode the notification following the RFC 1157
     * protocol operations format */

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_pdu_v1(asn1, &pdu1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    memset(&pdu2, 0, sizeof(pdu2));

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_pdu_v1(asn1, &pdu2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(pdu2.type == pdu1.type);

    vb = g_list_nth_data(pdu2.varbind_list, 0);
    g_assert(vb);
    g_assert(vb->type == GNET_SNMP_VARBIND_TYPE_TIMETICKS);
    g_assert(vb->value.ui32 == time);

    vb = g_list_nth_data(pdu2.varbind_list, 1);
    g_assert(vb);
    g_assert(vb->type == GNET_SNMP_VARBIND_TYPE_OBJECTID);
    g_assert(vb->value_len == G_N_ELEMENTS(coldStart));
    g_assert(memcmp(vb->value.ui32v, coldStart, vb->value_len) == 0);

    /* now do the same with the RFC 3416 protocol operations format */

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_pdu_v2(asn1, &pdu1, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(y));
    g_assert(memcmp(start, y, len) == 0);

    memset(&pdu2, 0, sizeof(pdu2));

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_pdu_v2(asn1, &pdu2, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(pdu2.type == pdu1.type);
    g_assert(pdu2.request_id == pdu1.request_id); 
    g_assert(pdu2.error_status == pdu1.error_status);
    g_assert(pdu2.error_index == pdu1.error_index);

    vb = g_list_nth_data(pdu2.varbind_list, 0);
    g_assert(vb);
    g_assert(vb->type == GNET_SNMP_VARBIND_TYPE_TIMETICKS);
    g_assert(vb->value.ui32 == time);

    vb = g_list_nth_data(pdu2.varbind_list, 1);
    g_assert(vb);
    g_assert(vb->type == GNET_SNMP_VARBIND_TYPE_OBJECTID);
    g_assert(vb->value_len == G_N_ELEMENTS(coldStart));
    g_assert(memcmp(vb->value.ui32v, coldStart, vb->value_len) == 0);
}

static void
test_ber_null()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gsize len;
    guint cls, con, tag;
    
    static const guchar x[] = {
	0x05, 0x00,
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    gnet_snmp_ber_enc_null(asn1, &eoi, &error);
    gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
			     GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_NUL, &error);
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
    g_assert(cls == GNET_SNMP_ASN1_UNI
	     && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_NUL);
    gnet_snmp_ber_dec_null(asn1, eoi, &error);
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_ber_gint32()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gint i;
    guint cls, con, tag;
    gsize len;
    
    gint32 a, v[] = {
	-2147483648L, -2147483647L, -1, 0, 1, 2147483646L, 2147483647L
    };

    static const guchar x[] = {
	0x02, 0x04, 0x80, 0x00, 0x00, 0x00,
	0x02, 0x04, 0x80, 0x00, 0x00, 0x01,
	0x02, 0x01, 0xFF,
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x01,
	0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFE,
	0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    for (i = G_N_ELEMENTS(v) - 1; i >= 0; i--) {
	gnet_snmp_ber_enc_gint32(asn1, &eoi, v[i], &error);
	gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
				 GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				 &error);
    }
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    for (i = 0; i < G_N_ELEMENTS(v); i++) {
	gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
	g_assert(cls == GNET_SNMP_ASN1_UNI
		 && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_INT);
	gnet_snmp_ber_dec_gint32(asn1, eoi, &a, &error);
	g_assert(a == v[i]);
    }
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_ber_gint64()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gint i;
    guint cls, con, tag;
    gsize len;
    
    gint64 a, v[] = {
	-9223372036854775808LL, -2147483648LL, -2147483647LL,
	-1, 0, 1,
	2147483646LL, 2147483647LL, 9223372036854775807LL
    };

    static const guchar x[] = {
	0x02, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x04, 0x80, 0x00, 0x00, 0x00,
	0x02, 0x04, 0x80, 0x00, 0x00, 0x01,
	0x02, 0x01, 0xFF,
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x01,
	0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFE,
	0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF,
	0x02, 0x08, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    for (i = G_N_ELEMENTS(v) - 1; i >= 0; i--) {
	gnet_snmp_ber_enc_gint64(asn1, &eoi, v[i], &error);
	gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
				 GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				 &error);
    }
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    for (i = 0; i < G_N_ELEMENTS(v); i++) {
	gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
	g_assert(cls == GNET_SNMP_ASN1_UNI
		 && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_INT);
	gnet_snmp_ber_dec_gint64(asn1, eoi, &a, &error);
	g_assert(a == v[i]);
    }
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_ber_guint32()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gint i;
    guint cls, con, tag;
    gsize len;

    guint32 a, v[] = {
	0, 1, 4294967294UL, 4294967295UL
    };

    static const guchar x[] = {
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x01,
	0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
	0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF	
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    for (i = G_N_ELEMENTS(v) - 1; i >= 0; i--) {
	gnet_snmp_ber_enc_guint32(asn1, &eoi, v[i], &error);
	gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
				 GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				 &error);
    }
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    for (i = 0; i < G_N_ELEMENTS(v); i++) {
	gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
	g_assert(cls == GNET_SNMP_ASN1_UNI
		 && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_INT);
	gnet_snmp_ber_dec_guint32(asn1, eoi, &a, &error);
	g_assert(a == v[i]);
    }
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_ber_guint64()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gint i;
    guint cls, con, tag;
    gsize len;

    guint64 a, v[] = {
	0, 1, 4294967295UL, 4294967296ULL, 18446744073709551615ULL
    };

    static const guchar x[] = {
	0x02, 0x01, 0x00,
	0x02, 0x01, 0x01,
	0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
	0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    for (i = G_N_ELEMENTS(v) - 1; i >= 0; i--) {
	gnet_snmp_ber_enc_guint64(asn1, &eoi, v[i], &error);
	gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
				 GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_INT,
				 &error);
    }
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    for (i = 0; i < G_N_ELEMENTS(v); i++) {
	gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
	g_assert(cls == GNET_SNMP_ASN1_UNI
		 && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_INT);
	gnet_snmp_ber_dec_guint64(asn1, eoi, &a, &error);
	g_assert(a == v[i]);
    }
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_ber_octets()
{
    GError *error = NULL;
    GNetSnmpBer *asn1;
    guchar buf[1234], *start, *eoi;
    gint i;
    guint cls, con, tag;
    gsize len, a_len;

    gchar *a, *v[] = {
	"", "a", "abcdefghijklmnopqrstuvwxyz"
    };

    static const guchar x[] = {
	0x04, 0x00,
	0x04, 0x01, 0x61,
	0x04, 0x1a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
	            0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
	            0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a
    };

    asn1 = gnet_snmp_ber_enc_new(buf, sizeof(buf));
    for (i = G_N_ELEMENTS(v) - 1; i >= 0; i--) {
	gnet_snmp_ber_enc_octets(asn1, &eoi,
				 (guchar *) v[i], strlen(v[i]), &error);
	gnet_snmp_ber_enc_header(asn1, eoi, GNET_SNMP_ASN1_UNI,
				 GNET_SNMP_ASN1_PRI, GNET_SNMP_ASN1_OTS,
				 &error);
    }
    gnet_snmp_ber_enc_delete(asn1, &start, &len);

    g_assert(error == NULL);
    g_assert(len == G_N_ELEMENTS(x));
    g_assert(memcmp(start, x, len) == 0);

    asn1 = gnet_snmp_ber_dec_new(start, len);
    for (i = 0; i < G_N_ELEMENTS(v); i++) {
	gnet_snmp_ber_dec_header(asn1, &eoi, &cls, &con, &tag, &error);
	g_assert(cls == GNET_SNMP_ASN1_UNI
		 && con == GNET_SNMP_ASN1_PRI && tag == GNET_SNMP_ASN1_OTS);
	gnet_snmp_ber_dec_octets(asn1, eoi, (guchar **) &a, &a_len, &error);
	g_assert(a_len == strlen(v[i]));
	g_assert(memcmp(a, v[i], a_len) == 0);
    }
    gnet_snmp_ber_dec_delete(asn1, &start, &len);
    g_assert(error == NULL);
}

static void
test_snmp_uri_parser()
{
#if 1
    GURI *uri;
#else
    GNetSnmp *snmp;
    GError *error = NULL;
#endif
    int i;

    static const gchar *testcases[] = {

	/* fully qualified service URIs which we accept */

	"snmp://localhost/",		"snmp://public@localhost:161/",
	"snmp://public@localhost/",	"snmp://public@localhost:161/",
	"snmp://localhost:162/",	"snmp://public@localhost:162/",
	"snmp://public@localhost:163/",	"snmp://public@localhost:163/",

	"snmp://127.0.0.1/",		"snmp://public@127.0.0.1:161/",
	"snmp://public@127.0.0.1/",	"snmp://public@127.0.0.1:161/",
	"snmp://127.0.0.1:162/",	"snmp://public@127.0.0.1:162/",
	"snmp://public@127.0.0.1:163/",	"snmp://public@127.0.0.1:163/",

	"snmp://[::1]/",		"snmp://public@[::1]:161/",
	"snmp://public@[::1]/",		"snmp://public@[::1]:161/",
	"snmp://[::1]:162/",		"snmp://public@[::1]:162/",
	"snmp://public@[::1]:163/",	"snmp://public@[::1]:163/",

	/* file URIs for local domain sockets */

	"file:/tmp/socket",		"file:/tmp/socket",
	
        /* abbreviated URIs which we also accept for convenience */

	"localhost",			"snmp://public@localhost:161/",
	"public@localhost",		"snmp://public@localhost:161/",
//	"localhost:161",		"snmp://public@localhost:161/",

	"127.0.0.1",			"snmp://public@127.0.0.1:161/",
	"public@127.0.0.1",		"snmp://public@127.0.0.1:161/",
//	"127.0.0.1:161",		"snmp://public@127.0.0.1:161/",

//	"::1",				"snmp://public@[::1]:161/",
//	"public@::1",			"snmp://public@[::1]:161/",

//	"[::1]",			"snmp://public@[::1]:161/",
//	"public@[::1]",			"snmp://public@[::1]:161/",
//	"[::1]:161",			"snmp://public@[::1]:161/",
//	"public@[::1]:161",		"snmp://public@[::1]:161/",

	"/tmp/socket",			"file:/tmp/socket",

	NULL, NULL
    };
    
    for (i = 0; testcases[i]; i++) {
#if 1
	uri = gnet_snmp_parse_uri(testcases[i++], NULL);
	g_printerr("testcases[%d] %s\n", i-1, testcases[i-1]);
	if (uri) {
	    gchar *s = gnet_uri_get_string(uri);
	    g_printerr("%s-> %s\n", testcases[i], s);
	    g_assert(strcmp(s, testcases[i]) == 0);
	    g_free(s);
	} else {
	    g_assert(testcases[i] == NULL);
	}
	if (uri) {
	    gnet_uri_delete(uri);
	}
#else
	snmp = gnet_snmp_new_string(testcases[i++], &error);
	g_printerr("testcases[%d] %s\n", i-1, testcases[i-1]);
	if (snmp && !error) {
	    gchar *s = gnet_snmp_get_uri_string(snmp);
	    g_printerr("%s-> %s\n", testcases[i], s);
	    g_assert(strcmp(s, testcases[i]) == 0);
	    g_free(s);
	} else {
	    g_assert(testcases[i] == NULL);
	}
	if (snmp) {
	    gnet_snmp_delete(snmp);
	}
#endif
    }
}

int
main(void)
{
    gint i;
    
    static struct {
	void (*func)(void);
	const gchar *desc;
    } tests[] = {
	{ test_ber_null,	"ASN.1/BER null encoding/decoding test" },
	{ test_ber_gint32,	"ASN.1/BER gint32 encoding/decoding test" },
	{ test_ber_gint64,	"ASN.1/BER gint64 encoding/decoding test" },
	{ test_ber_guint32,	"ASN.1/BER guint32 encoding/decoding test" },
	{ test_ber_guint64,	"ASN.1/BER guint64 encoding/decoding test" },
	{ test_ber_octets,	"ASN.1/BER octet string encoding/decoding test" },
	{ test_ber_std_pdu,	"ASN.1/BER standard pdu encoding/decoding test" },
	{ test_ber_trap_pdu,	"ASN.1/BER trap pdu encoding/decoding test" },
	{ test_ber_std_msg,	"ASN.1/BER standard msg encoding/decoding test" },
	{ test_md5_key_localization,	"MD5 key localization test" },
	{ test_sha_key_localization,	"SHA key localization test" },
	{ test_snmp_uri_parser,	"SNMP URI parser test" },
	{ NULL, NULL }
    };

    for (i = 0; tests[i].func && tests[i].desc; i++) {
	g_print("%3d: %s\n", i, tests[i].desc);
	tests[i].func();
    }

    return 0;
}
