/*							-- DO NOT EDIT --
 * Generated by smidump version 0.4.3-pre1:
 *   smidump -f scli SNMPv2-MIB
 *
 * Derived from SNMPv2-MIB:
 *   The MIB module for SNMP entities.
 *   
 *   Copyright (C) The Internet Society (2002). This
 *   version of this MIB module is part of RFC 3418;
 *   see the RFC itself for full legal notices.
 *
 * Revision 2002-10-16 00:00:
 *   This revision of this MIB module was published as
 *   RFC 3418.
 *
 * Revision 1995-11-09 00:00:
 *   This revision of this MIB module was published as
 *   RFC 1907.
 *
 * Revision 1993-04-01 00:00:
 *   The initial revision of this MIB module was published
 *   as RFC 1450.
 *
 * $Id$
 */

#include "snmpv2-mib.h"

GNetSnmpEnum const snmpv2_mib_enums_snmpEnableAuthenTraps[] = {
    { SNMPV2_MIB_SNMPENABLEAUTHENTRAPS_ENABLED,  "enabled" },
    { SNMPV2_MIB_SNMPENABLEAUTHENTRAPS_DISABLED, "disabled" },
    { 0, NULL }
};


static guint16 sysDescr_constraints[] = {0U, 255U, 0, 0};
static guint16 sysContact_constraints[] = {0U, 255U, 0, 0};
static guint16 sysName_constraints[] = {0U, 255U, 0, 0};
static guint16 sysLocation_constraints[] = {0U, 255U, 0, 0};
static gint32 sysServices_constraints[] = {0L, 127L, 0, 0};
static guint16 sysORDescr_constraints[] = {0U, 255U, 0, 0};
static gint32 snmpSetSerialNo_constraints[] = {0L, 2147483647L, 0, 0};


static guint32 const system_oid[] = {1, 3, 6, 1, 2, 1, 1};

static GNetSnmpAttribute system_attr[] = {
    { 1, GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
      SNMPV2_MIB_SYSDESCR, "sysDescr",
       sysDescr_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysDescr),
      G_STRUCT_OFFSET(snmpv2_mib_system_t, _sysDescrLength),
      0 },
    { 2, GNET_SNMP_VARBIND_TYPE_OBJECTID,
      SNMPV2_MIB_SYSOBJECTID, "sysObjectID",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysObjectID),
      G_STRUCT_OFFSET(snmpv2_mib_system_t, _sysObjectIDLength),
      0 },
    { 3, GNET_SNMP_VARBIND_TYPE_TIMETICKS,
      SNMPV2_MIB_SYSUPTIME, "sysUpTime",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysUpTime),
      0,
      0 },
    { 4, GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
      SNMPV2_MIB_SYSCONTACT, "sysContact",
       sysContact_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysContact),
      G_STRUCT_OFFSET(snmpv2_mib_system_t, _sysContactLength),
      GSNMP_ATTR_FLAG_WRITABLE },
    { 5, GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
      SNMPV2_MIB_SYSNAME, "sysName",
       sysName_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysName),
      G_STRUCT_OFFSET(snmpv2_mib_system_t, _sysNameLength),
      GSNMP_ATTR_FLAG_WRITABLE },
    { 6, GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
      SNMPV2_MIB_SYSLOCATION, "sysLocation",
       sysLocation_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysLocation),
      G_STRUCT_OFFSET(snmpv2_mib_system_t, _sysLocationLength),
      GSNMP_ATTR_FLAG_WRITABLE },
    { 7, GNET_SNMP_VARBIND_TYPE_INTEGER32,
      SNMPV2_MIB_SYSSERVICES, "sysServices",
       sysServices_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysServices),
      0,
      0 },
    { 8, GNET_SNMP_VARBIND_TYPE_TIMETICKS,
      SNMPV2_MIB_SYSORLASTCHANGE, "sysORLastChange",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_system_t, sysORLastChange),
      0,
      0 },
    { 0, 0, 0, NULL }
};

static guint32 const sysOREntry_oid[] = {1, 3, 6, 1, 2, 1, 1, 9, 1};

static GNetSnmpAttribute sysOREntry_attr[] = {
    { 2, GNET_SNMP_VARBIND_TYPE_OBJECTID,
      SNMPV2_MIB_SYSORID, "sysORID",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_sysOREntry_t, sysORID),
      G_STRUCT_OFFSET(snmpv2_mib_sysOREntry_t, _sysORIDLength),
      0 },
    { 3, GNET_SNMP_VARBIND_TYPE_OCTETSTRING,
      SNMPV2_MIB_SYSORDESCR, "sysORDescr",
       sysORDescr_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_sysOREntry_t, sysORDescr),
      G_STRUCT_OFFSET(snmpv2_mib_sysOREntry_t, _sysORDescrLength),
      0 },
    { 4, GNET_SNMP_VARBIND_TYPE_TIMETICKS,
      SNMPV2_MIB_SYSORUPTIME, "sysORUpTime",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_sysOREntry_t, sysORUpTime),
      0,
      0 },
    { 0, 0, 0, NULL }
};

static guint32 const snmp_oid[] = {1, 3, 6, 1, 2, 1, 11};

static GNetSnmpAttribute snmp_attr[] = {
    { 1, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINPKTS, "snmpInPkts",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInPkts),
      0,
      0 },
    { 2, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTPKTS, "snmpOutPkts",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutPkts),
      0,
      0 },
    { 3, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINBADVERSIONS, "snmpInBadVersions",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInBadVersions),
      0,
      0 },
    { 4, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINBADCOMMUNITYNAMES, "snmpInBadCommunityNames",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInBadCommunityNames),
      0,
      0 },
    { 5, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINBADCOMMUNITYUSES, "snmpInBadCommunityUses",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInBadCommunityUses),
      0,
      0 },
    { 6, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINASNPARSEERRS, "snmpInASNParseErrs",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInASNParseErrs),
      0,
      0 },
    { 8, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINTOOBIGS, "snmpInTooBigs",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInTooBigs),
      0,
      0 },
    { 9, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINNOSUCHNAMES, "snmpInNoSuchNames",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInNoSuchNames),
      0,
      0 },
    { 10, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINBADVALUES, "snmpInBadValues",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInBadValues),
      0,
      0 },
    { 11, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINREADONLYS, "snmpInReadOnlys",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInReadOnlys),
      0,
      0 },
    { 12, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINGENERRS, "snmpInGenErrs",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInGenErrs),
      0,
      0 },
    { 13, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINTOTALREQVARS, "snmpInTotalReqVars",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInTotalReqVars),
      0,
      0 },
    { 14, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINTOTALSETVARS, "snmpInTotalSetVars",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInTotalSetVars),
      0,
      0 },
    { 15, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINGETREQUESTS, "snmpInGetRequests",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInGetRequests),
      0,
      0 },
    { 16, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINGETNEXTS, "snmpInGetNexts",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInGetNexts),
      0,
      0 },
    { 17, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINSETREQUESTS, "snmpInSetRequests",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInSetRequests),
      0,
      0 },
    { 18, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINGETRESPONSES, "snmpInGetResponses",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInGetResponses),
      0,
      0 },
    { 19, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPINTRAPS, "snmpInTraps",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpInTraps),
      0,
      0 },
    { 20, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTTOOBIGS, "snmpOutTooBigs",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutTooBigs),
      0,
      0 },
    { 21, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTNOSUCHNAMES, "snmpOutNoSuchNames",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutNoSuchNames),
      0,
      0 },
    { 22, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTBADVALUES, "snmpOutBadValues",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutBadValues),
      0,
      0 },
    { 24, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTGENERRS, "snmpOutGenErrs",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutGenErrs),
      0,
      0 },
    { 25, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTGETREQUESTS, "snmpOutGetRequests",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutGetRequests),
      0,
      0 },
    { 26, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTGETNEXTS, "snmpOutGetNexts",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutGetNexts),
      0,
      0 },
    { 27, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTSETREQUESTS, "snmpOutSetRequests",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutSetRequests),
      0,
      0 },
    { 28, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTGETRESPONSES, "snmpOutGetResponses",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutGetResponses),
      0,
      0 },
    { 29, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPOUTTRAPS, "snmpOutTraps",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpOutTraps),
      0,
      0 },
    { 30, GNET_SNMP_VARBIND_TYPE_INTEGER32,
      SNMPV2_MIB_SNMPENABLEAUTHENTRAPS, "snmpEnableAuthenTraps",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpEnableAuthenTraps),
      0,
      GSNMP_ATTR_FLAG_WRITABLE },
    { 31, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPSILENTDROPS, "snmpSilentDrops",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpSilentDrops),
      0,
      0 },
    { 32, GNET_SNMP_VARBIND_TYPE_COUNTER32,
      SNMPV2_MIB_SNMPPROXYDROPS, "snmpProxyDrops",
       NULL,
      G_STRUCT_OFFSET(snmpv2_mib_snmp_t, snmpProxyDrops),
      0,
      0 },
    { 0, 0, 0, NULL }
};

static guint32 const snmpSet_oid[] = {1, 3, 6, 1, 6, 3, 1, 1, 6};

static GNetSnmpAttribute snmpSet_attr[] = {
    { 1, GNET_SNMP_VARBIND_TYPE_INTEGER32,
      SNMPV2_MIB_SNMPSETSERIALNO, "snmpSetSerialNo",
       snmpSetSerialNo_constraints,
      G_STRUCT_OFFSET(snmpv2_mib_snmpSet_t, snmpSetSerialNo),
      0,
      GSNMP_ATTR_FLAG_WRITABLE },
    { 0, 0, 0, NULL }
};


snmpv2_mib_system_t *
snmpv2_mib_new_system()
{
    snmpv2_mib_system_t *system;

    system = (snmpv2_mib_system_t *) g_malloc0(sizeof(snmpv2_mib_system_t) + sizeof(gpointer));
    return system;
}

static inline snmpv2_mib_system_t *
assign_system(GList *vbl)
{
    snmpv2_mib_system_t *system;
    char *p;

    system = snmpv2_mib_new_system();
    p = (char *) system + sizeof(snmpv2_mib_system_t);
    * (GList **) p = vbl;

    gnet_snmp_attr_assign(vbl, system_oid, G_N_ELEMENTS(system_oid),
                      system_attr, system);

    return system;
}

void
snmpv2_mib_get_system(GNetSnmp *s, snmpv2_mib_system_t **system, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 2, 1, 1, 0};

    *system = NULL;

    gnet_snmp_attr_get(s, &in, base, 8, 7, system_attr, mask);

    out = gnet_snmp_sync_getnext(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        if (s->error_status != GNET_SNMP_ERR_NOERROR) {
            g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
            g_list_free(out);
            return;
        }
        *system = assign_system(out);
    }
}

void
snmpv2_mib_set_system(GNetSnmp *s, snmpv2_mib_system_t *system, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 2, 1, 1, 0, 0};

    gnet_snmp_attr_set(s, &in, base, 9, 7, system_attr, mask, system);

    out = gnet_snmp_sync_set(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(out);
    }
}

void
snmpv2_mib_free_system(snmpv2_mib_system_t *system)
{
    GList *vbl;
    char *p;

    if (system) {
        p = (char *) system + sizeof(snmpv2_mib_system_t);
        vbl = * (GList **) p;
        g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(vbl);
        g_free(system);
    }
}

snmpv2_mib_sysOREntry_t *
snmpv2_mib_new_sysOREntry()
{
    snmpv2_mib_sysOREntry_t *sysOREntry;

    sysOREntry = (snmpv2_mib_sysOREntry_t *) g_malloc0(sizeof(snmpv2_mib_sysOREntry_t) + sizeof(gpointer));
    return sysOREntry;
}

static inline int
unpack_sysOREntry(GNetSnmpVarBind *vb, snmpv2_mib_sysOREntry_t *sysOREntry)
{
    guint8 idx = 10;

    if (vb->oid_len < idx) return -1;
    sysOREntry->sysORIndex = vb->oid[idx++];
    if ((sysOREntry->sysORIndex < 1)) {
         return -1;
    }
    if (vb->oid_len > idx) return -1;
    return 0;
}

static inline gint8
pack_sysOREntry(guint32 *base, gint32 sysORIndex)
{
    guint8 idx = 10;

    base[idx++] = sysORIndex;
    return idx;
}

static inline snmpv2_mib_sysOREntry_t *
assign_sysOREntry(GList *vbl)
{
    snmpv2_mib_sysOREntry_t *sysOREntry;
    char *p;

    sysOREntry = snmpv2_mib_new_sysOREntry();
    p = (char *) sysOREntry + sizeof(snmpv2_mib_sysOREntry_t);
    * (GList **) p = vbl;

    if (unpack_sysOREntry((GNetSnmpVarBind *) vbl->data, sysOREntry) < 0) {
        g_warning("%s: invalid instance identifier", "sysOREntry");
        g_free(sysOREntry);
        return NULL;
    }

    gnet_snmp_attr_assign(vbl, sysOREntry_oid, G_N_ELEMENTS(sysOREntry_oid),
                      sysOREntry_attr, sysOREntry);

    return sysOREntry;
}

void
snmpv2_mib_get_sysORTable(GNetSnmp *s, snmpv2_mib_sysOREntry_t ***sysOREntry, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    GList *row;
    int i;
    static guint32 base[] = {1, 3, 6, 1, 2, 1, 1, 9, 1, 0};

    *sysOREntry = NULL;

    gnet_snmp_attr_get(s, &in, base, 10, 9, sysOREntry_attr, mask);

    out = gnet_snmp_sync_table(s, in);
    /* gnet_snmp_varbind_list_free(in); */

    if (out) {
        *sysOREntry = (snmpv2_mib_sysOREntry_t **) g_malloc0((g_list_length(out) + 1) * sizeof(snmpv2_mib_sysOREntry_t *));
        for (row = out, i = 0; row; row = g_list_next(row), i++) {
            (*sysOREntry)[i] = assign_sysOREntry(row->data);
        }
    }
}

void
snmpv2_mib_get_sysOREntry(GNetSnmp *s, snmpv2_mib_sysOREntry_t **sysOREntry, gint32 sysORIndex, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    guint32 base[128];
    gint8 len;

    memcpy(base, sysOREntry_oid, sizeof(sysOREntry_oid));
    len = pack_sysOREntry(base, sysORIndex);
    if (len < 0) {
        g_warning("%s: invalid index values", "sysOREntry");
        s->error_status = GNET_SNMP_ERR_INTERNAL;
        return;
    }

    *sysOREntry = NULL;

    gnet_snmp_attr_get(s, &in, base, len, 9, sysOREntry_attr, mask);

    out = gnet_snmp_sync_get(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        if (s->error_status != GNET_SNMP_ERR_NOERROR) {
            g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
            g_list_free(out);
            return;
        }
        *sysOREntry = assign_sysOREntry(out);
    }
}

void
snmpv2_mib_free_sysOREntry(snmpv2_mib_sysOREntry_t *sysOREntry)
{
    GList *vbl;
    char *p;

    if (sysOREntry) {
        p = (char *) sysOREntry + sizeof(snmpv2_mib_sysOREntry_t);
        vbl = * (GList **) p;
        g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(vbl);
        g_free(sysOREntry);
    }
}

void
snmpv2_mib_free_sysORTable(snmpv2_mib_sysOREntry_t **sysOREntry)
{
    int i;

    if (sysOREntry) {
        for (i = 0; sysOREntry[i]; i++) {
            snmpv2_mib_free_sysOREntry(sysOREntry[i]);
        }
        g_free(sysOREntry);
    }
}

snmpv2_mib_snmp_t *
snmpv2_mib_new_snmp()
{
    snmpv2_mib_snmp_t *snmp;

    snmp = (snmpv2_mib_snmp_t *) g_malloc0(sizeof(snmpv2_mib_snmp_t) + sizeof(gpointer));
    return snmp;
}

static inline snmpv2_mib_snmp_t *
assign_snmp(GList *vbl)
{
    snmpv2_mib_snmp_t *snmp;
    char *p;

    snmp = snmpv2_mib_new_snmp();
    p = (char *) snmp + sizeof(snmpv2_mib_snmp_t);
    * (GList **) p = vbl;

    gnet_snmp_attr_assign(vbl, snmp_oid, G_N_ELEMENTS(snmp_oid),
                      snmp_attr, snmp);

    return snmp;
}

void
snmpv2_mib_get_snmp(GNetSnmp *s, snmpv2_mib_snmp_t **snmp, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 2, 1, 11, 0};

    *snmp = NULL;

    gnet_snmp_attr_get(s, &in, base, 8, 7, snmp_attr, mask);

    out = gnet_snmp_sync_getnext(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        if (s->error_status != GNET_SNMP_ERR_NOERROR) {
            g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
            g_list_free(out);
            return;
        }
        *snmp = assign_snmp(out);
    }
}

void
snmpv2_mib_set_snmp(GNetSnmp *s, snmpv2_mib_snmp_t *snmp, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 2, 1, 11, 0, 0};

    gnet_snmp_attr_set(s, &in, base, 9, 7, snmp_attr, mask, snmp);

    out = gnet_snmp_sync_set(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(out);
    }
}

void
snmpv2_mib_free_snmp(snmpv2_mib_snmp_t *snmp)
{
    GList *vbl;
    char *p;

    if (snmp) {
        p = (char *) snmp + sizeof(snmpv2_mib_snmp_t);
        vbl = * (GList **) p;
        g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(vbl);
        g_free(snmp);
    }
}

snmpv2_mib_snmpSet_t *
snmpv2_mib_new_snmpSet()
{
    snmpv2_mib_snmpSet_t *snmpSet;

    snmpSet = (snmpv2_mib_snmpSet_t *) g_malloc0(sizeof(snmpv2_mib_snmpSet_t) + sizeof(gpointer));
    return snmpSet;
}

static inline snmpv2_mib_snmpSet_t *
assign_snmpSet(GList *vbl)
{
    snmpv2_mib_snmpSet_t *snmpSet;
    char *p;

    snmpSet = snmpv2_mib_new_snmpSet();
    p = (char *) snmpSet + sizeof(snmpv2_mib_snmpSet_t);
    * (GList **) p = vbl;

    gnet_snmp_attr_assign(vbl, snmpSet_oid, G_N_ELEMENTS(snmpSet_oid),
                      snmpSet_attr, snmpSet);

    return snmpSet;
}

void
snmpv2_mib_get_snmpSet(GNetSnmp *s, snmpv2_mib_snmpSet_t **snmpSet, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 6, 3, 1, 1, 6, 0};

    *snmpSet = NULL;

    gnet_snmp_attr_get(s, &in, base, 10, 9, snmpSet_attr, mask);

    out = gnet_snmp_sync_getnext(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        if (s->error_status != GNET_SNMP_ERR_NOERROR) {
            g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
            g_list_free(out);
            return;
        }
        *snmpSet = assign_snmpSet(out);
    }
}

void
snmpv2_mib_set_snmpSet(GNetSnmp *s, snmpv2_mib_snmpSet_t *snmpSet, gint64 mask)
{
    GList *in = NULL, *out = NULL;
    static guint32 base[] = {1, 3, 6, 1, 6, 3, 1, 1, 6, 0, 0};

    gnet_snmp_attr_set(s, &in, base, 11, 9, snmpSet_attr, mask, snmpSet);

    out = gnet_snmp_sync_set(s, in);
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    if (out) {
        g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(out);
    }
}

void
snmpv2_mib_free_snmpSet(snmpv2_mib_snmpSet_t *snmpSet)
{
    GList *vbl;
    char *p;

    if (snmpSet) {
        p = (char *) snmpSet + sizeof(snmpv2_mib_snmpSet_t);
        vbl = * (GList **) p;
        g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
        g_list_free(vbl);
        g_free(snmpSet);
    }
}

