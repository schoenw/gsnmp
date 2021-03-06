/*							-- DO NOT EDIT --
 * Generated by smidump version 0.4.8:
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

#ifndef _SNMPV2_MIB_H_
#define _SNMPV2_MIB_H_

#include "gsnmp.h"

G_BEGIN_DECLS

/*
 * Tables to map enumerations to strings and vice versa.
 */

#define SNMPV2_MIB_SNMPENABLEAUTHENTRAPS_ENABLED  1
#define SNMPV2_MIB_SNMPENABLEAUTHENTRAPS_DISABLED 2

extern GNetSnmpEnum const snmpv2_mib_enums_snmpEnableAuthenTraps[];


/*
 * Tables to map notifications to strings and vice versa.
 */

#define SNMPV2_MIB_COLDSTART	1,3,6,1,6,3,1,1,5,1
#define SNMPV2_MIB_WARMSTART	1,3,6,1,6,3,1,1,5,2
#define SNMPV2_MIB_AUTHENTICATIONFAILURE	1,3,6,1,6,3,1,1,5,5

extern GNetSnmpIdentity const snmpv2_mib_notifications[];

/*
 * C type definitions for SNMPv2-MIB::system.
 */

#define SNMPV2_MIB_SYSDESCR        (1 << 0) 
#define SNMPV2_MIB_SYSOBJECTID     (1 << 1) 
#define SNMPV2_MIB_SYSUPTIME       (1 << 2) 
#define SNMPV2_MIB_SYSCONTACT      (1 << 3) 
#define SNMPV2_MIB_SYSNAME         (1 << 4) 
#define SNMPV2_MIB_SYSLOCATION     (1 << 5) 
#define SNMPV2_MIB_SYSSERVICES     (1 << 6) 
#define SNMPV2_MIB_SYSORLASTCHANGE (1 << 7) 

typedef struct {
    guchar   *sysDescr;            /* ro */
#define SNMPV2_MIB_SYSDESCRMINLENGTH 0
#define SNMPV2_MIB_SYSDESCRMAXLENGTH 255
    guint16  _sysDescrLength;
    guint32  *sysObjectID;         /* ro ObjectIdentifier */
#define SNMPV2_MIB_SYSOBJECTIDMINLENGTH 0
#define SNMPV2_MIB_SYSOBJECTIDMAXLENGTH 128
    guint16  _sysObjectIDLength;
    guint32  *sysUpTime;           /* ro SNMPv2-SMI::TimeTicks */
    guchar   *sysContact;          /* rw */
#define SNMPV2_MIB_SYSCONTACTMINLENGTH 0
#define SNMPV2_MIB_SYSCONTACTMAXLENGTH 255
    guint16  _sysContactLength;
    guchar   *sysName;             /* rw */
#define SNMPV2_MIB_SYSNAMEMINLENGTH 0
#define SNMPV2_MIB_SYSNAMEMAXLENGTH 255
    guint16  _sysNameLength;
    guchar   *sysLocation;         /* rw */
#define SNMPV2_MIB_SYSLOCATIONMINLENGTH 0
#define SNMPV2_MIB_SYSLOCATIONMAXLENGTH 255
    guint16  _sysLocationLength;
    gint32   *sysServices;         /* ro */
    guint32  *sysORLastChange;     /* ro SNMPv2-TC::TimeStamp */
} snmpv2_mib_system_t;

extern snmpv2_mib_system_t *
snmpv2_mib_new_system(void);

extern void
snmpv2_mib_get_system(GNetSnmp *s, snmpv2_mib_system_t **system, gint64 mask, GError **error);

extern void
snmpv2_mib_set_system(GNetSnmp *s, snmpv2_mib_system_t *system, gint64 mask, GError **error);

extern void
snmpv2_mib_free_system(snmpv2_mib_system_t *system);

/*
 * C type definitions for SNMPv2-MIB::sysOREntry.
 */

#define SNMPV2_MIB_SYSORID     (1 << 0) 
#define SNMPV2_MIB_SYSORDESCR  (1 << 1) 
#define SNMPV2_MIB_SYSORUPTIME (1 << 2) 

typedef struct {
    gint32   sysORIndex;       /* na */
    guint32  *sysORID;         /* ro ObjectIdentifier */
#define SNMPV2_MIB_SYSORIDMINLENGTH 0
#define SNMPV2_MIB_SYSORIDMAXLENGTH 128
    guint16  _sysORIDLength;
    guchar   *sysORDescr;      /* ro SNMPv2-TC::DisplayString */
#define SNMPV2_MIB_SYSORDESCRMINLENGTH 0
#define SNMPV2_MIB_SYSORDESCRMAXLENGTH 255
    guint16  _sysORDescrLength;
    guint32  *sysORUpTime;     /* ro SNMPv2-TC::TimeStamp */
} snmpv2_mib_sysOREntry_t;

extern void
snmpv2_mib_get_sysORTable(GNetSnmp *s, snmpv2_mib_sysOREntry_t ***sysOREntry, gint64 mask, GError **error);

extern void
snmpv2_mib_free_sysORTable(snmpv2_mib_sysOREntry_t **sysOREntry);

extern snmpv2_mib_sysOREntry_t *
snmpv2_mib_new_sysOREntry(void);

extern void
snmpv2_mib_get_sysOREntry(GNetSnmp *s, snmpv2_mib_sysOREntry_t **sysOREntry, gint32 sysORIndex, gint64 mask, GError **error);

extern void
snmpv2_mib_free_sysOREntry(snmpv2_mib_sysOREntry_t *sysOREntry);

/*
 * C type definitions for SNMPv2-MIB::snmp.
 */

#define SNMPV2_MIB_SNMPINPKTS              (1 << 0) 
#define SNMPV2_MIB_SNMPOUTPKTS             (1 << 1) 
#define SNMPV2_MIB_SNMPINBADVERSIONS       (1 << 2) 
#define SNMPV2_MIB_SNMPINBADCOMMUNITYNAMES (1 << 3) 
#define SNMPV2_MIB_SNMPINBADCOMMUNITYUSES  (1 << 4) 
#define SNMPV2_MIB_SNMPINASNPARSEERRS      (1 << 5) 
#define SNMPV2_MIB_SNMPINTOOBIGS           (1 << 6) 
#define SNMPV2_MIB_SNMPINNOSUCHNAMES       (1 << 7) 
#define SNMPV2_MIB_SNMPINBADVALUES         (1 << 8) 
#define SNMPV2_MIB_SNMPINREADONLYS         (1 << 9) 
#define SNMPV2_MIB_SNMPINGENERRS           (1 << 10) 
#define SNMPV2_MIB_SNMPINTOTALREQVARS      (1 << 11) 
#define SNMPV2_MIB_SNMPINTOTALSETVARS      (1 << 12) 
#define SNMPV2_MIB_SNMPINGETREQUESTS       (1 << 13) 
#define SNMPV2_MIB_SNMPINGETNEXTS          (1 << 14) 
#define SNMPV2_MIB_SNMPINSETREQUESTS       (1 << 15) 
#define SNMPV2_MIB_SNMPINGETRESPONSES      (1 << 16) 
#define SNMPV2_MIB_SNMPINTRAPS             (1 << 17) 
#define SNMPV2_MIB_SNMPOUTTOOBIGS          (1 << 18) 
#define SNMPV2_MIB_SNMPOUTNOSUCHNAMES      (1 << 19) 
#define SNMPV2_MIB_SNMPOUTBADVALUES        (1 << 20) 
#define SNMPV2_MIB_SNMPOUTGENERRS          (1 << 21) 
#define SNMPV2_MIB_SNMPOUTGETREQUESTS      (1 << 22) 
#define SNMPV2_MIB_SNMPOUTGETNEXTS         (1 << 23) 
#define SNMPV2_MIB_SNMPOUTSETREQUESTS      (1 << 24) 
#define SNMPV2_MIB_SNMPOUTGETRESPONSES     (1 << 25) 
#define SNMPV2_MIB_SNMPOUTTRAPS            (1 << 26) 
#define SNMPV2_MIB_SNMPENABLEAUTHENTRAPS   (1 << 27) 
#define SNMPV2_MIB_SNMPSILENTDROPS         (1 << 28) 
#define SNMPV2_MIB_SNMPPROXYDROPS          (1 << 29) 

typedef struct {
    guint32  *snmpInPkts;                  /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutPkts;                 /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInBadVersions;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInBadCommunityNames;     /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInBadCommunityUses;      /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInASNParseErrs;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInTooBigs;               /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInNoSuchNames;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInBadValues;             /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInReadOnlys;             /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInGenErrs;               /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInTotalReqVars;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInTotalSetVars;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInGetRequests;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInGetNexts;              /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInSetRequests;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInGetResponses;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpInTraps;                 /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutTooBigs;              /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutNoSuchNames;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutBadValues;            /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutGenErrs;              /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutGetRequests;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutGetNexts;             /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutSetRequests;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutGetResponses;         /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpOutTraps;                /* ro SNMPv2-SMI::Counter32 */
    gint32   *snmpEnableAuthenTraps;       /* rw */
    guint32  *snmpSilentDrops;             /* ro SNMPv2-SMI::Counter32 */
    guint32  *snmpProxyDrops;              /* ro SNMPv2-SMI::Counter32 */
} snmpv2_mib_snmp_t;

extern snmpv2_mib_snmp_t *
snmpv2_mib_new_snmp(void);

extern void
snmpv2_mib_get_snmp(GNetSnmp *s, snmpv2_mib_snmp_t **snmp, gint64 mask, GError **error);

extern void
snmpv2_mib_set_snmp(GNetSnmp *s, snmpv2_mib_snmp_t *snmp, gint64 mask, GError **error);

extern void
snmpv2_mib_free_snmp(snmpv2_mib_snmp_t *snmp);

/*
 * C type definitions for SNMPv2-MIB::snmpSet.
 */

#define SNMPV2_MIB_SNMPSETSERIALNO (1 << 0) 

typedef struct {
    gint32   *snmpSetSerialNo;     /* rw SNMPv2-TC::TestAndIncr */
} snmpv2_mib_snmpSet_t;

extern snmpv2_mib_snmpSet_t *
snmpv2_mib_new_snmpSet(void);

extern void
snmpv2_mib_get_snmpSet(GNetSnmp *s, snmpv2_mib_snmpSet_t **snmpSet, gint64 mask, GError **error);

extern void
snmpv2_mib_set_snmpSet(GNetSnmp *s, snmpv2_mib_snmpSet_t *snmpSet, gint64 mask, GError **error);

extern void
snmpv2_mib_free_snmpSet(snmpv2_mib_snmpSet_t *snmpSet);


G_END_DECLS

#endif /* _SNMPV2_MIB_H_ */
