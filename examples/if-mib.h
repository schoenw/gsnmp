/*							-- DO NOT EDIT --
 * Generated by smidump version 0.4.3-pre1:
 *   smidump -f scli IF-MIB
 *
 * Derived from IF-MIB:
 *   The MIB module to describe generic objects for network
 *   interface sub-layers.  This MIB is an updated version of
 *   MIB-II's ifTable, and incorporates the extensions defined in
 *   RFC 1229.
 *
 * Revision 2000-06-14 00:00:
 *   Clarifications agreed upon by the Interfaces MIB WG, and
 *   published as RFC 2863.
 *
 * Revision 1996-02-28 21:55:
 *   Revisions made by the Interfaces MIB WG, and published in
 *   RFC 2233.
 *
 * Revision 1993-11-08 21:55:
 *   Initial revision, published as part of RFC 1573.
 *
 * $Id$
 */

#ifndef _IF_MIB_H_
#define _IF_MIB_H_

#include "gsnmp.h"

G_BEGIN_DECLS

/*
 * Tables to map enumerations to strings and vice versa.
 */

#define IF_MIB_IFADMINSTATUS_UP      1
#define IF_MIB_IFADMINSTATUS_DOWN    2
#define IF_MIB_IFADMINSTATUS_TESTING 3

extern GNetSnmpEnum const if_mib_enums_ifAdminStatus[];

#define IF_MIB_IFOPERSTATUS_UP             1
#define IF_MIB_IFOPERSTATUS_DOWN           2
#define IF_MIB_IFOPERSTATUS_TESTING        3
#define IF_MIB_IFOPERSTATUS_UNKNOWN        4
#define IF_MIB_IFOPERSTATUS_DORMANT        5
#define IF_MIB_IFOPERSTATUS_NOTPRESENT     6
#define IF_MIB_IFOPERSTATUS_LOWERLAYERDOWN 7

extern GNetSnmpEnum const if_mib_enums_ifOperStatus[];

#define IF_MIB_IFLINKUPDOWNTRAPENABLE_ENABLED  1
#define IF_MIB_IFLINKUPDOWNTRAPENABLE_DISABLED 2

extern GNetSnmpEnum const if_mib_enums_ifLinkUpDownTrapEnable[];

#define IF_MIB_IFTESTSTATUS_NOTINUSE 1
#define IF_MIB_IFTESTSTATUS_INUSE    2

extern GNetSnmpEnum const if_mib_enums_ifTestStatus[];

#define IF_MIB_IFTESTRESULT_NONE         1
#define IF_MIB_IFTESTRESULT_SUCCESS      2
#define IF_MIB_IFTESTRESULT_INPROGRESS   3
#define IF_MIB_IFTESTRESULT_NOTSUPPORTED 4
#define IF_MIB_IFTESTRESULT_UNABLETORUN  5
#define IF_MIB_IFTESTRESULT_ABORTED      6
#define IF_MIB_IFTESTRESULT_FAILED       7

extern GNetSnmpEnum const if_mib_enums_ifTestResult[];

#define IF_MIB_IFRCVADDRESSTYPE_OTHER       1
#define IF_MIB_IFRCVADDRESSTYPE_VOLATILE    2
#define IF_MIB_IFRCVADDRESSTYPE_NONVOLATILE 3

extern GNetSnmpEnum const if_mib_enums_ifRcvAddressType[];


/*
 * C type definitions for IF-MIB::interfaces.
 */

#define IF_MIB_IFNUMBER (1 << 0) 

typedef struct {
    gint32   *ifNumber;     /* ro Integer32 */
} if_mib_interfaces_t;

extern if_mib_interfaces_t *
if_mib_new_interfaces(void);

extern void
if_mib_get_interfaces(GNetSnmp *s, if_mib_interfaces_t **interfaces, gint64 mask);

extern void
if_mib_free_interfaces(if_mib_interfaces_t *interfaces);

/*
 * C type definitions for IF-MIB::ifEntry.
 */

#define IF_MIB_IFINDEX           (1 << 0) 
#define IF_MIB_IFDESCR           (1 << 1) 
#define IF_MIB_IFTYPE            (1 << 2) 
#define IF_MIB_IFMTU             (1 << 3) 
#define IF_MIB_IFSPEED           (1 << 4) 
#define IF_MIB_IFPHYSADDRESS     (1 << 5) 
#define IF_MIB_IFADMINSTATUS     (1 << 6) 
#define IF_MIB_IFOPERSTATUS      (1 << 7) 
#define IF_MIB_IFLASTCHANGE      (1 << 8) 
#define IF_MIB_IFINOCTETS        (1 << 9) 
#define IF_MIB_IFINUCASTPKTS     (1 << 10) 
#define IF_MIB_IFINNUCASTPKTS    (1 << 11) 
#define IF_MIB_IFINDISCARDS      (1 << 12) 
#define IF_MIB_IFINERRORS        (1 << 13) 
#define IF_MIB_IFINUNKNOWNPROTOS (1 << 14) 
#define IF_MIB_IFOUTOCTETS       (1 << 15) 
#define IF_MIB_IFOUTUCASTPKTS    (1 << 16) 
#define IF_MIB_IFOUTNUCASTPKTS   (1 << 17) 
#define IF_MIB_IFOUTDISCARDS     (1 << 18) 
#define IF_MIB_IFOUTERRORS       (1 << 19) 
#define IF_MIB_IFOUTQLEN         (1 << 20) 
#define IF_MIB_IFSPECIFIC        (1 << 21) 

typedef struct {
    gint32   ifIndex;                /* ro IF-MIB::InterfaceIndex */
    guchar   *ifDescr;               /* ro */
#define IF_MIB_IFDESCRMINLENGTH 0
#define IF_MIB_IFDESCRMAXLENGTH 255
    guint16  _ifDescrLength;
    gint32   *ifType;                /* ro IANAifType-MIB::IANAifType */
    gint32   *ifMtu;                 /* ro Integer32 */
    guint32  *ifSpeed;               /* ro SNMPv2-SMI::Gauge32 */
    guchar   *ifPhysAddress;         /* ro SNMPv2-TC::PhysAddress */
#define IF_MIB_IFPHYSADDRESSMINLENGTH 0
#define IF_MIB_IFPHYSADDRESSMAXLENGTH 65535
    guint16  _ifPhysAddressLength;
    gint32   *ifAdminStatus;         /* rw */
    gint32   *ifOperStatus;          /* ro */
    guint32  *ifLastChange;          /* ro SNMPv2-SMI::TimeTicks */
    guint32  *ifInOctets;            /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInUcastPkts;         /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInNUcastPkts;        /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInDiscards;          /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInErrors;            /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInUnknownProtos;     /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutOctets;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutUcastPkts;        /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutNUcastPkts;       /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutDiscards;         /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutErrors;           /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutQLen;             /* ro SNMPv2-SMI::Gauge32 */
    guint32  *ifSpecific;            /* ro ObjectIdentifier */
#define IF_MIB_IFSPECIFICMINLENGTH 0
#define IF_MIB_IFSPECIFICMAXLENGTH 128
    guint16  _ifSpecificLength;
} if_mib_ifEntry_t;

extern void
if_mib_get_ifTable(GNetSnmp *s, if_mib_ifEntry_t ***ifEntry, gint64 mask);

extern void
if_mib_free_ifTable(if_mib_ifEntry_t **ifEntry);

extern if_mib_ifEntry_t *
if_mib_new_ifEntry(void);

extern void
if_mib_get_ifEntry(GNetSnmp *s, if_mib_ifEntry_t **ifEntry, gint32 ifIndex, gint64 mask);

extern void
if_mib_set_ifEntry(GNetSnmp *s, if_mib_ifEntry_t *ifEntry, gint64 mask);

extern void
if_mib_free_ifEntry(if_mib_ifEntry_t *ifEntry);

/*
 * C type definitions for IF-MIB::ifMIBObjects.
 */

#define IF_MIB_IFTABLELASTCHANGE (1 << 0) 
#define IF_MIB_IFSTACKLASTCHANGE (1 << 1) 

typedef struct {
    guint32  *ifTableLastChange;     /* ro SNMPv2-SMI::TimeTicks */
    guint32  *ifStackLastChange;     /* ro SNMPv2-SMI::TimeTicks */
} if_mib_ifMIBObjects_t;

extern if_mib_ifMIBObjects_t *
if_mib_new_ifMIBObjects(void);

extern void
if_mib_get_ifMIBObjects(GNetSnmp *s, if_mib_ifMIBObjects_t **ifMIBObjects, gint64 mask);

extern void
if_mib_free_ifMIBObjects(if_mib_ifMIBObjects_t *ifMIBObjects);

/*
 * C type definitions for IF-MIB::ifXEntry.
 */

#define IF_MIB_IFNAME                     (1 << 0) 
#define IF_MIB_IFINMULTICASTPKTS          (1 << 1) 
#define IF_MIB_IFINBROADCASTPKTS          (1 << 2) 
#define IF_MIB_IFOUTMULTICASTPKTS         (1 << 3) 
#define IF_MIB_IFOUTBROADCASTPKTS         (1 << 4) 
#define IF_MIB_IFHCINOCTETS               (1 << 5) 
#define IF_MIB_IFHCINUCASTPKTS            (1 << 6) 
#define IF_MIB_IFHCINMULTICASTPKTS        (1 << 7) 
#define IF_MIB_IFHCINBROADCASTPKTS        (1 << 8) 
#define IF_MIB_IFHCOUTOCTETS              (1 << 9) 
#define IF_MIB_IFHCOUTUCASTPKTS           (1 << 10) 
#define IF_MIB_IFHCOUTMULTICASTPKTS       (1 << 11) 
#define IF_MIB_IFHCOUTBROADCASTPKTS       (1 << 12) 
#define IF_MIB_IFLINKUPDOWNTRAPENABLE     (1 << 13) 
#define IF_MIB_IFHIGHSPEED                (1 << 14) 
#define IF_MIB_IFPROMISCUOUSMODE          (1 << 15) 
#define IF_MIB_IFCONNECTORPRESENT         (1 << 16) 
#define IF_MIB_IFALIAS                    (1 << 17) 
#define IF_MIB_IFCOUNTERDISCONTINUITYTIME (1 << 18) 

typedef struct {
    gint32   ifIndex;                         /* ro IF-MIB::InterfaceIndex */
    guchar   *ifName;                         /* ro SNMPv2-TC::DisplayString */
#define IF_MIB_IFNAMEMINLENGTH 0
#define IF_MIB_IFNAMEMAXLENGTH 255
    guint16  _ifNameLength;
    guint32  *ifInMulticastPkts;              /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifInBroadcastPkts;              /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutMulticastPkts;             /* ro SNMPv2-SMI::Counter32 */
    guint32  *ifOutBroadcastPkts;             /* ro SNMPv2-SMI::Counter32 */
    guint64  *ifHCInOctets;                   /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCInUcastPkts;                /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCInMulticastPkts;            /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCInBroadcastPkts;            /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCOutOctets;                  /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCOutUcastPkts;               /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCOutMulticastPkts;           /* ro SNMPv2-SMI::Counter64 */
    guint64  *ifHCOutBroadcastPkts;           /* ro SNMPv2-SMI::Counter64 */
    gint32   *ifLinkUpDownTrapEnable;         /* rw */
    guint32  *ifHighSpeed;                    /* ro SNMPv2-SMI::Gauge32 */
    gint32   *ifPromiscuousMode;              /* rw SNMPv2-TC::TruthValue */
    gint32   *ifConnectorPresent;             /* ro SNMPv2-TC::TruthValue */
    guchar   *ifAlias;                        /* rw */
#define IF_MIB_IFALIASMINLENGTH 0
#define IF_MIB_IFALIASMAXLENGTH 64
    guint16  _ifAliasLength;
    guint32  *ifCounterDiscontinuityTime;     /* ro SNMPv2-TC::TimeStamp */
} if_mib_ifXEntry_t;

extern void
if_mib_get_ifXTable(GNetSnmp *s, if_mib_ifXEntry_t ***ifXEntry, gint64 mask);

extern void
if_mib_free_ifXTable(if_mib_ifXEntry_t **ifXEntry);

extern if_mib_ifXEntry_t *
if_mib_new_ifXEntry(void);

extern void
if_mib_get_ifXEntry(GNetSnmp *s, if_mib_ifXEntry_t **ifXEntry, gint32 ifIndex, gint64 mask);

extern void
if_mib_set_ifXEntry(GNetSnmp *s, if_mib_ifXEntry_t *ifXEntry, gint64 mask);

extern void
if_mib_free_ifXEntry(if_mib_ifXEntry_t *ifXEntry);

/*
 * C type definitions for IF-MIB::ifStackEntry.
 */

#define IF_MIB_IFSTACKSTATUS (1 << 0) 

typedef struct {
    gint32   ifStackHigherLayer; /* na IF-MIB::InterfaceIndexOrZero */
    gint32   ifStackLowerLayer;  /* na IF-MIB::InterfaceIndexOrZero */
    gint32   *ifStackStatus;     /* rw SNMPv2-TC::RowStatus */
} if_mib_ifStackEntry_t;

extern void
if_mib_get_ifStackTable(GNetSnmp *s, if_mib_ifStackEntry_t ***ifStackEntry, gint64 mask);

extern void
if_mib_free_ifStackTable(if_mib_ifStackEntry_t **ifStackEntry);

extern if_mib_ifStackEntry_t *
if_mib_new_ifStackEntry(void);

extern void
if_mib_get_ifStackEntry(GNetSnmp *s, if_mib_ifStackEntry_t **ifStackEntry, gint32 ifStackHigherLayer, gint32 ifStackLowerLayer, gint64 mask);

extern void
if_mib_set_ifStackEntry(GNetSnmp *s, if_mib_ifStackEntry_t *ifStackEntry, gint64 mask);

extern void
if_mib_free_ifStackEntry(if_mib_ifStackEntry_t *ifStackEntry);

/*
 * C type definitions for IF-MIB::ifTestEntry.
 */

#define IF_MIB_IFTESTID     (1 << 0) 
#define IF_MIB_IFTESTSTATUS (1 << 1) 
#define IF_MIB_IFTESTTYPE   (1 << 2) 
#define IF_MIB_IFTESTRESULT (1 << 3) 
#define IF_MIB_IFTESTCODE   (1 << 4) 
#define IF_MIB_IFTESTOWNER  (1 << 5) 

typedef struct {
    gint32   ifIndex;           /* ro IF-MIB::InterfaceIndex */
    gint32   *ifTestId;         /* rw SNMPv2-TC::TestAndIncr */
    gint32   *ifTestStatus;     /* rw */
    guint32  *ifTestType;       /* rw SNMPv2-TC::AutonomousType */
#define IF_MIB_IFTESTTYPEMINLENGTH 0
#define IF_MIB_IFTESTTYPEMAXLENGTH 128
    guint16  _ifTestTypeLength;
    gint32   *ifTestResult;     /* ro */
    guint32  *ifTestCode;       /* ro ObjectIdentifier */
#define IF_MIB_IFTESTCODEMINLENGTH 0
#define IF_MIB_IFTESTCODEMAXLENGTH 128
    guint16  _ifTestCodeLength;
    guchar   *ifTestOwner;      /* rw IF-MIB::OwnerString */
#define IF_MIB_IFTESTOWNERMINLENGTH 0
#define IF_MIB_IFTESTOWNERMAXLENGTH 255
    guint16  _ifTestOwnerLength;
} if_mib_ifTestEntry_t;

extern void
if_mib_get_ifTestTable(GNetSnmp *s, if_mib_ifTestEntry_t ***ifTestEntry, gint64 mask);

extern void
if_mib_free_ifTestTable(if_mib_ifTestEntry_t **ifTestEntry);

extern if_mib_ifTestEntry_t *
if_mib_new_ifTestEntry(void);

extern void
if_mib_get_ifTestEntry(GNetSnmp *s, if_mib_ifTestEntry_t **ifTestEntry, gint32 ifIndex, gint64 mask);

extern void
if_mib_set_ifTestEntry(GNetSnmp *s, if_mib_ifTestEntry_t *ifTestEntry, gint64 mask);

extern void
if_mib_free_ifTestEntry(if_mib_ifTestEntry_t *ifTestEntry);

/*
 * C type definitions for IF-MIB::ifRcvAddressEntry.
 */

#define IF_MIB_IFRCVADDRESSSTATUS (1 << 0) 
#define IF_MIB_IFRCVADDRESSTYPE   (1 << 1) 

typedef struct {
    gint32   ifIndex;                 /* ro IF-MIB::InterfaceIndex */
    guchar   ifRcvAddressAddress[117]; /* na SNMPv2-TC::PhysAddress */
#define IF_MIB_IFRCVADDRESSADDRESSMINLENGTH 0
#define IF_MIB_IFRCVADDRESSADDRESSMAXLENGTH 117
    guint16  _ifRcvAddressAddressLength;
    gint32   *ifRcvAddressStatus;     /* rw SNMPv2-TC::RowStatus */
    gint32   *ifRcvAddressType;       /* rw */
} if_mib_ifRcvAddressEntry_t;

extern void
if_mib_get_ifRcvAddressTable(GNetSnmp *s, if_mib_ifRcvAddressEntry_t ***ifRcvAddressEntry, gint64 mask);

extern void
if_mib_free_ifRcvAddressTable(if_mib_ifRcvAddressEntry_t **ifRcvAddressEntry);

extern if_mib_ifRcvAddressEntry_t *
if_mib_new_ifRcvAddressEntry(void);

extern void
if_mib_get_ifRcvAddressEntry(GNetSnmp *s, if_mib_ifRcvAddressEntry_t **ifRcvAddressEntry, gint32 ifIndex, guchar *ifRcvAddressAddress, guint16 _ifRcvAddressAddressLength, gint64 mask);

extern void
if_mib_set_ifRcvAddressEntry(GNetSnmp *s, if_mib_ifRcvAddressEntry_t *ifRcvAddressEntry, gint64 mask);

extern void
if_mib_free_ifRcvAddressEntry(if_mib_ifRcvAddressEntry_t *ifRcvAddressEntry);


G_END_DECLS

#endif /* _IF_MIB_H_ */