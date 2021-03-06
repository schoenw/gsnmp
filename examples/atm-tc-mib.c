/*							-- DO NOT EDIT --
 * Generated by smidump version 0.4.8:
 *   smidump -f scli ATM-TC-MIB
 *
 * Derived from ATM-TC-MIB:
 *   This MIB Module provides Textual Conventions
 *   and OBJECT-IDENTITY Objects to be used by
 *   ATM systems.
 *
 * Revision 1998-10-19 02:00:
 *   [Revision added by libsmi due to a LAST-UPDATED clause.]
 *
 * $Id$
 */

#include "atm-tc-mib.h"

GNetSnmpEnum const atm_tc_mib_enums_AtmConnCastType[] = {
    { ATM_TC_MIB_ATMCONNCASTTYPE_P2P,      "p2p" },
    { ATM_TC_MIB_ATMCONNCASTTYPE_P2MPROOT, "p2mpRoot" },
    { ATM_TC_MIB_ATMCONNCASTTYPE_P2MPLEAF, "p2mpLeaf" },
    { 0, NULL }
};

GNetSnmpEnum const atm_tc_mib_enums_AtmConnKind[] = {
    { ATM_TC_MIB_ATMCONNKIND_PVC,           "pvc" },
    { ATM_TC_MIB_ATMCONNKIND_SVCINCOMING,   "svcIncoming" },
    { ATM_TC_MIB_ATMCONNKIND_SVCOUTGOING,   "svcOutgoing" },
    { ATM_TC_MIB_ATMCONNKIND_SPVCINITIATOR, "spvcInitiator" },
    { ATM_TC_MIB_ATMCONNKIND_SPVCTARGET,    "spvcTarget" },
    { 0, NULL }
};

GNetSnmpEnum const atm_tc_mib_enums_AtmInterfaceType[] = {
    { ATM_TC_MIB_ATMINTERFACETYPE_OTHER,            "other" },
    { ATM_TC_MIB_ATMINTERFACETYPE_AUTOCONFIG,       "autoConfig" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ITUDSS2,          "ituDss2" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFUNI3DOT0,     "atmfUni3Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFUNI3DOT1,     "atmfUni3Dot1" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFUNI4DOT0,     "atmfUni4Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFIISPUNI3DOT0, "atmfIispUni3Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFIISPUNI3DOT1, "atmfIispUni3Dot1" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFIISPUNI4DOT0, "atmfIispUni4Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFPNNI1DOT0,    "atmfPnni1Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFBICI2DOT0,    "atmfBici2Dot0" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFUNIPVCONLY,   "atmfUniPvcOnly" },
    { ATM_TC_MIB_ATMINTERFACETYPE_ATMFNNIPVCONLY,   "atmfNniPvcOnly" },
    { 0, NULL }
};

GNetSnmpEnum const atm_tc_mib_enums_AtmServiceCategory[] = {
    { ATM_TC_MIB_ATMSERVICECATEGORY_OTHER,  "other" },
    { ATM_TC_MIB_ATMSERVICECATEGORY_CBR,    "cbr" },
    { ATM_TC_MIB_ATMSERVICECATEGORY_RTVBR,  "rtVbr" },
    { ATM_TC_MIB_ATMSERVICECATEGORY_NRTVBR, "nrtVbr" },
    { ATM_TC_MIB_ATMSERVICECATEGORY_ABR,    "abr" },
    { ATM_TC_MIB_ATMSERVICECATEGORY_UBR,    "ubr" },
    { 0, NULL }
};

GNetSnmpEnum const atm_tc_mib_enums_AtmVorXAdminStatus[] = {
    { ATM_TC_MIB_ATMVORXADMINSTATUS_UP,   "up" },
    { ATM_TC_MIB_ATMVORXADMINSTATUS_DOWN, "down" },
    { 0, NULL }
};

GNetSnmpEnum const atm_tc_mib_enums_AtmVorXOperStatus[] = {
    { ATM_TC_MIB_ATMVORXOPERSTATUS_UP,      "up" },
    { ATM_TC_MIB_ATMVORXOPERSTATUS_DOWN,    "down" },
    { ATM_TC_MIB_ATMVORXOPERSTATUS_UNKNOWN, "unknown" },
    { 0, NULL }
};


static guint32 const atmNoTrafficDescriptor[]
	= { ATM_TC_MIB_ATMNOTRAFFICDESCRIPTOR };
static guint32 const atmNoClpNoScr[]
	= { ATM_TC_MIB_ATMNOCLPNOSCR };
static guint32 const atmClpNoTaggingNoScr[]
	= { ATM_TC_MIB_ATMCLPNOTAGGINGNOSCR };
static guint32 const atmClpTaggingNoScr[]
	= { ATM_TC_MIB_ATMCLPTAGGINGNOSCR };
static guint32 const atmNoClpScr[]
	= { ATM_TC_MIB_ATMNOCLPSCR };
static guint32 const atmClpNoTaggingScr[]
	= { ATM_TC_MIB_ATMCLPNOTAGGINGSCR };
static guint32 const atmClpTaggingScr[]
	= { ATM_TC_MIB_ATMCLPTAGGINGSCR };
static guint32 const atmClpNoTaggingMcr[]
	= { ATM_TC_MIB_ATMCLPNOTAGGINGMCR };
static guint32 const atmClpTransparentNoScr[]
	= { ATM_TC_MIB_ATMCLPTRANSPARENTNOSCR };
static guint32 const atmClpTransparentScr[]
	= { ATM_TC_MIB_ATMCLPTRANSPARENTSCR };
static guint32 const atmNoClpTaggingNoScr[]
	= { ATM_TC_MIB_ATMNOCLPTAGGINGNOSCR };
static guint32 const atmNoClpNoScrCdvt[]
	= { ATM_TC_MIB_ATMNOCLPNOSCRCDVT };
static guint32 const atmNoClpScrCdvt[]
	= { ATM_TC_MIB_ATMNOCLPSCRCDVT };
static guint32 const atmClpNoTaggingScrCdvt[]
	= { ATM_TC_MIB_ATMCLPNOTAGGINGSCRCDVT };
static guint32 const atmClpTaggingScrCdvt[]
	= { ATM_TC_MIB_ATMCLPTAGGINGSCRCDVT };

GNetSnmpIdentity const atm_tc_mib_identities[] = {
    { atmNoTrafficDescriptor,
      G_N_ELEMENTS(atmNoTrafficDescriptor),
      "atmNoTrafficDescriptor" },
    { atmNoClpNoScr,
      G_N_ELEMENTS(atmNoClpNoScr),
      "atmNoClpNoScr" },
    { atmClpNoTaggingNoScr,
      G_N_ELEMENTS(atmClpNoTaggingNoScr),
      "atmClpNoTaggingNoScr" },
    { atmClpTaggingNoScr,
      G_N_ELEMENTS(atmClpTaggingNoScr),
      "atmClpTaggingNoScr" },
    { atmNoClpScr,
      G_N_ELEMENTS(atmNoClpScr),
      "atmNoClpScr" },
    { atmClpNoTaggingScr,
      G_N_ELEMENTS(atmClpNoTaggingScr),
      "atmClpNoTaggingScr" },
    { atmClpTaggingScr,
      G_N_ELEMENTS(atmClpTaggingScr),
      "atmClpTaggingScr" },
    { atmClpNoTaggingMcr,
      G_N_ELEMENTS(atmClpNoTaggingMcr),
      "atmClpNoTaggingMcr" },
    { atmClpTransparentNoScr,
      G_N_ELEMENTS(atmClpTransparentNoScr),
      "atmClpTransparentNoScr" },
    { atmClpTransparentScr,
      G_N_ELEMENTS(atmClpTransparentScr),
      "atmClpTransparentScr" },
    { atmNoClpTaggingNoScr,
      G_N_ELEMENTS(atmNoClpTaggingNoScr),
      "atmNoClpTaggingNoScr" },
    { atmNoClpNoScrCdvt,
      G_N_ELEMENTS(atmNoClpNoScrCdvt),
      "atmNoClpNoScrCdvt" },
    { atmNoClpScrCdvt,
      G_N_ELEMENTS(atmNoClpScrCdvt),
      "atmNoClpScrCdvt" },
    { atmClpNoTaggingScrCdvt,
      G_N_ELEMENTS(atmClpNoTaggingScrCdvt),
      "atmClpNoTaggingScrCdvt" },
    { atmClpTaggingScrCdvt,
      G_N_ELEMENTS(atmClpTaggingScrCdvt),
      "atmClpTaggingScrCdvt" },
    { 0, 0, NULL }
};


