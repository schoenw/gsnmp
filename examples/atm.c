/*
 * This example creates an entry in the atm traffic description
 * parameter table. This example was motivated by Marek Malowidzki
 * <malowidz@wil.waw.pl> who wanted to see how complicated and how
 * readable this code would be. Judge yourself.
 *
 * Compile using the following command line:
 *
 * gcc -g `pkg-config --cflags gsnmp gnet` -o atm atm.c \
 *	   snmpv2-tc.c atm-tc-mib.c atm-mib.c \
 *	   `pkg-config --libs gsnmp gnet`
 */

#include <stdlib.h>

#include "snmpv2-tc.h"
#include "atm-tc-mib.h"
#include "atm-mib.h"

static gint32 createAndGo = SNMPV2_TC_ROWSTATUS_CREATEANDGO;
static gint32 on = SNMPV2_TC_TRUTHVALUE_TRUE;

static guint32 noclpnoscr[] = { ATM_TC_MIB_ATMNOCLPNOSCR };
static gint32 cbr = ATM_TC_MIB_ATMSERVICECATEGORY_CBR;

int
main()
{
    GNetSnmp *s;
    GError *error = NULL;
    atm_mib_atmMIBObjects_t *o;
    atm_mib_atmTrafficDescrParamEntry_t *p;
    gint32 param1 = 500;
    const char *uri_string = "snmp://public@localhost/";

    s = gnet_snmp_new_string(uri_string, &error);
    if (error) {
	g_printerr("%s: %s\n", g_get_prgname(), error->message);
	exit(1);
    }

    atm_mib_get_atmMIBObjects(s, &o, ATM_MIB_ATMTRAFFICDESCRPARAMINDEXNEXT, &error);
    if (error || s->error_status || !o || !o->atmTrafficDescrParamIndexNext) return 2;
    
    p = atm_mib_new_atmTrafficDescrParamEntry();
    p->atmTrafficDescrParamIndex = *o->atmTrafficDescrParamIndexNext;
    p->atmTrafficDescrType = noclpnoscr;
    p->_atmTrafficDescrTypeLength = G_N_ELEMENTS(noclpnoscr);
    p->atmTrafficDescrParam1 = &param1;
    p->atmTrafficDescrRowStatus = &createAndGo;
    p->atmServiceCategory = &cbr;
    p->atmTrafficFrameDiscard = &on;
    atm_mib_set_atmTrafficDescrParamEntry(s, p, 0, &error);
    if (error || s->error_status) return 3;

    atm_mib_free_atmMIBObjects(o);
    atm_mib_free_atmTrafficDescrParamEntry(p);

    gnet_snmp_delete(s);

    return 0;
}
