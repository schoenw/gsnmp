/*
 * gsnmp-iftable.c --
 *
 * A simple program to retrieve some data from the interface table.
 */

#include <stdlib.h>
#include <unistd.h>

#include "ianaiftype-mib.h"
#include "if-mib.h"

static const char *progname = "gsnmp-iftable";

static void
show_ifentry(if_mib_ifEntry_t *ifEntry)
{
    const char *ifType = NULL;
    const char *ifAdminStatus = NULL;
    const char *ifOperStatus = NULL;

    if (ifEntry->ifType) {
	ifType = gnet_snmp_enum_get_label(ianaiftype_mib_enums_IANAifType,
					  *ifEntry->ifType);
    }
    if (ifEntry->ifAdminStatus) {
	ifAdminStatus = gnet_snmp_enum_get_label(if_mib_enums_ifAdminStatus,
						 *ifEntry->ifAdminStatus);
    }
    if (ifEntry->ifOperStatus) {
	ifOperStatus = gnet_snmp_enum_get_label(if_mib_enums_ifOperStatus,
						*ifEntry->ifOperStatus);
    }
    g_print("%8d %-16s %-8s %-8s %.*s\n",
	    ifEntry->ifIndex,
	    ifType ? ifType : "",
	    ifAdminStatus ? ifAdminStatus : "",
	    ifOperStatus ? ifOperStatus : "",
	    ifEntry->_ifDescrLength, ifEntry->ifDescr);
}

static void
show_iftable(GNetSnmp *snmp)
{
    if_mib_ifEntry_t **ifTable;
    int i;
    gchar *s;

    s = gnet_uri_get_string(gnet_snmp_get_uri(snmp));
    g_print("<%s>:\n", s);
    g_free(s);

#if 0
    if_mib_get_ifTable(snmp, &ifTable, IF_MIB_IFDESCR | IF_MIB_IFTYPE
		       | IF_MIB_IFADMINSTATUS | IF_MIB_IFOPERSTATUS);
#else
    if_mib_get_ifTable(snmp, &ifTable, 0);
#endif
    if (! snmp->error_status && ifTable) {
	for (i = 0; ifTable[i]; i++) {
	    show_ifentry(ifTable[i]);
	}
    }

    if (ifTable) if_mib_free_ifTable(ifTable);
}

int
main(int argc, char **argv)
{
    GNetSnmp *snmp;
    GURI *uri;
    int c, tflag = 0;

    while ((c = getopt(argc, argv, "dt")) >= 0) {
	switch (c) {
	case 'd':
#if 0
	    gnet_snmp_debug_flags = GNET_SNMP_DEBUG_ALL;
#else
	    gnet_snmp_debug_flags = GNET_SNMP_DEBUG_SESSION
		    | GNET_SNMP_DEBUG_REQUESTS;
#endif
	    break;
	case 't':
	    tflag = 1;
	    break;
	default:
	    g_printerr("usage: %s [-d] [-t] [snmp-uri ...]\n", progname);
	    exit(EXIT_FAILURE);
	}
    }

    if (! gnet_snmp_init(FALSE)) {
	exit(1);
    }

    for (; optind < argc; optind++) {
	
	uri = gnet_snmp_parse_uri(argv[optind]);
	if (! uri) {
	    g_printerr("%s: invalid snmp uri: %s\n", progname, argv[optind]);
	    continue;
	}
	
	snmp = gnet_snmp_new_uri(uri);
	if (! snmp) {
	    g_printerr("%s: unable to create session\n", progname);
	    gnet_uri_delete(uri);
	    continue;
	}
	gnet_snmp_set_version(snmp, GNET_SNMP_V1);
	
	show_iftable(snmp);
	
	gnet_snmp_delete(snmp);
	gnet_uri_delete(uri);
    }
    
    return 0;
}

