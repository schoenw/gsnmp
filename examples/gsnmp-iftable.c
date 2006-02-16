/*
 * gsnmp-iftable.c --
 *
 * A simple program to retrieve and display some data from the
 * standard interface table.
 */

#include "ianaiftype-mib.h"
#include "if-mib.h"

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
    g_print("Interface table at <%s>:\n", s);
    g_free(s);

    if_mib_get_ifTable(snmp, &ifTable, IF_MIB_IFDESCR | IF_MIB_IFTYPE
		       | IF_MIB_IFADMINSTATUS | IF_MIB_IFOPERSTATUS);
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
    gint i, r;
    static gint repeats = 1;
    static gboolean dflag = 0;
    GNetSnmp *s;
    GError *error = NULL;
    GOptionContext *context;

    static GOptionEntry entries[] = {
	{ "repeats", 'r', 0, G_OPTION_ARG_INT, &repeats,
	  "Executes N times", "N" },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &dflag,
	  "Generate debug messages", NULL },
	{ NULL }
    };

    context = g_option_context_new("uri - display snmp interface info");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_add_group (context, gnet_snmp_get_option_group());    
    if (! g_option_context_parse(context, &argc, &argv, &error)) {
	g_printerr("%s: %s\n", g_get_prgname(),
		   (error && error->message) ? error->message
		   : "option parsing failed");
	return 1;
    }

    if (dflag) {
	gnet_snmp_debug_flags = GNET_SNMP_DEBUG_ALL;
    }

    for (i = 1; i < argc; i++) {
	s = gnet_snmp_new_string(argv[i], &error);
	if (! s) {
	    g_printerr("%s: %s\n", g_get_prgname(),
		       (error && error->message) ? error->message
		       : "creating SNMP session failed");
	    return 1;
	}

	for (r = 0; r < repeats; r++) {
	    show_iftable(s);
	}
	
	gnet_snmp_delete(s);
    }
    
    return 0;
}
