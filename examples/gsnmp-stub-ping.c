/*
 * gsnmp-stub-ping.c --
 *
 * A simple program to retrieve some data with the gnet-snmp API and
 * scli stub procedures generated by smidump. The stubs also validates
 * the received values against type, range or indexing errors.
 */

#include <stdlib.h>
#include <unistd.h>

#include "snmpv2-mib.h"

static const char *progname = "gsnmp-stub-ping";

static void
ping(GNetSnmp *s, int sflag)
{
    snmpv2_mib_system_t *system;
    
    snmpv2_mib_get_system(s, &system,
			  SNMPV2_MIB_SYSUPTIME | SNMPV2_MIB_SYSDESCR);
    if (s->error_status != GNET_SNMP_ERR_NOERROR) {
	g_printerr("%s: snmp error: %s @ %d\n", progname,
		   gnet_snmp_enum_get_label(gnet_snmp_enum_error_table,
					    s->error_status),
		   s->error_index);
	goto cleanup;
    }

    if (system && system->sysUpTime) {
	if (!sflag) {
	    g_print("%u: %.*s\n", *system->sysUpTime,
		    system->_sysDescrLength, system->sysDescr);
	}
    }

  cleanup:
    if (system) snmpv2_mib_free_system(system);
}

int
main(int argc, char **argv)
{
    GNetSnmp *s;
    GURI *uri;
    int i, c, iterations = 1, sflag = 0, tflag = 0;

    while ((c = getopt(argc, argv, "dl:st")) >= 0) {
	switch (c) {
	case 'd':
	    gnet_snmp_debug_flags = GNET_SNMP_DEBUG_ALL;
	    break;
	case 'l':
	    iterations = atoi(optarg);
	    break;
	case 's':
	    sflag = 1;
	    break;
	case 't':
	    tflag = 1;
	    break;
	default:
	    g_printerr("usage: %s [-d] [-l iterations] [-s] [-t] snmp-uri\n",
		       progname);
	    exit(EXIT_FAILURE);
	}
    }

    if (! gnet_snmp_init(FALSE)) {
	exit(1);
    }

    if (optind != argc-1) {
	g_printerr("gsnmp-walk: wrong number of arguments\n");
	exit(EXIT_FAILURE);
    }

    uri = gnet_snmp_parse_uri(argv[optind]);
    if (! uri) {
	g_printerr("%s: invalid snmp uri: %s\n", progname, argv[optind]);
	exit(1);
    }
    s = gnet_snmp_new_uri(uri);
    if (! s) {
	g_printerr("%s: unable to create session\n", progname);
	exit(1);
    }
    gnet_snmp_set_version(s, GNET_SNMP_V1);

    for (i = 0; i < iterations; i++) {
	ping(s, sflag);
    }
    
    gnet_snmp_delete(s);
    gnet_uri_delete(uri);
    
    return 0;
}
