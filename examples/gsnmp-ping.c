/*
 * gsnmp-ping.c --
 *
 * A simple program to retrieve some data with the gnet-snmp API.
 */

#include "gsnmp.h"

#include <stdlib.h>
#include <unistd.h>

static const char *progname = "gsnmp-ping";

static void
print(gpointer data, gpointer user)
{
    GNetSnmpVarBind *vb = (GNetSnmpVarBind *) data;
    switch (vb->type) {
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	g_print("%.*s", vb->value_len, vb->value.ui8v);
	break;
    case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	g_print("%u: ", vb->value.ui32);
	break;
    default:
	break;
    }
}

static void
ping(GNetSnmp *s, int sflag)
{
    GNetSnmpVarBind *vb;
    GList *in = NULL, *out = NULL;
    guint32 n1[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };	/* sysUpTime.0 */
    guint32 n2[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };	/* sysDescr.0 */

    vb = gnet_snmp_varbind_new(n1, sizeof(n1)/sizeof(n1[0]),
			       GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
    in = g_list_append(in, vb);
    vb = gnet_snmp_varbind_new(n2, sizeof(n2)/sizeof(n2[0]),
			       GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
    in = g_list_append(in, vb);

    out = gnet_snmp_sync_get(s, in);
    if (s->error_status != GNET_SNMP_ERR_NOERROR) {
	g_printerr("snmp error: %s @ %d\n",
		   gnet_snmp_enum_get_label(gnet_snmp_enum_error_table,
					    s->error_status),
		   s->error_index);
	goto cleanup;
    }

    if (!sflag) {
	g_list_foreach(out, print, NULL);
	g_print("\n");
    }

  cleanup:
    g_list_foreach(in, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(in);
    g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(out);
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
