/*
 * gsnmp-walk.c --
 *
 * A simple program to walk a MIB using the gnet-snmp API.
 */

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "gsnmp.h"

static const char *progname = "gsnmp-walk";

static void
print(gpointer data, gpointer user)
{
    GNetSnmpVarBind *vb = (GNetSnmpVarBind *) data;
    gint i;

    for (i = 0; i < vb->oid_len; i++) {
	g_print("%s%u", i ? "." : "", vb->oid[i]);
    }
    g_print(" = ");
    
    switch (vb->type) {
    case GNET_SNMP_VARBIND_TYPE_NULL:
	g_print("[NULL]");
	break;
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	for (i = 0; i < vb->value_len; i++) {
	    if (! isprint(vb->value.ui8v[i])) break;
	}
	if (i == vb->value_len) {
	    g_print("%.*s", vb->value_len, vb->value.ui8v);
	} else {
	    for (i = 0; i < vb->value_len; i++) {
		g_print("%s%02x", i ? ":" : "", vb->value.ui8v[i]);
	    }
	}
	break;
    case GNET_SNMP_VARBIND_TYPE_OBJECTID:
	for (i = 0; i < vb->value_len; i++) {
	    g_print("%s%u", i ? "." : "", vb->value.ui32v[i]);
	}
	break;
    case GNET_SNMP_VARBIND_TYPE_IPADDRESS:
	if (vb->value_len == 4) {
	    g_print("%d.%d.%d.%d",
		    vb->value.ui8v[0], vb->value.ui8v[1],
		    vb->value.ui8v[2], vb->value.ui8v[3]);
	}
	break;
    case GNET_SNMP_VARBIND_TYPE_INTEGER32:
	g_print("%u", vb->value.i32);
	break;
    case GNET_SNMP_VARBIND_TYPE_UNSIGNED32:
	g_print("%u", vb->value.ui32);
	break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER32:
	g_print("%u", vb->value.ui32);
	break;
    case GNET_SNMP_VARBIND_TYPE_TIMETICKS:
	g_print("%u", vb->value.ui32);
	break;
    case GNET_SNMP_VARBIND_TYPE_OPAQUE:
	for (i = 0; i < vb->value_len; i++) {
	    g_print("%s%02x", i ? ":" : "", vb->value.ui8v[i]);
	}
	break;
    case GNET_SNMP_VARBIND_TYPE_COUNTER64:
	g_print("%llu", vb->value.ui64);
	break;
    case GNET_SNMP_VARBIND_TYPE_NOSUCHOBJECT:
	g_print("[NOSUCHOBJECT]");
	break;
    case GNET_SNMP_VARBIND_TYPE_NOSUCHINSTANCE:
	g_print("[NOSUCHINSTANCE]");
	break;
    case GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW:
	g_print("[ENDOFMIBVIEW]");
	break;
    }
    g_print("\n");
}

static void
walk(GNetSnmp *s, int sflag)
{
    GURI *uri;
    GNetSnmpVarBind *vb;
    GList *in = NULL, *out = NULL;
    guint32 iso_org[] = { 1, 3, 6, 1, 2 };	/* SNMPv2-SMI::mib-2 */

    uri = gnet_snmp_get_uri(s);
    if (uri) {
	gchar *name = gnet_uri_get_string(uri);
	g_print("walking <%s>:\n", name);
	g_free(name);
    }

    vb = gnet_snmp_varbind_new(iso_org, G_N_ELEMENTS(iso_org),
			       GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
    in = g_list_append(in, vb);
    out = gnet_snmp_sync_walk(s, in);
    if (s->error_status != GNET_SNMP_ERR_NOERROR
	&& s->error_status != GNET_SNMP_ERR_NOSUCHNAME) {
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
    g_list_foreach(in,  (GFunc) gnet_snmp_varbind_delete, NULL);
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
        walk(s, sflag);
    }

    gnet_snmp_delete(s);
    gnet_uri_delete(uri);

    return 0;
}
