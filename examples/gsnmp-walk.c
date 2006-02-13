/*
 * gsnmp-walk.c --
 *
 * A simple program to walk a MIB tree using the gnet-snmp API.
 */

#include "gsnmp.h"

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
	    if (! g_ascii_isprint(vb->value.ui8v[i])) break;
	}
	if (i == vb->value_len) {
	    g_print("%.*s", (gint) vb->value_len, vb->value.ui8v);
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
    if (s->error_status != GNET_SNMP_PDU_ERR_NOERROR
	&& s->error_status != GNET_SNMP_PDU_ERR_NOSUCHNAME) {
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
    gint i, r;
    static gint repeats = 1;
    static gboolean sflag = 0, dflag = 0;
    GNetSnmp *s;
    GError *error = NULL;
    GOptionContext *context;

    static GOptionEntry entries[] = {
	{ "repeats", 'r', 0, G_OPTION_ARG_INT, &repeats,
	  "Executes N times", "N" },
	{ "silent", 's', 0, G_OPTION_ARG_NONE, &sflag,
	  "Keep silent and produce no output", NULL },
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &dflag,
	  "Generate debug messages", NULL },
	{ NULL }
    };

    context = g_option_context_new("uri - walk snmp agents");
    g_option_context_add_main_entries(context, entries, NULL);
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
	    walk(s, sflag);
	}
	
	gnet_snmp_delete(s);
    }

    return 0;
}
