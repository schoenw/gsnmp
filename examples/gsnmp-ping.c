/*
 * gsnmp-ping.c --
 *
 * A simple program to retrieve sysUpTime.0 and sysDescr.0 using the
 * gnet-snmp API.
 */

#include "gsnmp.h"

static void
print(gpointer data, gpointer user)
{
    GNetSnmpVarBind *vb = (GNetSnmpVarBind *) data;
    switch (vb->type) {
    case GNET_SNMP_VARBIND_TYPE_OCTETSTRING:
	g_print("%.*s", (gint) vb->value_len, vb->value.ui8v);
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
    if (s->error_status != GNET_SNMP_PDU_ERR_NOERROR) {
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
    gint i, r;
    static gint repeats = 1;
    static gboolean sflag = 0;
    GNetSnmp *s;
    GError *error = NULL;
    GOptionContext *context;

    static GOptionEntry entries[] = {
	{ "repeats", 'r', 0, G_OPTION_ARG_INT, &repeats,
	  "Executes N times", "N" },
	{ "silent", 's', 0, G_OPTION_ARG_NONE, &sflag,
	  "Keep silent and produce no output", NULL },
	{ NULL }
    };

    context = g_option_context_new("uri - ping snmp agents");
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_add_group (context, gnet_snmp_get_option_group());    
    if (! g_option_context_parse(context, &argc, &argv, &error)) {
	g_printerr("%s: %s\n", g_get_prgname(),
		   (error && error->message) ? error->message
		   : "option parsing failed");
	return 1;
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
	    ping(s, sflag);
	}
	
	gnet_snmp_delete(s);
    }
    
    return 0;
}
