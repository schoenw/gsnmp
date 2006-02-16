/*
 * gsnmp-get.c --
 *
 * A simple program to retrieve SNMP information by using snmp: URIs
 * as specified in RFC 4088.
 */

#include <unistd.h>

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
walk(GNetSnmp *s, GList *vbl, int sflag)
{
    GList *out = NULL;

    out = gnet_snmp_sync_walk(s, vbl);
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
    }

  cleanup:
    g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(out);
}

static void
next(GNetSnmp *s, GList *vbl, int sflag)
{
    GList *out;
    
    out = gnet_snmp_sync_getnext(s, vbl);
    if (s->error_status != GNET_SNMP_PDU_ERR_NOERROR) {
	g_printerr("snmp error: %s @ %d\n",
		   gnet_snmp_enum_get_label(gnet_snmp_enum_error_table,
					    s->error_status),
		   s->error_index);
	return;
    }

    if (!sflag) {
	g_list_foreach(out, print, NULL);
    }

    g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(out);
}

static void
get(GNetSnmp *s, GList *vbl, int sflag)
{
    GList *out;
    
    out = gnet_snmp_sync_get(s, vbl);
    if (s->error_status != GNET_SNMP_PDU_ERR_NOERROR) {
	g_printerr("snmp error: %s @ %d\n",
		   gnet_snmp_enum_get_label(gnet_snmp_enum_error_table,
					    s->error_status),
		   s->error_index);
	return;
    }

    if (!sflag) {
	g_list_foreach(out, print, NULL);
    }

    g_list_foreach(out, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(out);
}

int
main(int argc, char **argv)
{
    gint i, r;
    GList *vbl = NULL;
    GURI *uri;
    GNetSnmp *s;
    GNetSnmpUriType type;
    static gint repeats = 1;
    static gboolean sflag = 0, dflag = 0;
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

    context = g_option_context_new("uri - retrieve OIDs from snmp agents");
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
	uri = gnet_snmp_parse_uri(argv[i]);
	if (! uri) {
	    g_printerr("%s: invalid snmp uri: %s\n",
		       g_get_prgname(), argv[i]);
	    return 1;
	}
	
	if (! gnet_snmp_parse_path(uri->path, &vbl, &type, &error)) {
	    if (error) {
		g_printerr("%s: %s\n", g_get_prgname(), error->message);
	    }
	    gnet_uri_delete(uri);
	    return 1;
	}
	
	g_print("%s ", argv[i]);
	switch (type) {
	case GNET_SNMP_URI_GET:
	    g_print("(get):\n");
	    break;
	case GNET_SNMP_URI_NEXT:
	    g_print("(next):\n");
	    break;
	case GNET_SNMP_URI_WALK:
	    g_print("(walk):\n");
	    break;
	}
	
	s = gnet_snmp_new_uri(uri);
	if (! s) {
	    g_printerr("%s: unable to create session\n", g_get_prgname());
	    return 1;
	}
	
	for (r = 0; r < repeats; r++) {
	    switch (type) {
	    case GNET_SNMP_URI_GET:
		get(s, vbl, sflag);
		break;
	    case GNET_SNMP_URI_NEXT:
		next(s, vbl, sflag);
		break;
	    case GNET_SNMP_URI_WALK:
		walk(s, vbl, sflag);
		break;
	    }
	}
	
	g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(vbl);
	
	gnet_snmp_delete(s);
	gnet_uri_delete(uri);
    }
    
    return 0;
}
