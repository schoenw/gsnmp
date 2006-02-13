/*
 * GNET-SNMP -- glib-based SNMP implementation
 *
 * Copyright (c) 2003 Juergen Schoenwaelder
 * Copyright (c) 1998 Gregory McLean & Jochen Friedrich
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

#include "gsnmp.h"


struct _GNetSnmpWalk {
    GNetSnmp     *snmp;
    GList        *orig_objs;
    GList	 *prev_objs;
    gpointer      data;
    gpointer      request;
    void       (* cb_error)(GNetSnmp *snmp, gpointer data);
    void       (* cb_row)(GNetSnmp *snmp, GList *vbl, gpointer data);
    void       (* cb_finish)(GNetSnmp *snmp, gpointer data);
};



static gboolean
g_snmp_walk_done_callback(GNetSnmp *snmp, 
			  GNetSnmpPdu *pdu, GList *objs, gpointer data)
{
    GNetSnmpWalk   *walk;
    GList	*elem, *orig_elem, *prev_elem;
    int		endofviews = 0;
    
    snmp->error_status = pdu->error_status;
    snmp->error_index = pdu->error_index;
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: error-status = %d, error-index = %d\n",
		   snmp, snmp->error_status, snmp->error_index);
    }

    walk = (GNetSnmpWalk *) data;
    walk->request = 0;

    /*
     * Check whether we got an error or reached the end of the MIB view.
     */
    
    if (pdu->error_status == GNET_SNMP_PDU_ERR_NOSUCHNAME) {
	if (walk->cb_finish) {
	    walk->cb_finish(snmp, walk->data);
	} else {
	    gnet_snmp_walk_delete(walk);
	}
	return TRUE;
    }
    if (pdu->error_status) {
	if (walk->cb_error) {
	    walk->cb_error(snmp, walk->data);
	} else {
	    gnet_snmp_walk_delete(walk);
	}
	return TRUE;
    }

    /*
     * Check whether we got end of mib view exceptions for all varbinds.
     */

    for (elem = objs; elem; elem = g_list_next(elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	if (vb->type == GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW) {
	    endofviews++;
	}
    }
    if (endofviews == g_list_length(objs)) {
	if (walk->cb_finish) {
	    walk->cb_finish(snmp, walk->data);
	} else {
	    gnet_snmp_walk_delete(walk);
	}
	return TRUE;
    }

#if 1
    /* sanity check whether the new oid is larger than the previous */

    for (elem = objs, prev_elem = walk->prev_objs;
	 elem && prev_elem;
	 elem = g_list_next(elem), prev_elem = g_list_next(prev_elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	GNetSnmpVarBind *prev_vb = (GNetSnmpVarBind *) prev_elem->data;
	int x;

	x = gnet_snmp_compare_oids(prev_vb->oid, prev_vb->oid_len,
				   vb->oid, vb->oid_len);
	if (x >= 0) {
	    if (walk->cb_error) {
		walk->cb_error(snmp, walk->data);
	    } else {
		gnet_snmp_walk_delete(walk);
	    }
	    return TRUE;
	}
    }
#endif

    /* Check whether the new oid is within the scope of the walk. */

    for (elem = objs, orig_elem = walk->orig_objs;
	 elem && orig_elem;
	 elem = g_list_next(elem), orig_elem = g_list_next(orig_elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	GNetSnmpVarBind *orig_vb = (GNetSnmpVarBind *) orig_elem->data;

	if (vb->oid_len < orig_vb->oid_len
	    || memcmp(vb->oid, orig_vb->oid, orig_vb->oid_len * sizeof(guint32))) {
	    if (walk->cb_finish) {
		walk->cb_finish(snmp, walk->data);
	    } else {
		gnet_snmp_walk_delete(walk);
	    }
	    g_list_foreach(objs, (GFunc) gnet_snmp_varbind_delete, NULL);
	    g_list_free(objs);
	    return TRUE;
	}
    }

#if 0
    if (walk->prev_objs) {
	g_list_foreach(walk->prev_objs, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(walk->prev_objs);
    }
#endif
    
    walk->prev_objs = objs;

    if (walk->cb_row) {
	walk->cb_row(snmp, objs, walk->data);
    }

    walk->request = gnet_snmp_async_getnext(snmp, objs);

    return TRUE;
}  



static void
g_snmp_walk_time_callback(GNetSnmp *snmp, gpointer data)
{
    GNetSnmpWalk *walk;
    
    walk = (GNetSnmpWalk *) data;
    walk->request = 0;
    if (walk->cb_error) {
	walk->cb_error(snmp, walk->data);
    } else {
	gnet_snmp_walk_delete(walk);
    }

    snmp->error_index = 0;
    snmp->error_status = GNET_SNMP_PDU_ERR_NORESPONSE;
}



GNetSnmpWalk *
gnet_snmp_walk_new(GNetSnmp *session,
		   GList *vbl,
		   void (* cb_error)(),
		   void (* cb_row)(),
		   void (* cb_finish)(),
		   gpointer data)
{
    GList *elem;
    GNetSnmpWalk *walk;

    walk          = g_malloc0(sizeof(GNetSnmpWalk));

    walk->snmp = gnet_snmp_clone(session);
    walk->snmp->magic = walk;
    walk->snmp->done_callback = g_snmp_walk_done_callback;
    walk->snmp->time_callback = g_snmp_walk_time_callback;
    
    for (elem = vbl; elem; elem = g_list_next(elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	GNetSnmpVarBind *nvb;
	nvb = gnet_snmp_varbind_new(vb->oid, vb->oid_len,
				    GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
	walk->orig_objs = g_list_append(walk->orig_objs, nvb);
    }
    walk->data = data;
    
    walk->cb_error  = cb_error;
    walk->cb_row    = cb_row;
    walk->cb_finish = cb_finish;
    
    return walk;
}



void
gnet_snmp_walk_delete(GNetSnmpWalk *walk)
{
    if (walk->request) {
	gnet_snmp_request_dequeue(walk->request);
	gnet_snmp_request_delete(walk->request);
    }
    g_list_foreach(walk->orig_objs, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(walk->orig_objs);
    gnet_snmp_delete(walk->snmp);
    g_free(walk);
}



void
gnet_snmp_async_walk(GNetSnmpWalk *walk)
{
    walk->request = gnet_snmp_async_getnext(walk->snmp,
					    walk->orig_objs);
}



/*
 * Another entry point which is used by the scli package.
 */

static GMainLoop *loop = NULL;


static void
cb_finish(GNetSnmp *snmp, gpointer *data)
{
    if (loop) g_main_quit(loop);
}



static void
cb_error(GNetSnmp *snmp, gpointer *data)
{
    if (loop) g_main_quit(loop);
}



static void
cb_row(GNetSnmp *snmp, GList *vbl, gpointer *data)
{
    GList **walklist = (GList **) data;
    GList *elem;

    for (elem = vbl; elem; elem = g_list_next(elem)) {
	*walklist = g_list_append(*walklist, elem->data);
    }
}



GList*
gnet_snmp_sync_walk(GNetSnmp *s, GList *in)
{
    GNetSnmpWalk *walk;
    GList *walklist = NULL;

    walk = gnet_snmp_walk_new(s, in, cb_error, cb_row, cb_finish, &walklist);

    gnet_snmp_async_walk(walk);

    loop = g_main_new(TRUE);
    while (loop && g_main_is_running(loop)) {
	g_main_run(loop);
    }
    g_main_destroy(loop);
    loop = NULL;

    s->error_status = walk->snmp->error_status;
    s->error_index = walk->snmp->error_index;

    gnet_snmp_walk_delete(walk);
    
    return walklist;
}

