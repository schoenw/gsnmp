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


struct _GNetSnmpTable {
    GNetSnmp	 *snmp;
    GList 	 *orig_objs;
    GList	 *prev_objs;
    gpointer      data;
    gpointer      request;
    void       (* cb_error)(GNetSnmp *snmp, gpointer data);
    void       (* cb_row)(GNetSnmp *snmp, GList *vbl, int indexlen, gpointer data);
    void       (* cb_finish)(GNetSnmp *snmp, gpointer data);
};


static gboolean
g_snmp_table_done_callback(GNetSnmp *snmp,
                           GNetSnmpPdu *spdu, GList *objs, gpointer data)
{
    GNetSnmpTable   *table;
    GList        *nobjs; /* New varbind list for next query */
    GNetSnmpVarBind *cobj;  /* Current object being processed */
    GNetSnmpVarBind *obj;   /* Base object being processed */
    int           cols;  /* Number of columns we expect */
    int           i, j, eov = 0;
    guint32       index[GNET_SNMP_SIZE_OBJECTID];
    int           index_len;
    GList *cb_vbl = NULL;

    snmp->error_status = spdu->error_status;
    snmp->error_index = spdu->error_index;
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: error-status = %d, error-index = %d\n",
		   snmp, snmp->error_status, snmp->error_index);
    }
    
    table = (GNetSnmpTable *) data;
    table->request = 0;

    /* Check whether we reached the end of the MIB view... */
    
    cols = g_list_length(table->orig_objs);
    if (spdu->error_status == GNET_SNMP_PDU_ERR_NOSUCHNAME) {
	if (table->cb_finish) {
	    table->cb_finish(snmp, table->data);
	} else {
	    gnet_snmp_table_delete(table);
	}
	return TRUE;
    }
    
    /* Check whether we got an error back... */
    
    if (spdu->error_status) {
	if (table->cb_error) {
	    table->cb_error(snmp, table->data);
	} else {
	    gnet_snmp_table_delete(table);
	}
	return TRUE;
    }
    
    /* Check if the number of requested variables matches the number
       of returned variables */
    
    if (g_list_length(objs) != cols) {
	if (table->cb_error) {
	    table->cb_error(snmp, table->data);
	} else {
	    gnet_snmp_table_delete(table);
	}
	return TRUE;
    }
    
    /* Search smallest index in all valid returned columns. */

    index_len = 0;
    for (i = 0; i < cols; i++) {
	obj  = (GNetSnmpVarBind *) g_list_nth_data(table->orig_objs, i);
	cobj = (GNetSnmpVarBind *) g_list_nth_data(objs, i);
	if (cobj->oid_len >= obj->oid_len
	    && !memcmp (cobj->oid, obj->oid, obj->oid_len * sizeof (guint32))) {
	    if (!index_len) {
		index_len = cobj->oid_len - obj->oid_len;
		g_memmove(index, cobj->oid + obj->oid_len, 
			  index_len * sizeof (guint32));
            } else {
		if ((j=memcmp(index, cobj->oid + obj->oid_len, 
			      MIN(index_len, cobj->oid_len - obj->oid_len)
			      * sizeof (guint32)))) {
		    /* g_warning("Non-regular SNMP table"); (js) */
		    if (j>0) {
			index_len = cobj->oid_len - obj->oid_len;
			g_memmove(index, cobj->oid + obj->oid_len,
				  index_len * sizeof (guint32));
		    }
		}
		if (cobj->oid_len - obj->oid_len < index_len) {
		    g_warning("SNMP table index length changed");
		    index_len = cobj->oid_len - obj->oid_len;
                }
            }
	}
	if (cobj->type == GNET_SNMP_VARBIND_TYPE_ENDOFMIBVIEW) {
	    eov++;
        }
    }
    
    /* If no valid columns found, table query must be finished. */

    if (! index_len || eov) {
	if (table->cb_finish) {
	    table->cb_finish(snmp, table->data);
	} else {
	    gnet_snmp_table_delete(table);
	}
	return TRUE;
    }
    
    /* Build varbind list for the callback and construct a new varbind
       list for next row. */
    
    nobjs = NULL;
    for (i = 0; i < cols; i++) {
	obj  = (GNetSnmpVarBind *) g_list_nth_data(table->orig_objs, i);
	cobj = (GNetSnmpVarBind *) g_list_nth_data(objs, i);
	if (!memcmp (cobj->oid, obj->oid, obj->oid_len * sizeof (guint32))) {
	    if (cobj->oid_len - obj->oid_len == index_len)
		if (!memcmp(cobj->oid + obj->oid_len, index, 
			    index_len * sizeof (guint32))) {
		    cb_vbl = g_list_append(cb_vbl, cobj);
		}
	}
	if (obj->oid_len + index_len < GNET_SNMP_SIZE_OBJECTID) {
	    GNetSnmpVarBind *vb;
	    guint32 oid[GNET_SNMP_SIZE_OBJECTID];
	    g_memmove(oid, obj->oid, obj->oid_len * sizeof(guint32));
	    g_memmove(oid + obj->oid_len, index, index_len * sizeof(guint32)); 
	    vb = gnet_snmp_varbind_new(oid, obj->oid_len + index_len,
				       GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
	    nobjs = g_list_append(nobjs, vb);
	}
    }
    
    table->prev_objs = cb_vbl;

    if (table->cb_row) {
	table->cb_row(snmp, cb_vbl, index_len, table->data);
    }
    /* g_list_free(cb_vbl); ?? */
    
    table->request = gnet_snmp_async_getnext(table->snmp, nobjs, NULL);
#if 0
    g_list_foreach(nobjs, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(nobjs);
#endif
    return TRUE;
}


static void
g_snmp_table_time_callback(GNetSnmp *snmp, gpointer data)
{
    GNetSnmpTable *table;
    
    table = (GNetSnmpTable *) data;
    table->request = 0;
    if (table->cb_error) {
	table->cb_error(snmp, table->data);
    } else {
	gnet_snmp_table_delete(table);
    }

    snmp->error_index = 0;
    snmp->error_status = GNET_SNMP_PDU_ERR_NORESPONSE;
}


GNetSnmpTable *
gnet_snmp_table_new(GNetSnmp *snmp,
		    GList *vbl,
		    void (* cb_error)(),
		    void (* cb_row)(),
		    void (* cb_finish)(),
		    gpointer data)
{
    GList *elem;
    GNetSnmpTable *table;

    table          = g_malloc0(sizeof(GNetSnmpTable));

    table->snmp = gnet_snmp_clone(snmp);
    table->snmp->magic = table;
    table->snmp->done_callback = g_snmp_table_done_callback;
    table->snmp->time_callback = g_snmp_table_time_callback;
    
    for (elem = vbl; elem; elem = g_list_next(elem)) {
	GNetSnmpVarBind *vb = (GNetSnmpVarBind *) elem->data;
	GNetSnmpVarBind *nvb;
	nvb = gnet_snmp_varbind_new(vb->oid, vb->oid_len,
				   GNET_SNMP_VARBIND_TYPE_NULL, NULL, 0);
	table->orig_objs = g_list_append(table->orig_objs, nvb);
    }
    table->data = data;
    
    table->cb_error  = cb_error;
    table->cb_row    = cb_row;
    table->cb_finish = cb_finish;
    
    return table;
}


void
gnet_snmp_table_delete(GNetSnmpTable *table)
{
    if (table->request) {
	gnet_snmp_request_dequeue(table->request);
	gnet_snmp_request_delete(table->request);
    }
    gnet_snmp_delete(table->snmp);
    g_list_foreach(table->orig_objs, (GFunc) gnet_snmp_varbind_delete, NULL);
    g_list_free(table->orig_objs);
    g_free(table);
}


void
gnet_snmp_async_table(GNetSnmpTable *table, GError **error)
{
    table->request = gnet_snmp_async_getnext(table->snmp, table->orig_objs, error);
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
cb_row(GNetSnmp *snmp, GList *rowlist, int index_len, gpointer *data)
{
    GList **tablelist = (GList **) data;

    *tablelist = g_list_append(*tablelist, rowlist);
}


GList *
gnet_snmp_sync_table(GNetSnmp *s, GList *in, GError **error)
{
    GNetSnmpTable *table;
    GList *tablelist = NULL;

    table = gnet_snmp_table_new(s, in, cb_error, cb_row, cb_finish, &tablelist);

    gnet_snmp_async_table(table, error);

    loop = g_main_new(TRUE);
    while (loop && g_main_is_running(loop)) {
	g_main_run(loop);
    }
    g_main_destroy(loop);
    loop = NULL;

    s->error_status = table->snmp->error_status;
    s->error_index = table->snmp->error_index;

    gnet_snmp_table_delete(table);
    
    return tablelist;
}

