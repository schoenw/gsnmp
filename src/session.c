/*
 * GNET-SNMP -- glib-based SNMP library
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>

static GSList  *request_queue = NULL;   /* queue of active requests */
static int initialized = 0;

guint           gnet_snmp_retries = GNET_SNMP_DEFAULT_RETRIES;
guint           gnet_snmp_timeout = GNET_SNMP_DEFAULT_TIMEOUT;
GNetSnmpVersion gnet_snmp_version = GNET_SNMP_V2C;

static int g_snmp_timeout_cb(gpointer data);

GQuark
gnet_snmp_error_quark(void)
{
    static GQuark quark = 0;
    if (quark == 0) {
	quark = g_quark_from_static_string("gnet-snmp-error-quark");
    }
    return quark;
}

/*
 * Allocate a new session data structure.
 */

GNetSnmp*
gnet_snmp_new()
{
    GNetSnmp *session;

    if (! initialized) {
	g_timeout_add(100, g_snmp_timeout_cb, NULL);
    }

    session = g_malloc0(sizeof(GNetSnmp));
    session->tdomain = GNET_SNMP_TDOMAIN_NONE;
    session->taddress = NULL;
    session->retries = gnet_snmp_retries;
    session->timeout = gnet_snmp_timeout;
    session->version = gnet_snmp_version;
    session->sec_level = GNET_SNMP_SECLEVEL_NANP;
    session->sec_model = GNET_SNMP_SECMODEL_ANY;
    session->sec_name = g_string_new(NULL);
    session->ctxt_name = g_string_new(NULL);

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: new\n", session);
    }
    return session;
}

/**
 * gnet_snmp_new_uri:
 * @uri: the snmp: uri
 *
 * Allocate and initialize a new GNetSnmp session.
 *
 * Returns: a pointer to a new GNetSnmp session.
 */

/* XXX must use the glib error handling mechanism here (and in other
   XXX session related functions) */

/* XXX what about TCP/UDP selection? probing? should we pass some flags? */

GNetSnmp*
gnet_snmp_new_uri(const GURI *uri)
{
    GNetSnmp *snmp = NULL;
    GInetAddr *taddress = NULL;
    GNetSnmpTDomain tdomain = GNET_SNMP_TDOMAIN_NONE;
    int ipv6;
    
    g_return_val_if_fail(uri, NULL);
    
    taddress = gnet_inetaddr_new(uri->hostname, uri->port);
    if (taddress) {
	ipv6 = gnet_inetaddr_is_ipv6(taddress);
	tdomain =
	    ipv6 ? GNET_SNMP_TDOMAIN_UDP_IPV6 : GNET_SNMP_TDOMAIN_UDP_IPV4;
	
	snmp = gnet_snmp_new();
	if (snmp) {
	    GString *s = g_string_new(uri->userinfo);
	    gnet_snmp_set_transport(snmp, tdomain, taddress);
	    gnet_snmp_set_sec_name(snmp, s);
	    g_string_free(s, 1);

	    if (uri->path && uri->path[0] == '/' && uri->path[1]) {
		char *end = strchr(uri->path+1, '/');
		GString *s;
		if (end) {
		    s = g_string_new_len(uri->path+1, end - uri->path - 1);
		} else {
		    s = g_string_new(uri->path+1);
		}
		gnet_snmp_set_ctxt_name(snmp, s);
		g_string_free(s, 1);
	    }
	    
	}
	gnet_inetaddr_delete(taddress);
    }

    return snmp;
}

GNetSnmp*
gnet_snmp_new_string(const gchar *string, GError **error)
{
    GURI *uri;
    GNetSnmp *s;

    uri = gnet_snmp_parse_uri(string);
    if (! uri) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_ERROR,
			GNET_SNMP_ERROR_BADURI,
			"invalid snmp uri");
	}
	return NULL;
    }

    s = gnet_snmp_new_uri(uri);
    if (! s) {
	gnet_uri_delete(uri);
	if (error) {
	    g_set_error(error,
			GNET_SNMP_ERROR,
			GNET_SNMP_ERROR_NEWFAIL,
			"unable to create snmp session");
	}
	return NULL;
    }
    gnet_uri_delete(uri);
    return s;
}

/*
 * Clone a session data structure.
 */

GNetSnmp*
gnet_snmp_clone(GNetSnmp *session)
{
    GNetSnmp *clone;

    g_return_val_if_fail(session, NULL);

    clone = gnet_snmp_new();
    gnet_snmp_set_transport(clone, session->tdomain, session->taddress);
    gnet_snmp_set_timeout(clone, session->timeout);
    gnet_snmp_set_retries(clone, session->retries);
    gnet_snmp_set_version(clone, session->version);
    gnet_snmp_set_sec_model(clone, session->sec_model);
    gnet_snmp_set_sec_level(clone, session->sec_level);
    gnet_snmp_set_sec_name(clone, session->sec_name);
    gnet_snmp_set_ctxt_name(clone, session->ctxt_name);

    return clone;
}

/*
 * Destroy a session data structure.
 */

void
gnet_snmp_delete(GNetSnmp *snmp)
{
    g_return_if_fail(snmp);

    /* XXX delete all requests that refer to this session first */

    if (snmp->taddress) gnet_inetaddr_delete(snmp->taddress);
    if (snmp->uri) gnet_uri_delete(snmp->uri);
    if (snmp->sec_name) g_string_free(snmp->sec_name, 1);
    if (snmp->ctxt_name) g_string_free(snmp->ctxt_name, 1);
    g_free(snmp);

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: deleted\n", snmp);
    }
}

void
gnet_snmp_set_transport(GNetSnmp *snmp,
			GNetSnmpTDomain tdomain, GInetAddr *taddress)
{
    g_return_if_fail(snmp);

    if (snmp->taddress) gnet_inetaddr_delete(snmp->taddress);
    snmp->tdomain = GNET_SNMP_TDOMAIN_NONE;
    snmp->taddress = NULL;
    if (taddress) {
	snmp->tdomain = tdomain;
	snmp->taddress = gnet_inetaddr_clone(taddress);
    }
    (void) gnet_snmp_get_uri(snmp);
}

/* decrecated interface */

void
gnet_snmp_set_community(GNetSnmp *snmp, gchar *community)
{
    GString *s;
    
    g_return_if_fail(snmp);

    s = g_string_new(community);
    gnet_snmp_set_sec_name(snmp, s);
    g_string_free(s, 1);
    (void) gnet_snmp_get_uri(snmp);	/* update the uri */
}

/* deprecated interface */

const gchar*
gnet_snmp_get_community(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, NULL);

    return snmp->sec_name->str;
}

void
gnet_snmp_set_timeout(GNetSnmp *snmp, guint timeout)
{
    g_return_if_fail(snmp);

    snmp->timeout = timeout;
}

guint
gnet_snmp_get_timeout(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, 0);

    return snmp->timeout;
}

void
gnet_snmp_set_retries(GNetSnmp *snmp, guint retries)
{
    g_return_if_fail(snmp);

    snmp->retries = retries;
}

guint
gnet_snmp_get_retries(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, 0);

    return snmp->retries;
}

void
gnet_snmp_set_version(GNetSnmp *snmp, GNetSnmpVersion version)
{
    g_return_if_fail(snmp);

    snmp->version = version;
}

GNetSnmpVersion
gnet_snmp_get_version(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, 0);

    return snmp->version;
}

void
gnet_snmp_set_sec_name(GNetSnmp *snmp, GString *name)
{
    g_return_if_fail(snmp);

    g_string_assign(snmp->sec_name, name->str);
    (void) gnet_snmp_get_uri(snmp);	/* update the uri */
}

GString*
gnet_snmp_get_sec_name(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, NULL);
    
    return snmp->sec_name;
}

void
gnet_snmp_set_sec_model(GNetSnmp *snmp, GNetSnmpSecModel model)
{
    g_return_if_fail(snmp);

    snmp->sec_model = model;
}

GNetSnmpSecModel gnet_snmp_get_sec_model(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, 0);

    return snmp->sec_model;
}

void
gnet_snmp_set_sec_level(GNetSnmp *snmp, GNetSnmpSecLevel level)
{
    g_return_if_fail(snmp);

    snmp->sec_level = level;
}

GNetSnmpSecLevel gnet_snmp_get_sec_level(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, 0);

    return snmp->sec_level;
}

void
gnet_snmp_set_ctxt_name(GNetSnmp *snmp, GString *name)
{
    g_return_if_fail(snmp);

    g_string_assign(snmp->ctxt_name, name->str);
    (void) gnet_snmp_get_uri(snmp);	/* update the uri */
}

GString*
gnet_snmp_get_ctxt_name(const GNetSnmp *snmp)
{
    g_return_val_if_fail(snmp, NULL);
    
    return snmp->ctxt_name;
}

/*
 * Allocate a new request data structure.
 */

GNetSnmpRequest*
gnet_snmp_request_new()
{
    GNetSnmpRequest *request;

    request = g_malloc0(sizeof(GNetSnmpRequest));
    request->sec_name = g_string_new(NULL);
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	g_printerr("request %p: new\n", request);
    }

    return request;
}

/*
 * Destroy a request data structure.
 */

void
gnet_snmp_request_delete(GNetSnmpRequest *request)
{
    g_return_if_fail(request);
    
    if (request->sec_name) {
	g_string_free(request->sec_name, 1);
    }
    g_free(request);

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	g_printerr("request %p: deleted\n", request);
    }
}

/*
 * Add a request to the global queue of outstanding requests.
 * XXX This is not thread-safe.
 */

void
gnet_snmp_request_queue(GNetSnmpRequest *request)
{
    g_return_if_fail(request);
    
    request_queue = g_slist_append(request_queue, request);
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	g_printerr("request %p: queued\n", request);
    }
}

/*
 * Remove a request from the global queue of outstanding requests.
 * XXX This is not thread-safe.
 */

void
gnet_snmp_request_dequeue(GNetSnmpRequest *request)
{
    g_return_if_fail(request);

    request_queue = g_slist_remove(request_queue, request);
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	g_printerr("request %p: dequeued\n", request);
    }
}

/*
 * Find the request with a given request id in the global queue of
 * outstanding requests.
 * XXX This is not thread-safe.
 */

GNetSnmpRequest*
gnet_snmp_request_find(gint32 id)
{
    GSList *elem;

    for (elem = request_queue; elem; elem = g_slist_next(elem)) {
	GNetSnmpRequest *request = (GNetSnmpRequest *) elem->data;
	if (request->pdu.request_id == id) {
	    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
		g_printerr("request %p: found\n", request);
	    }
	    return request;
	}
    }

    return NULL;
}

/*
 *
 */

void
gnet_snmp_request_timeout(GNetSnmpRequest *request)
{
    if (request->timeout) {
	if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	    g_printerr("request %p: timeout callback invoked\n", request);
	}
	request->timeout(request->session, request->magic);
    }
}


/* 
 * query/set one mib from a snmp host
 *
 * host    -- Host info in question
 * callback-- Pointer to function that will handle the reply 
 *
 */

/* Asynchronous SNMP functions */

static gpointer
g_async_send(GNetSnmp *session, GNetSnmpPduType type,
	     GList *vbl, guint32 arg1, guint32 arg2)
{
    GError *error = NULL;
    GNetSnmpRequest *request;
    GTimeVal	  now;
    static gint32 id = -1;
    
    if (id < 0) {
	id = random();
    }

    g_get_current_time(&now);

    session->error_status = GNET_SNMP_PDU_ERR_NOERROR;
    session->error_index = 0;
    
    request = gnet_snmp_request_new();
    request->callback = session->done_callback;
    request->timeout  = session->time_callback;
    request->pdu.request_id   = id++;
    request->pdu.error_status = arg1;
    request->pdu.error_index  = arg2;
    request->pdu.varbind_list = vbl;
    request->pdu.context_name = (guchar *) session->ctxt_name->str;
    request->pdu.context_name_len = session->ctxt_name->len;
    request->sec_name         = g_string_append(request->sec_name,
						session->sec_name->str);
    request->sec_model	      = session->sec_model;
    request->sec_level	      = session->sec_level;
    request->pdu.type	      = type;
    request->retries          = session->retries;
    request->timeoutval       = session->timeout;
    request->magic            = session->magic;
    request->version          = session->version;
    request->tdomain          = session->tdomain;
    request->taddress         = session->taddress;
    request->session          = session;
    request->timer            = now;
    request->timer.tv_sec    += request->timeoutval / 1000;
    request->timer.tv_usec   += (request->timeoutval % 1000) * 1000;

    gnet_snmp_dispatcher_send_pdu(request->tdomain, request->taddress,
				  request->version,
				  request->sec_model,
				  request->sec_name,
				  request->sec_level,
				  &request->pdu, TRUE, &error);

    if (error) {
	gnet_snmp_request_timeout(request);
	gnet_snmp_request_delete(request);
	g_error_free(error);
	return NULL;
    }
    
    gnet_snmp_request_queue(request);

    return request;
}

gpointer
gnet_snmp_async_set(GNetSnmp *snmp, GList *vbl)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_async_set pdu %p\n", snmp, vbl);
    }
    return g_async_send(snmp, GNET_SNMP_PDU_SET, vbl, 0, 0);
}

gpointer
gnet_snmp_async_get(GNetSnmp *snmp, GList *vbl)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_async_get pdu %p\n", snmp, vbl);
    }
    return g_async_send(snmp, GNET_SNMP_PDU_GET, vbl, 0, 0);
}

gpointer
gnet_snmp_async_getnext(GNetSnmp *snmp, GList *vbl)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_async_getnext pdu %p\n", snmp, vbl);
    }
    return g_async_send(snmp, GNET_SNMP_PDU_NEXT, vbl, 0, 0);
}

gpointer
gnet_snmp_async_getbulk(GNetSnmp *snmp, GList *vbl,
			guint32 nonrep, guint32 maxrep)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_async_getbulk pdu %p\n", snmp, vbl);
    }
    return g_async_send(snmp, GNET_SNMP_PDU_BULK, vbl, nonrep, maxrep);
}

/* Synchronous SNMP functions */

struct inputcb {
  int sock_nr;
  void (*receiveMessage)();
};

struct syncmagic {
    GMainLoop *loop;
    GList *result;
};

static void
cb_time(GNetSnmp *session, void *magic)
{
    struct syncmagic *sm = (struct syncmagic *) magic;
    sm->result = NULL;
    session->error_index = 0;
    session->error_status = GNET_SNMP_PDU_ERR_NORESPONSE;

    g_main_quit(sm->loop);
}

static gboolean
cb_done(GNetSnmp *session, GNetSnmpPdu *spdu, GList *objs, gpointer magic)
{
    struct syncmagic *sm = (struct syncmagic *) magic;
    sm->result = objs;
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: error-status = %d, error-index = %d\n",
		   session, session->error_status, session->error_index);
    }
    g_main_quit(sm->loop);
    return FALSE;
}

static GList *
g_sync_send(GNetSnmp *session, GNetSnmpPduType type,
	    GList *objs, guint32 arg1, guint32 arg2)
{
    struct syncmagic * magic;
    GList *result;
    
    magic = (struct syncmagic *) g_malloc(sizeof(struct syncmagic));
    magic->loop = g_main_new(TRUE);
    
    session->done_callback = cb_done;
    session->time_callback = cb_time;
    session->magic = magic;
    if (! g_async_send(session, type, objs, arg1, arg2)) {
	if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	    g_printerr("session %p: g_sync_send failed to send PDU\n", session);
	}
	g_main_destroy(magic->loop);
	g_free(magic);
	return NULL;
    }
    
    while(g_main_is_running(magic->loop)) {
	g_main_run(magic->loop);
    }
    g_main_destroy(magic->loop);
    result = magic->result;
    g_free(magic);
    return result;
}

GList *
gnet_snmp_sync_set(GNetSnmp *snmp, GList *pdu)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_sync_set pdu %p\n", snmp, pdu);
    }
    return g_sync_send(snmp, GNET_SNMP_PDU_SET, pdu, 0, 0);
}

GList *
gnet_snmp_sync_get(GNetSnmp *snmp, GList *pdu)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_sync_get pdu %p\n", snmp, pdu);
    }
    return g_sync_send(snmp, GNET_SNMP_PDU_GET, pdu, 0, 0);
}

GList *
gnet_snmp_sync_getnext(GNetSnmp *snmp, GList *pdu)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_sync_getnext pdu %p\n", snmp, pdu);
    }
    return g_sync_send(snmp, GNET_SNMP_PDU_NEXT, pdu, 0, 0);
}

GList *
gnet_snmp_sync_getbulk(GNetSnmp *snmp, GList *pdu,
		       guint32 nonrep, guint32 maxrep)
{
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_SESSION) {
	g_printerr("session %p: g_sync_getbulk pdu %p\n", snmp, pdu);
    }
    return g_sync_send(snmp, GNET_SNMP_PDU_BULK, pdu, nonrep, maxrep);
}

#if 0
gboolean
g_pdu_add_oid(GList **pdu, guint32 *myoid, guint mylength,
	      GSnmpVarBindType type, gpointer value)
{
  GSnmpVarBind *obj;

  obj = g_snmp_varbind_new(myoid, mylength, type, value, -1);
  if (! obj) {
      return FALSE;
  }
  *pdu = g_list_append(*pdu, obj);
  return TRUE;
}
#endif

#if 0
/* This should be nuked once the new parser and mib module are available.
   For now, either use this or the print function in struct tree          */

void 
g_snmp_printf(char *buf, int buflen, GSnmpVarBind *obj)
{
  int i;
  /*
   * Changed all the sprintf's to snprintf, paranoid I know but
   * I'd rather not get caught with any buffer overflows..
   */
  switch(obj->type)
    {
      case G_SNMP_INTEGER32:
        g_snprintf(buf, buflen, "%d", obj->syntax.i32[0]);
        break;
      case G_SNMP_COUNTER32:
      case G_SNMP_UNSIGNED32:
        g_snprintf(buf, buflen, "%u", obj->syntax.ui32[0]);
        break;
      case G_SNMP_TIMETICKS:
	/* replaced this duplicated code with a call to existing code */
	/* timetick_string (obj->syntax.ul[0], buf); */
        g_snprintf(buf, buflen, "%u", obj->syntax.ui32[0]);
        break;
      case G_SNMP_OCTET_STRING:
      case G_SNMP_OPAQUE:
        /* xxx fix this (data is not necessarily printable) */
        memcpy(buf, obj->syntax.uc,
	       obj->syntax_len > buflen ? buflen: obj->syntax_len);
	buf[obj->syntax_len > buflen ? buflen: obj->syntax_len] = '\0';
        break;
      case G_SNMP_IPADDRESS:
        if (obj->syntax_len == 4) /* IPv4 */
          g_snprintf(buf, buflen, "%d.%d.%d.%d", obj->syntax.uc[0],
                                               obj->syntax.uc[1],
                                               obj->syntax.uc[2],
                                               obj->syntax.uc[3]);
        break;
      case G_SNMP_OBJECT_ID:
        g_snprintf(buf, buflen, "%u", obj->syntax.ui32[0]);
        i=1;
        while(i < obj->syntax_len / sizeof(guint32))
          g_snprintf(buf+strlen(buf), buflen-strlen(buf), ".%u", 
                   obj->syntax.ui32[i++]);
        break;
      case G_SNMP_COUNTER64:
        g_snprintf(buf, buflen, "%llu", obj->syntax.ui64[0]);
	break;
      case G_SNMP_NULL:
        g_snprintf(buf, buflen, "<null>");
        break;
      case G_SNMP_NOSUCHOBJECT:
        g_snprintf(buf, buflen, "<nosuchobject>");
        break;
      case G_SNMP_NOSUCHINSTANCE:
        g_snprintf(buf, buflen, "<nosuchinstance>");
        break;
      case G_SNMP_ENDOFMIBVIEW:
        g_snprintf(buf, buflen, "<endofmibview>");
        break;
    }
}
#endif

/*
 * The low level callbacks
 */

static int
g_snmp_timeout_cb(gpointer data)
{
    GSList *mylist;
    GTimeVal now;
    GNetSnmpRequest *request;
    
  again:
    g_get_current_time(&now);
    mylist = request_queue;
    
    while (mylist) {
	request = (GNetSnmpRequest *) mylist->data;
	mylist = mylist->next;
	if (request->timer.tv_sec < now.tv_sec
	    || (request->timer.tv_sec == now.tv_sec
		&& request->timer.tv_usec <= now.tv_usec)) {
	    if (request->retries) {
		request->retries--;
		
		request->timer = now;
		request->timer.tv_sec  += request->timeoutval / 1000;
		request->timer.tv_usec += (request->timeoutval % 1000) * 1000;
		
		if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
		    g_printerr("request %p: timeout ...\n", request);
		}
		
		{
		    GError *error = NULL;

		    gnet_snmp_dispatcher_send_pdu(request->tdomain,
						  request->taddress,
						  request->version,
						  request->sec_model,
						  request->sec_name,
						  request->sec_level,
						  &request->pdu, TRUE, &error);

		    if (error) {
			g_error_free(error);
			gnet_snmp_request_timeout(request);
			gnet_snmp_request_dequeue(request);
			gnet_snmp_request_delete(request);
			goto again;
		    }
		}
#if 0
		if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
		    g_warning("request %p: timeout, retry shipped", request);
		}
#endif
	    } else {
		if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
		    g_printerr("request %p: final timeout ...\n", request);
		}
		
		gnet_snmp_request_timeout(request);
		gnet_snmp_request_dequeue(request);
		gnet_snmp_request_delete(request);
		goto again;
	    }
	}
    }
    return TRUE;
}

void
g_session_response_pdu(GNetSnmpMsg *msg)
{
    GNetSnmpPdu     *pdu;
    GList           *vbl;
    GNetSnmpRequest *request;

    g_assert(msg);

    if (! msg->data) return;

    pdu = (GNetSnmpPdu *) msg->data;
    vbl = pdu->varbind_list;

    request = gnet_snmp_request_find(pdu->request_id);
    if (! request) {
	g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(vbl);
	return;
    }

#if 0
    /* XXX this needs to be generalized I think */
    
    if (memcmp(securityName->str, request->sec_name->str, securityName->len)) {
	g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(vbl);
	return;
    }
#endif

    gnet_snmp_request_dequeue(request);
    request->session->error_status = pdu->error_status;
    request->session->error_index = pdu->error_index;
    if (! request->callback) {
	g_list_foreach(vbl, (GFunc) gnet_snmp_varbind_delete, NULL);
	g_list_free(vbl);
	gnet_snmp_request_delete(request);
	return;
    }

    if (request->callback(request->session, pdu, vbl, request->magic)) {
	if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_REQUESTS) {
	    g_printerr("request %p: callback invoked\n", request);
	}
	/* g_snmp_vbl_free(vbl); */
    }
    gnet_snmp_request_delete(request);
}

GURI*
gnet_snmp_get_uri(GNetSnmp *snmp)
{
    gchar *host, *name, *path = NULL;
    gint port;
    
    g_return_val_if_fail(snmp, NULL);
    
    if (snmp->uri) gnet_uri_delete(snmp->uri);

    host = gnet_inetaddr_get_canonical_name(snmp->taddress);
    port = gnet_inetaddr_get_port(snmp->taddress);
    name = snmp->sec_name ? snmp->sec_name->str : NULL;
    if (snmp->ctxt_name) {
	path = g_strdup_printf("/%s/", snmp->ctxt_name->str);
    }

    snmp->uri = gnet_uri_new_fields_all("snmp", name, host, port,
					path, NULL, NULL);

    if (path) g_free(path);
    
    return snmp->uri;
}
