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

#ifndef __GNET_SNMP_SESSION_H__
#define __GNET_SNMP_SESSION_H__

/*
 * Basic snmp info on a per session basis. Note that status
 * information of the last SNMP interaction is returned to the
 * application as part of the session structure. (!)
 */

typedef struct _GNetSnmp GNetSnmp;

/* XXX there should only be a single callback (for everything) with
   the condition signalled as part of the session state / error
   code XXX */

typedef gboolean (*GNetSnmpDoneFunc) (GNetSnmp *snmp,
				      GNetSnmpPdu *pdu,
				      GList *vbl,
				      gpointer data);
typedef void     (*GNetSnmpTimeFunc) (GNetSnmp *snmp,
				      gpointer data);

/* XXX this structure should be completely private XXX */

struct _GNetSnmp {
    GNetSnmpTAddress *taddress;
    GURI	    *uri;
    gint32           error_status;
    guint32	     error_index;
    guint            retries;		/* number of retries */
    guint            timeout;		/* timeout in milliseconds */
    GNetSnmpVersion  version;           /* message version */
    GString	    *ctxt_name;		/* context name */
    GString	    *sec_name;		/* security name */
    GNetSnmpSecModel sec_model;		/* security model */
    GNetSnmpSecLevel sec_level;		/* security level */
    GNetSnmpDoneFunc done_callback;	/* what to call when complete */
    GNetSnmpTimeFunc time_callback;	/* what to call on a timeout */
    gpointer         magic;             /* additional data for callbacks */
};

#define GNET_SNMP_DEFAULT_RETRIES 3
#define GNET_SNMP_DEFAULT_TIMEOUT 200

/*
 * Session error codes. Eventually, all session API functions should
 * return error information via the GError mechanism...
 */

typedef enum
{
    GNET_SNMP_ERROR_NEWFAIL,
    GNET_SNMP_ERROR_BADURI
} GNetSnmpXXError;

#define GNET_SNMP_ERROR gnet_snmp_error_quark()

/*
 * Session API functions.
 */

GNetSnmp*	gnet_snmp_new		(void);
GNetSnmp*	gnet_snmp_new_uri	(const GURI *uri,
					 GError **error);
GNetSnmp*	gnet_snmp_new_string	(const gchar *string,
					 GError **error);
GNetSnmp*	gnet_snmp_clone		(GNetSnmp *snmp);
void		gnet_snmp_delete	(GNetSnmp *snmp);

void		gnet_snmp_set_transport	(GNetSnmp *snmp,
					 GNetSnmpTAddress *taddress);
void		gnet_snmp_set_sec_name	(GNetSnmp *snmp,
					 GString *name);
void		gnet_snmp_set_sec_model (GNetSnmp *snmp,
					 GNetSnmpSecModel model);
void		gnet_snmp_set_sec_level (GNetSnmp *snmp,
					 GNetSnmpSecLevel level);
void		gnet_snmp_set_ctxt_name	(GNetSnmp *snmp,
					 GString *name);
void		gnet_snmp_set_timeout	(GNetSnmp *snmp,
					 guint timeout);
void		gnet_snmp_set_retries	(GNetSnmp *snmp,
					 guint retries);
void		gnet_snmp_set_version	(GNetSnmp *snmp,
					 GNetSnmpVersion version);

const gchar*	gnet_snmp_get_community	(const GNetSnmp *snmp);
GString*	gnet_snmp_get_sec_name	(const GNetSnmp *snmp);
GNetSnmpSecModel gnet_snmp_get_sec_model(const GNetSnmp *snmp);
GNetSnmpSecLevel gnet_snmp_get_sec_level(const GNetSnmp *snmp);
GString*	gnet_snmp_get_ctxt_name	(const GNetSnmp *snmp);
guint		gnet_snmp_get_timeout	(const GNetSnmp *snmp);
guint		gnet_snmp_get_retries	(const GNetSnmp *snmp);
GNetSnmpVersion	gnet_snmp_get_version	(const GNetSnmp *snmp);
GNetSnmpTDomain gnet_snmp_get_tdomain	(const GNetSnmp *snmp);
gchar*		gnet_snmp_get_uri_string(GNetSnmp *snmp);

void		gnet_snmp_update_uri	(GNetSnmp *snmp);

gpointer	gnet_snmp_async_set	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
gpointer	gnet_snmp_async_set	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
gpointer	gnet_snmp_async_get	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
gpointer	gnet_snmp_async_getnext	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
gpointer	gnet_snmp_async_getbulk	(GNetSnmp *snmp,
					 GList *vbl,
					 guint32 nonrep,
					 guint32 maxrep,
					 GError **error);

GList*		gnet_snmp_sync_set	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
GList*		gnet_snmp_sync_get      (GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
GList*		gnet_snmp_sync_getnext  (GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);
GList*		gnet_snmp_sync_getbulk  (GNetSnmp *snmp,
					 GList *vbl,
					 guint32 nonrep,
					 guint32 maxrep,
					 GError **error);

/* Is it necessary to support multiple walks per session (with shared
   callbacks anyway)? If we drop this feature, we could merge the walk
   state into the session itself and simplify the API. */

typedef struct  _GNetSnmpWalk		GNetSnmpWalk;

GNetSnmpWalk*	gnet_snmp_walk_new	(GNetSnmp *snmp,
					 GList *vbl,
					 void (* cb_error)(),
					 void (* cb_row)(),
					 void (* cb_finish)(),
					 gpointer data);
void		gnet_snmp_walk_delete	(GNetSnmpWalk *walk);

void		gnet_snmp_async_walk	(GNetSnmpWalk *walk,
					 GError **error);
GList*		gnet_snmp_sync_walk	(GNetSnmp *snmp,
					 GList *vbl,
					 GError **error);

/* Is it necessary to support multiple takes per session (with shared
   callbacks anyway)? If we drop this feature, we could merge the table
   state into the session itself and simplify the API. */

typedef struct  _GNetSnmpTable		GNetSnmpTable;

GNetSnmpTable*	gnet_snmp_table_new	(GNetSnmp *snmp,
					 GList *vbl,
					 void (* cb_error)(),
					 void (* cb_row)(),
					 void (* cb_finish)(),
					 gpointer data);
void		gnet_snmp_table_delete	(GNetSnmpTable *table);

void		gnet_snmp_async_table	(GNetSnmpTable *table,
					 GError **error);
GList*		gnet_snmp_sync_table	(GNetSnmp *snmp, 
					 GList *vbl,
					 GError **error);

typedef struct _GNetSnmpRequest {
    GNetSnmpDoneFunc callback;
    GNetSnmpTimeFunc timeout;
    GNetSnmp        *session;
    GNetSnmpPdu      pdu;
    struct sockaddr *address;
    GNetSnmpTAddress *taddress;
    GTimeVal         timer;
    guint            retries;
    guint            timeoutval;
    GNetSnmpVersion  version;
    GString         *sec_name;
    GNetSnmpSecModel sec_model;
    GNetSnmpSecLevel sec_level;
    gpointer         magic;
} GNetSnmpRequest;


GNetSnmpRequest* gnet_snmp_request_new	  (void);
void		 gnet_snmp_request_delete (GNetSnmpRequest *request);

void		 gnet_snmp_request_queue  (GNetSnmpRequest *request);
void		 gnet_snmp_request_dequeue(GNetSnmpRequest *request);
GNetSnmpRequest* gnet_snmp_request_find	  (gint32 request_id);
void		 gnet_snmp_request_timeout(GNetSnmpRequest *request);

/*
 * Session API - the stuff below needs to be cleaned up. XXX
 */

void g_session_response_pdu(GNetSnmpMsg *msg);

#endif /* __GNET_SNMP_SESSION_H__ */
