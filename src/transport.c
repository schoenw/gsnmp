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
 * Foundation, Inc.,  59 Temple Place - Suite 330, Cambridge, MA 02139, USA.
 *
 * $Id$
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

#include <gnet.h>

#include "transport.h"
#include "dispatch.h"
#include "pdu.h"	/* xxx only needed for debugging flags... */


static GUdpSocket  *udp_ipv4_socket = NULL;
static GUdpSocket  *udp_ipv6_socket = NULL;

static GTcpSocket  *tcp_ipv4_socket = NULL;	/* this should be a pool */
static GUnixSocket *unix_socket = NULL;		/* this should be a pool */

GQuark
gnet_snmp_transport_error_quark(void)
{
    static GQuark quark = 0;
    if (quark == 0) {
	quark = g_quark_from_static_string("gnet-snmp-transport-error-quark");
    }
    return quark;
}

/*
 *
 */

GNetSnmpTAddress*
gnet_snmp_taddress_new(void)
{
    GNetSnmpTAddress *taddr;

    taddr = g_malloc0(sizeof(GNetSnmpTAddress));
    taddr->domain = GNET_SNMP_TDOMAIN_NONE;
    taddr->inetaddr = NULL;
    taddr->path = NULL;

    return taddr;
}

GNetSnmpTAddress*
gnet_snmp_taddress_new_inet(GNetSnmpTDomain domain, GInetAddr* addr)
{
    GNetSnmpTAddress *taddr;

    /* XXX validate domain and addr */

    taddr = gnet_snmp_taddress_new();
    taddr->domain = domain;
    taddr->inetaddr = gnet_inetaddr_clone(addr);
    return taddr;
}

GNetSnmpTAddress*
gnet_snmp_taddress_new_path(GNetSnmpTDomain domain, gchar *path)
{
    GNetSnmpTAddress *taddr;

    /* XXX validate domain and addr */

    taddr = gnet_snmp_taddress_new();
    taddr->domain = domain;
    taddr->path = g_strdup(path);
    return taddr;
}

GNetSnmpTAddress*
gnet_snmp_taddress_clone(GNetSnmpTAddress *taddr)
{
    g_return_val_if_fail(taddr, NULL);

    switch (taddr->domain) {
    case GNET_SNMP_TDOMAIN_UDP_IPV4:
    case GNET_SNMP_TDOMAIN_TCP_IPV4:
    case GNET_SNMP_TDOMAIN_UDP_IPV6:
    case GNET_SNMP_TDOMAIN_TCP_IPV6:
	return gnet_snmp_taddress_new_inet(taddr->domain, taddr->inetaddr);
    case GNET_SNMP_TDOMAIN_NONE:
    case GNET_SNMP_TDOMAIN_IPX:
	return gnet_snmp_taddress_new();
    case GNET_SNMP_TDOMAIN_LOCAL:
	return gnet_snmp_taddress_new_path(taddr->domain, taddr->path);
	break;
    }

    return NULL;
}

gchar*
gnet_snmp_taddress_get_short_name(const GNetSnmpTAddress *taddr)
{
    gchar *name = NULL;
    
    g_return_val_if_fail(taddr, NULL);

    switch (taddr->domain) {
    case GNET_SNMP_TDOMAIN_UDP_IPV4:
    case GNET_SNMP_TDOMAIN_TCP_IPV4:
    case GNET_SNMP_TDOMAIN_UDP_IPV6:
    case GNET_SNMP_TDOMAIN_TCP_IPV6:
	name = g_strdup(gnet_inetaddr_get_canonical_name(taddr->inetaddr));
	break;
    case GNET_SNMP_TDOMAIN_LOCAL:
	name = g_strdup(taddr->path);
	break;
    case GNET_SNMP_TDOMAIN_NONE:
    case GNET_SNMP_TDOMAIN_IPX:
	break;
    }

    return name;
}

void
gnet_snmp_taddress_delete(GNetSnmpTAddress *taddr)
{
    if (taddr) {
	switch (taddr->domain) {
	case GNET_SNMP_TDOMAIN_UDP_IPV4:
	case GNET_SNMP_TDOMAIN_TCP_IPV4:
	case GNET_SNMP_TDOMAIN_UDP_IPV6:
	case GNET_SNMP_TDOMAIN_TCP_IPV6:
	    if (taddr->inetaddr) gnet_inetaddr_delete(taddr->inetaddr);
	    break;
	case GNET_SNMP_TDOMAIN_LOCAL:
	    if (taddr->path) g_free(taddr->path);
	    break;
	case GNET_SNMP_TDOMAIN_NONE:
	case GNET_SNMP_TDOMAIN_IPX:
	    break;
	}
	g_free(taddr);
    }
}

/*
 * Subroutine to dump packet contents to the screen - jms
 */

static void
dump_packet(guchar *data, gsize len)
{
    guint i;
    g_printerr("packet  %p: ", data);
    for (i = 0; i < len; i++) {
	g_printerr("%2.2x", data[i]);
	if (i+1 < len) {
	    if (i % 16 == 15) {
		g_printerr("\npacket  %p: ", data);
	    } else {
		g_printerr(":");
	    }
	}
    }
    // if (i % 16 != 15)
    g_printerr("\n");
}

static gboolean
gaga(GIOChannel *source, GIOCondition condition, gpointer data)
{
    void (*func)(void);
    func = data;
    func();
    return TRUE;
}

/*
 * xxx - first approximation handles just one established tcp session
 */

static void
tcp_ipv4_receive_message()
{
    guchar buffer[MAX_DGRAM_SIZE];
    GIOChannel *channel;
    GInetAddr* addr;
    gsize len;

    addr = gnet_tcp_socket_get_remote_inetaddr(tcp_ipv4_socket);
    channel = gnet_tcp_socket_get_io_channel(tcp_ipv4_socket);
    if (! channel) {
	g_warning("retrieving snmp over tcp/ipv4 socket failed");
	return;
    }

    if (g_io_channel_read(channel, (gchar *) buffer, sizeof(buffer), &len)) {
        return;
    }

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. tcp/ipv4: received %d bytes from %s:%d\n",
		   (gint) len,
		   gnet_inetaddr_get_name(addr),
		   gnet_inetaddr_get_port(addr));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(buffer, len);
    }
    gnet_snmp_dispatcher_recv_msg(
	gnet_snmp_taddress_new_inet(GNET_SNMP_TDOMAIN_TCP_IPV4, addr),
	buffer, len, NULL);
    gnet_inetaddr_delete(addr);
}

static gboolean
tcp_ipv4_send_message(GNetSnmpTAddress *taddress,
		      guchar *msg, gsize msg_len, GError **error)
{
    GIOChannel *channel;
    gsize len;
    
    g_return_val_if_fail(taddress
		 && taddress->domain == GNET_SNMP_TDOMAIN_TCP_IPV4, FALSE);

    if (! tcp_ipv4_socket
	|| ! gnet_inetaddr_equal(taddress, gnet_tcp_socket_get_remote_inetaddr(tcp_ipv4_socket))) {
	if (tcp_ipv4_socket) {
	    gnet_tcp_socket_delete(tcp_ipv4_socket);
	}
	tcp_ipv4_socket = gnet_tcp_socket_new(taddress->inetaddr);
	if (! tcp_ipv4_socket) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_TRANSPORT_ERROR,
			    GNET_SNMP_TRANSPORT_ERROR_CONNECT,
			    "failed to connect tcp/ipv4 socket: %s",
			    g_strerror(errno));
	    }
	    return FALSE;
	}
    }

    channel = gnet_tcp_socket_get_io_channel(tcp_ipv4_socket);
    if (! channel) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_REGISTER,
			"failed to get io channel for tcp/ipv4 socket: %s",
			g_strerror(errno));
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. tcp/ipv4: send %d bytes to %s:%d\n",
		   (gint) msg_len,
		   gnet_inetaddr_get_name(taddress->inetaddr),
		   gnet_inetaddr_get_port(taddress->inetaddr));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(msg, msg_len);
    }
    
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, tcp_ipv4_receive_message);
    if (G_IO_ERROR_NONE != gnet_io_channel_writen(channel, msg,
						  msg_len, &len)) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to write to tcp/ipv4 socket: %s",
			g_strerror(errno));
	}
	gnet_tcp_socket_delete(tcp_ipv4_socket);
	tcp_ipv4_socket = NULL;
	return FALSE;
    }
    return TRUE;
}

static gboolean
tcp_ipv4_init(GError **error)
{
    tcp_ipv4_socket = NULL;
    return TRUE;
}

static gboolean
udp_ipv4_send_message(GNetSnmpTAddress *taddress,
		      guchar *msg, gsize msg_len, GError **error)
{
    gint rv;

    g_return_val_if_fail(taddress
		 && taddress->domain == GNET_SNMP_TDOMAIN_UDP_IPV4, FALSE);

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(msg, msg_len);
    }

    rv = gnet_udp_socket_send(udp_ipv4_socket, (gchar *) msg,
			      msg_len, taddress->inetaddr);
    if (rv) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to write to udp/ipv4 socket: %s",
			g_strerror(errno));
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv4: send %d bytes to %s:%d\n",
		   (gint) msg_len,
		   gnet_inetaddr_get_name(taddress->inetaddr),
		   gnet_inetaddr_get_port(taddress->inetaddr));
    }
    return TRUE;
}

static void
udp_ipv4_receive_message(GError **error)
{
    guchar buffer[MAX_DGRAM_SIZE];
    GInetAddr* addr;
    int len;

    len = gnet_udp_socket_receive(udp_ipv4_socket, (gchar *) buffer, sizeof(buffer), &addr);
    if (! len) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_RECV,
			"failed to receive from udp/ipv4 socket");
	}
        return;
    }

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv4: received %d bytes from %s:%d\n", len,
		   gnet_inetaddr_get_name(addr),
		   gnet_inetaddr_get_port(addr));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(buffer, len);
    }
    gnet_snmp_dispatcher_recv_msg(
	gnet_snmp_taddress_new_inet(GNET_SNMP_TDOMAIN_UDP_IPV4, addr),
	buffer, len, NULL);
    gnet_inetaddr_delete(addr);
}

static gboolean
udp_ipv4_init(GError **error)
{
    GIOChannel *channel;

    udp_ipv4_socket = gnet_udp_socket_new();
    if (! udp_ipv4_socket) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SOCKET,
			"failed to create udp/ipv4 socket: %s",
			g_strerror(errno));
	} else {
	    g_warning("opening snmp over udp/ipv4 socket failed");
	}
	return FALSE;
    }

    channel = gnet_udp_socket_get_io_channel(udp_ipv4_socket);
    if (! channel) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_REGISTER,
			"failed to get io channel for udp/ipv4 socket: %s",
			g_strerror(errno));
	} else {
	    g_warning("failed to get io channel for udp/ipv4 socket: %s",
		      g_strerror(errno));
	}
	return FALSE;
    }
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, udp_ipv4_receive_message);

    return TRUE;
}

static gboolean
udp_ipv6_send_message(GNetSnmpTAddress *taddress,
		      guchar *msg, gsize msg_len, GError **error)
{
    gint rv;

    g_return_val_if_fail(taddress
		 && taddress->domain == GNET_SNMP_TDOMAIN_UDP_IPV6, FALSE);

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(msg, msg_len);
    }

    rv = gnet_udp_socket_send(udp_ipv6_socket, (gchar *) msg,
			      msg_len, taddress->inetaddr);
    if (rv) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to write to udp/ipv6 socket: %s",
			g_strerror(errno));
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv6: send %d bytes to %s:%d\n",
		   (gint) msg_len,
		   gnet_inetaddr_get_name(taddress->inetaddr),
		   gnet_inetaddr_get_port(taddress->inetaddr));
    }
    return TRUE;
}

static void
udp_ipv6_receive_message(GError **error)
{
    guchar buffer[MAX_DGRAM_SIZE];
    GInetAddr* addr;
    int len;

    len = gnet_udp_socket_receive(udp_ipv6_socket, (gchar *) buffer, sizeof(buffer), &addr);
    if (! len) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_RECV,
			"failed to receive from udp/ipv6 socket");
	}
        return;
    }

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv6: received %d bytes from %s:%d\n", len,
		   gnet_inetaddr_get_name(addr),
		   gnet_inetaddr_get_port(addr));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(buffer, len);
    }
    gnet_snmp_dispatcher_recv_msg(
	gnet_snmp_taddress_new_inet(GNET_SNMP_TDOMAIN_UDP_IPV6, addr),
	buffer, len, NULL);
    gnet_inetaddr_delete(addr);
}

static gboolean
udp_ipv6_init(GError **error)
{
    GIOChannel *channel;
    GInetAddr *addr = gnet_inetaddr_new("::", 0);

    udp_ipv6_socket = gnet_udp_socket_new_full(addr, 0);
    if (! udp_ipv6_socket) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SOCKET,
			"failed to create udp/ipv6 socket: %s",
			g_strerror(errno));
	} else {
	    g_warning("opening snmp over udp/ipv6 socket failed");
	}
	return FALSE;
    }

    channel = gnet_udp_socket_get_io_channel(udp_ipv6_socket);
    if (! channel) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_REGISTER,
			"failed to get io channel for udp/ipv6 socket: %s",
			g_strerror(errno));
	} else {
	    g_warning("failed to get io channel for udp/ipv6 socket: %s",
		      g_strerror(errno));
	}
	return FALSE;
    }
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, udp_ipv6_receive_message);

    return TRUE;
}

/*
 * xxx - first approximation handles just one established unix session
 */

static void
unix_receive_message()
{
    guchar buffer[MAX_DGRAM_SIZE];
    GIOChannel *channel;
    gchar *path;
    gsize len;

    path = gnet_unix_socket_get_path(unix_socket);
    channel = gnet_unix_socket_get_io_channel(unix_socket);
    if (! channel) {
	g_warning("retrieving snmp over local domain socket failed");
	return;
    }

    if (g_io_channel_read(channel, (gchar *) buffer, sizeof(buffer), &len)) {
        return;
    }

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. local: received %d bytes from %s\n",
		   (gint) len, path);
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(buffer, len);
    }
    gnet_snmp_dispatcher_recv_msg(
	gnet_snmp_taddress_new_path(GNET_SNMP_TDOMAIN_LOCAL, path),
	buffer, len, NULL);
}

static gboolean
unix_send_message(GNetSnmpTAddress *taddress,
		  guchar *msg, gsize msg_len, GError **error)
{
    GIOChannel *channel;
    gsize len;
    
    g_return_val_if_fail(taddress
		 && taddress->domain == GNET_SNMP_TDOMAIN_LOCAL, FALSE);

    if (! unix_socket
	|| strcmp(taddress->path, gnet_unix_socket_get_path(unix_socket))) {
	if (unix_socket) {
	    gnet_unix_socket_delete(unix_socket);
	}
	if (g_access(taddress->path, R_OK | W_OK) != 0) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_TRANSPORT_ERROR,
			    GNET_SNMP_TRANSPORT_ERROR_CONNECT,
			    "no access to '%s': %s",
			    taddress->path,
			    g_strerror(errno));
	    }
	    return FALSE;
	}
	unix_socket = gnet_unix_socket_new(taddress->path);
	if (! unix_socket) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_TRANSPORT_ERROR,
			    GNET_SNMP_TRANSPORT_ERROR_CONNECT,
			    "failed to create socket '%s': %s",
			    taddress->path,
			    g_strerror(errno));
	    }
	    return FALSE;
	}
    }

    channel = gnet_unix_socket_get_io_channel(unix_socket);
    if (! channel) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_REGISTER,
			"failed get io channel for '%s': %s",
			taddress->path,
			g_strerror(errno));
	}
	return FALSE;
    }

    (void) g_io_channel_set_flags(channel, G_IO_FLAG_NONBLOCK, error);
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. local: send %d bytes to %s\n",
		   (gint) msg_len,
		   gnet_unix_socket_get_path(unix_socket));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(msg, msg_len);
    }
    
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, unix_receive_message);
    if (G_IO_ERROR_NONE != gnet_io_channel_writen(channel, msg,
						  msg_len, &len)) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to write to '%s': %s",
			taddress->path,
			g_strerror(errno));
	}
	gnet_unix_socket_delete(unix_socket);
	unix_socket = NULL;
	return FALSE;
    }
    return TRUE;
}

static gboolean
unix_init(GError **error)
{
    unix_socket = NULL;
    return TRUE;
}

gboolean
gnet_snmp_transport_send(GNetSnmpTAddress *taddress,
			 guchar *msg, guint msg_len, GError **error)
{
    static int initialized = 0;

    g_return_val_if_fail(taddress, FALSE);

    if (! initialized) {		/* xxx race condition xxx */
	if (! *error) udp_ipv4_init(error);
	if (! *error) tcp_ipv4_init(error);
	if (! *error) udp_ipv6_init(error);
	if (! *error) unix_init(error);
	initialized = 1;
    }

    switch (taddress->domain) {
    case GNET_SNMP_TDOMAIN_UDP_IPV4:
	return udp_ipv4_send_message(taddress, msg, msg_len, error);
    case GNET_SNMP_TDOMAIN_TCP_IPV4:
	return tcp_ipv4_send_message(taddress, msg, msg_len, error);
    case GNET_SNMP_TDOMAIN_UDP_IPV6:
	return udp_ipv6_send_message(taddress, msg, msg_len, error);
    case GNET_SNMP_TDOMAIN_LOCAL:
	return unix_send_message(taddress, msg, msg_len, error);
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_UNSUPPORTED,
			"unsupported transport domain %d",
			taddress->domain);
	}
	break;
    }

    return FALSE;
}
