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

#include <gnet.h>

#include "transport.h"
#include "dispatch.h"
#include "pdu.h"	/* xxx only needed for debugging flags... */


static GUdpSocket *udp_ipv4_socket = NULL;
static GUdpSocket *udp_ipv6_socket = NULL;

static GTcpSocket *tcp_ipv4_socket = NULL;	/* this should be a pool */

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
 * Subroutine to dump packet contents to the screen - jms
 */

static void
dump_packet(guchar *data, guint len)
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

    if (g_io_channel_read(channel, buffer, sizeof(buffer), &len)) {
        return;
    }

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. tcp/ipv4: received %d bytes from %s:%d\n", len,
		   gnet_inetaddr_get_name(addr),
		   gnet_inetaddr_get_port(addr));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(buffer, len);
    }
    g_receive_message(GNET_SNMP_TDOMAIN_TCP_IPV4, addr, buffer, len);
    gnet_inetaddr_delete(addr);
}

static gboolean
tcp_ipv4_send_message(GInetAddr *taddress,
		      guchar *outgoingMessage,
		      guint outgoingMessageLength,
		      GError **error)
{
    GIOChannel *channel;
    guint len;
    
    if (! tcp_ipv4_socket
	|| ! gnet_inetaddr_equal(taddress, gnet_tcp_socket_get_remote_inetaddr(tcp_ipv4_socket))) {
	if (tcp_ipv4_socket) {
	    gnet_tcp_socket_delete(tcp_ipv4_socket);
	}
	tcp_ipv4_socket = gnet_tcp_socket_new(taddress);
	if (! tcp_ipv4_socket) {
	    if (error) {
		g_set_error(error,
			    GNET_SNMP_TRANSPORT_ERROR,
			    GNET_SNMP_TRANSPORT_ERROR_CONNECT,
			    "failed to connect tcp/ipv4 socket");
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
			"failed to register tcp/ipv4 socket");
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. tcp/ipv4: send %d bytes to %s:%d\n", len,
		   gnet_inetaddr_get_name(taddress),
		   gnet_inetaddr_get_port(taddress));
    }
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(outgoingMessage, outgoingMessageLength);
    }
    
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, tcp_ipv4_receive_message);
    if (G_IO_ERROR_NONE != gnet_io_channel_writen(channel, outgoingMessage,
						  outgoingMessageLength,
						  &len)) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to send over tcp/ipv4 socket");
	}
	gnet_tcp_socket_delete(tcp_ipv4_socket);
	tcp_ipv4_socket = NULL;
	return FALSE;
    }
    return TRUE;
}

static gboolean
tcp_ipv4_init(gboolean dobind)		/* xxx dobind is not used */
{
    tcp_ipv4_socket = NULL;
    return TRUE;
}

static gboolean
udp_ipv4_send_message(GInetAddr *taddress,
		      guchar *outgoingMessage,
		      guint outgoingMessageLength,
		      GError **error)
{
    gint rv;

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(outgoingMessage, outgoingMessageLength);
    }

    rv = gnet_udp_socket_send(udp_ipv4_socket, outgoingMessage,
			      outgoingMessageLength, taddress);
    if (rv) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to send over udp/ipv4 socket");
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv4: send %d bytes to %s:%d\n",
		   outgoingMessageLength,
		   gnet_inetaddr_get_name(taddress),
		   gnet_inetaddr_get_port(taddress));
    }
    return TRUE;
}

static void
udp_ipv4_receive_message(GError **error)
{
    guchar buffer[MAX_DGRAM_SIZE];
    GInetAddr* addr;
    int len;

    len = gnet_udp_socket_receive(udp_ipv4_socket, buffer, sizeof(buffer), &addr);
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
    g_receive_message(GNET_SNMP_TDOMAIN_UDP_IPV4, addr, buffer, len);
    gnet_inetaddr_delete(addr);
}

static gboolean
upd_ipv4_init(gboolean dobind)		/* xxx dobind is not used */
{
    GIOChannel *channel;

    udp_ipv4_socket = gnet_udp_socket_new();
    if (! udp_ipv4_socket) {
	g_warning("opening snmp over udp/ipv4 socket failed");
	return FALSE;
    }

    channel = gnet_udp_socket_get_io_channel(udp_ipv4_socket);
    if (! channel) {
        g_error("registering snmp over udp/ipv4 socket failed");
	return FALSE;
    }
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, udp_ipv4_receive_message);

    return TRUE;
}

static gboolean
udp_ipv6_send_message(GInetAddr *taddress,
		      guchar *outgoingMessage,
		      guint outgoingMessageLength,
		      GError **error)
{
    gint rv;

    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_PACKET) {
	dump_packet(outgoingMessage, outgoingMessageLength);
    }

    rv = gnet_udp_socket_send(udp_ipv6_socket, outgoingMessage,
			      outgoingMessageLength, taddress);
    if (rv) {
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_SEND,
			"failed to send over udp/ipv6 socket");
	}
	return FALSE;
    }
    
    if (gnet_snmp_debug_flags & GNET_SNMP_DEBUG_TRANSPORT) {
	g_printerr("transp. udp/ipv6: send %d bytes to %s:%d\n",
		   outgoingMessageLength,
		   gnet_inetaddr_get_name(taddress),
		   gnet_inetaddr_get_port(taddress));
    }
    return TRUE;
}

static void
udp_ipv6_receive_message(GError **error)
{
    guchar buffer[MAX_DGRAM_SIZE];
    GInetAddr* addr;
    int len;

    len = gnet_udp_socket_receive(udp_ipv6_socket, buffer, sizeof(buffer), &addr);
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
    g_receive_message(GNET_SNMP_TDOMAIN_UDP_IPV6, addr, buffer, len);
    gnet_inetaddr_delete(addr);
}

static gboolean
udp_ipv6_init(gboolean dobind)
{
    GIOChannel *channel;
    GInetAddr *addr = gnet_inetaddr_new("::", 0);

    udp_ipv6_socket = gnet_udp_socket_new_full(addr, 0);
    if (! udp_ipv6_socket) {
	g_warning("opening snmp over udp/ipv6 socket failed");
	return FALSE;
    }

    channel = gnet_udp_socket_get_io_channel(udp_ipv6_socket);
    if (! channel) {
        g_error("registering snmp over udp/ipv6 socket failed");
	return FALSE;
    }
    g_io_add_watch(channel, (G_IO_IN | G_IO_PRI),
		   gaga, udp_ipv6_receive_message);

    return TRUE;
}

gboolean
gnet_snmp_transport_send(GNetSnmpTDomain tdomain, GInetAddr *taddress,
			 guchar *msg, guint msg_len, GError **error)
{
    static int initialized = 0;

    if (! initialized) {		/* xxx race condition xxx */
	initialized = 1;
	upd_ipv4_init(0);
	tcp_ipv4_init(0);
	udp_ipv6_init(0);
    }

    switch (tdomain) {
    case GNET_SNMP_TDOMAIN_UDP_IPV4:
	return udp_ipv4_send_message(taddress, msg, msg_len, error);
    case GNET_SNMP_TDOMAIN_TCP_IPV4:
	return tcp_ipv4_send_message(taddress, msg, msg_len, error);
    case GNET_SNMP_TDOMAIN_UDP_IPV6:
	return udp_ipv6_send_message(taddress, msg, msg_len, error);
    default:
	if (error) {
	    g_set_error(error,
			GNET_SNMP_TRANSPORT_ERROR,
			GNET_SNMP_TRANSPORT_ERROR_UNSUPPORTED,
			"unsupported transport domain");
	}
	break;
    }

    return FALSE;
}


