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

#ifndef __GNET_SNMP_TRANSPORT_H__
#define __GNET_SNMP_TRANSPORT_H__

/*
 * Enumeration for the SNMP transport domains we care of.
 */

typedef enum {
    GNET_SNMP_TDOMAIN_NONE	= 0,
    GNET_SNMP_TDOMAIN_UDP_IPV4	= 1,	/* RFC 3417 */
    GNET_SNMP_TDOMAIN_UDP_IPV6	= 2,
    GNET_SNMP_TDOMAIN_IPX	= 3,	/* RFC 3417 */
    GNET_SNMP_TDOMAIN_TCP_IPV4	= 4,	/* RFC 3430 */
    GNET_SNMP_TDOMAIN_TCP_IPV6	= 5	/* RFC 3430 */
} GNetSnmpTDomain;

/*
 * The maximum datagram size we are prepared to deal with.
 */

#define MAX_DGRAM_SIZE 32768

/*
 * Transport related runtime error handling.
 */

typedef enum
{
    GNET_SNMP_TRANSPORT_ERROR_SEND,
    GNET_SNMP_TRANSPORT_ERROR_RECV,
    GNET_SNMP_TRANSPORT_ERROR_CONNECT,
    GNET_SNMP_TRANSPORT_ERROR_REGISTER,
    GNET_SNMP_TRANSPORT_ERROR_UNSUPPORTED,
} GNetSnmpTransportError;

#define GNET_SNMP_TRANSPORT_ERROR gnet_snmp_transport_error_quark()

GQuark	 gnet_snmp_transport_error_quark();

/*
 * The entrance into the transport module.
 */

gboolean gnet_snmp_transport_send	(GNetSnmpTDomain tdomain,
					 GInetAddr *taddress,
					 guchar *msg,
					 guint msg_len,
					 GError **error);

#endif /* __GNET_SNMP_TRANSPORT_H__ */
