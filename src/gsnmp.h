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

#ifndef __GNET_SNMP_H__
#define __GNET_SNMP_H__

#include <gnet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

G_BEGIN_DECLS

typedef enum
{
    GNET_SNMP_DEBUG_REQUESTS	= 1 << 0,
    GNET_SNMP_DEBUG_SESSION	= 1 << 1,
    GNET_SNMP_DEBUG_TRANSPORT	= 1 << 2,
    GNET_SNMP_DEBUG_PACKET	= 1 << 3,
    GNET_SNMP_DEBUG_BER		= 1 << 4,
    GNET_SNMP_DEBUG_ALL		= GNET_SNMP_DEBUG_REQUESTS
				  | GNET_SNMP_DEBUG_SESSION
				  | GNET_SNMP_DEBUG_TRANSPORT
				  | GNET_SNMP_DEBUG_PACKET
				  | GNET_SNMP_DEBUG_BER,
    GNET_SNMP_DEBUG_MASK	= 0x1f
} GNetSnmpDebugFlags;

extern		GNetSnmpDebugFlags gnet_snmp_debug_flags;

#include "ber.h"
#include "pdu.h"
#include "transport.h"
#include "message.h"
#include "security.h"
#include "session.h"
#include "dispatch.h"
#include "utils.h"

gboolean	gnet_snmp_init(gboolean dobind);

G_END_DECLS

#endif /* __GNET_SNMP_H__ */
