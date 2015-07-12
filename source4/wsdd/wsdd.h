/*
   Unix SMB/CIFS implementation.

   Web Services for Device and LLMNR Samba service

   https://msdn.microsoft.com/library/windows/desktop/aa826001(v=vs.85).aspx
   https://msdn.microsoft.com/library/windows/hardware/jj123472.aspx
   https://tools.ietf.org/html/rfc4795

   Copyright (C) Tobias Waldvogel 2013
   Copyright (C) Jose M. Prieto 2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef WSDD_H
#define WSDD_H

#include "smbd/service_task.h"

/* struct for computer device */
struct wsdd_devinfo {
	char *name;
	char *workgroup;
	char friendly_name[128];
	char url[256];
	char manufacturer[128];
	char model[128];
	char serial[32];
	char firmware[16];
};

struct wsdd_server {
	struct task_server *task;
	uint32_t instance_id;
	char *endpoint;
	char *sequence;
	uint64_t msg_no;
	struct wsdd_devinfo *devinfo;
	struct interface *ifaces;
	char **ipaddrs;
	bool enable_wcard;
	bool enable_ipv4;
	bool enable_ipv6;
};

#endif
