/*
   Unix SMB/CIFS implementation.

   Web Services for Devices (WSD) helper functions (header)

   https://msdn.microsoft.com/library/windows/desktop/aa826001(v=vs.85).aspx
   https://msdn.microsoft.com/library/windows/hardware/jj123472.aspx

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
#ifndef WSD_H
#define WSD_H

#include <talloc.h>

#include "wsdd.h"
#include "xmlns.h"
#include "lib/util/data_blob.h"

#define WSD_PORT		3702
#define WSD_HTTP_PORT		WSD_PORT
#define WSD_MCAST_ADDR		("239.255.255.250")
#define WSD_MCAST6_ADDR		("FF02::C")
#define WSD_HTTP_TIMEOUT	120

enum wsd_action {
	WSD_ACTION_NONE,
	WSD_ACTION_HELLO,
	WSD_ACTION_BYE,
	WSD_ACTION_PROBE,
	WSD_ACTION_PROBEMATCH,
	WSD_ACTION_RESOLVE,
	WSD_ACTION_RESOLVEMATCH,
	WSD_ACTION_GET,
	WSD_ACTION_GETRESPONSE
};

struct wsd_req_info {
	char *action;
	char *msgid;
	struct {
		struct xmlns_qname *types[64];
		size_t types_length;
	} probe;
	struct {
		char *endpoint;
	} resolve;
};

struct wsd_req_info *wsd_req_parse(TALLOC_CTX *, DATA_BLOB);
enum wsd_action wsd_action_id(struct wsd_req_info *);
DATA_BLOB wsd_soap_fault(TALLOC_CTX *, int, const char *, const char *);
DATA_BLOB wsd_response_http_header(TALLOC_CTX *, uint16_t, uint32_t);
DATA_BLOB wsd_action_hello(TALLOC_CTX *, struct wsdd_server *);
DATA_BLOB wsd_action_bye(TALLOC_CTX *, struct wsdd_server *);
DATA_BLOB wsd_action_probe(TALLOC_CTX *, struct wsdd_server *,
			   struct wsd_req_info *, const char *, const uint16_t);
DATA_BLOB wsd_action_resolve(TALLOC_CTX *, struct wsdd_server *,
			     struct wsd_req_info *, const char *,
			     const uint16_t);
DATA_BLOB wsd_action_get(TALLOC_CTX *, struct wsdd_server *,
			 struct wsd_req_info *);

#endif

