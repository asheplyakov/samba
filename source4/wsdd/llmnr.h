/*
   Unix SMB/CIFS implementation.

   Link-Local Multicast Name Resolution (LLMNR) helper function (header)
   (https://tools.ietf.org/html/rfc4795)

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
#ifndef LLMNR_H
#define LLMNR_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <talloc.h>

#include "lib/util/data_blob.h"

#define LLMNR_MCAST_ADDR ("224.0.0.252")
#define LLMNR_MCAST6_ADDR ("FF02::1:3")
#define LLMNR_PORT 5355

DATA_BLOB llmnr_call_process(TALLOC_CTX *, DATA_BLOB,
                             const char *, const char *);

#endif

