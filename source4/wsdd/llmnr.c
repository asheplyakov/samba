/*
   Unix SMB/CIFS implementation.

   Link-Local Multicast Name Resolution (LLMNR) helper functions
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "llmnr.h"
#include "includes.h"
#include "lib/util/debug.h"

/* set new debug class */
#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_WSDD

#define DNS_TYPE_A	0x0001
#define DNS_CLASS_IN	0x0001

DATA_BLOB llmnr_call_process(TALLOC_CTX *mem_ctx, DATA_BLOB in,
				const char *myname, const char *ip)
{
	uint16_t qdcount, ancount, nscount;
	uint16_t qtype, qclass;
	char *in_name, in_label[64];
	uint8_t *in_name_p;
	size_t in_name_len, out_name_len;
	DATA_BLOB out = data_blob_null;
	struct in_addr si;
	int ret;

	/*
	 * LLMNR header format according to RFC 4795:
	 *
	 *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |                   ID                          |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |QR|   Opcode  | C|TC| T| Z| Z| Z| Z|   RCODE   |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |                  QDCOUNT                      |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |                  ANCOUNT                      |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |                  NSCOUNT                      |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |                  ARCOUNT                      |
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 */

	/*
	 * LLMNR packet format has a header of 12 bytes
	 * plus at least 1 byte of question section
	 * (see RFCs 4795 and 1035)
	 */
	if (in.length < 13) {
		DEBUG(1, ("llmnr: packet less than 13 bytes\n"));
		return out;
	}

	/*
	 * 3rd octect of LLMNR header
	 * check for standard query:
	 * - Q/R (1-bit)     = 0
	 * - OPCODE (4-bits) = 0
	 */
	if (in.data[2] & 0xF8) {
		DEBUG(1, ("llmnr: not standard query\n"));
		return out;
	}

	/* check whether conflict bit (C) is not set */
	if (in.data[2] & 0x04) {
		DEBUG(1, ("llmnr: conflict bit set in query\n"));
		return out;
	}

	/* check whether truncation bit is not set */
	if (in.data[2] & 0x02) {
		DEBUG(1, ("llmnr: truncation bit set in query\n"));
		return out;
	}

	/*
	 * check number of entries in question section (QDCOUNT)
	 * it must be just one
	 */
	qdcount = (in.data[4]*256) + in.data[5];
	if (qdcount != 1) {
		DEBUG(1, ("llmnr: only a question entry allowed, "
			  "found %u\n", (unsigned)qdcount));
		return out;
	}

	/*
	 * check number of entries in answer and nameserver sections
	 * must be zero in the request
	 */
	ancount = (in.data[6]*256) + in.data[7];
	nscount = (in.data[8]*256) + in.data[9];
	if (ancount > 0 || nscount > 0) {
		DEBUG(1, ("llmnr: number of answer and/or nameserver entries "
			  "in query is invalid (ancount: %u, nscount: %u)\n",
			  (unsigned)ancount, (unsigned)nscount));
		return out;
	}

	/* process all labels in question section */
	in_name = NULL;
	in_name_len = 0;
	in_name_p = &in.data[12];
	while (*in_name_p > 0) {
		/*
		 * not supporting message compression
		 * see section 4.1.4 of RFC 1035
		 */
		if (*in_name_p >= 0xC0) {
			DEBUG(1, ("llmnr: message compression not "
				  "supported\n"));
			TALLOC_FREE(in_name);
			return out;
		}

		/* process current label in question section */
		memcpy(in_label, in_name_p+1, *in_name_p);
		in_label[*in_name_p + 1] = '\0';

		/* append to the whole name */
		in_name_len += *in_name_p + 1;
		if (in_name) {
			in_name = talloc_asprintf_append_buffer(in_name, ".%s",
								in_label);
		} else {
			in_name = talloc_asprintf(mem_ctx, "%s", in_label);
		}

		/* next label */
		in_name_p += (*in_name_p + 1);
		memset(in_label, 0, sizeof(in_label));
	}

	DEBUG(10, ("llmnr: name in query %s (length: %lu)\n", in_name,
		   in_name_len));

	/*
	 * this implementation only supports questiosn of type A
	 * and class IN
	 */
	qtype = in_name_p[1]*256 + in_name_p[2];
	qclass = in_name_p[3]*256 + in_name_p[4];
	if (qtype != DNS_TYPE_A || qclass != DNS_CLASS_IN ) {
		DEBUG(1, ("llmnr: record in question not of type A or "
			  "class IN\n"));
		return out;
	}

	/* check whether we are authorize for resolving this query */
	in_name_len = strlen(in_name);
	if (strlen(myname) != in_name_len ||
	    strncasecmp(myname, in_name, in_name_len))
	{
		DEBUG(1, ("llmnr: not authoritative for name %s\n", in_name));
		TALLOC_FREE(in_name);
		return out;
	}

	TALLOC_FREE(in_name);

	/*
	 * start building up the LLMNR response
	 */

	ret = inet_pton(AF_INET, ip, &si);
	if (ret <= 0) {
		DEBUG(1, ("llmnr: can't convert %s to network byte order\n",
			  ip));
		return out;
	}

	/*
	 * allocate output buffer
	 * size will be same one as incoming query plus the answer section
	 * according to RFC 1035, answer section size will be:
	 * - 2 bytes for pointer a name in query section (we are using a
	 *   referral)
	 * - 2 bytes QTYPE
	 * - 2 bytes QCLASS
	 * - 4 bytes TTL
	 * - 2 bytes RDLENGTH
	 * - 4 bytes RDATA (AF_INET address in network byte order)
	 */
	out = data_blob_talloc_zero(mem_ctx, in.length+12+sizeof(si));
	if (out.data == NULL) {
		DEBUG(1, ("llmnr: no memory for output buffer\n"));
		return data_blob_null;
	}

	/* copy incoming message to output buffer */
	memcpy(out.data, in.data, in.length);

	/*
	 * set flags in response:
	 * - QR bit sets to 1
	 * - OPCODE sets to 0
	 * - C, TC and T bits set to 0
	 * - RCODE sets to 0
	 */
	(out.data)[2] = 0x80;
	(out.data)[3] = 0x00;

	/* one answer */
	(out.data)[6] = 0x00;
	(out.data)[7] = 0x01;

	/* offset to beginning of answer section */
	out_name_len = in.length;

	/*
	 * pointer to name in question section
	 * (offset is 12th bytes from packet beginning)
	 */
	(out.data)[out_name_len++] = 0xC0;
	(out.data)[out_name_len++] = 0x0C;

	/* type A */
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = 0x01;

	/* class IN */
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = 0x01;

	/* TTL */
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = 0x00;

	/* RDLENGTH and RDATA in answer section */
	(out.data)[out_name_len++] = 0x00;
	(out.data)[out_name_len++] = sizeof(si);
	memcpy(out.data+out_name_len, &si, sizeof(si));

	return out;
}

