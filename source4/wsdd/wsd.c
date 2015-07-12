/*
   Unix SMB/CIFS implementation.

   Web Services for Devices (WSD) helper functions

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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <talloc.h>

#include "wsdd.h"
#include "yxml.h"
#include "xmlns.h"
#include "wsd.h"
#include "includes.h"
#include "lib/util/debug.h"
#include "lib/util/data_blob.h"
#include "librpc/ndr/libndr.h"

/* set new debug class */
#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_WSDD

#define XML_PARSE_BUFSIZE (8*1024)

#define SOAP11_NS \
	"http://schemas.xmlsoap.org/soap/envelope/"
#define SOAP12_NS \
	"http://www.w3.org/2003/05/soap-envelope"
#define WSA_NS \
	"http://schemas.xmlsoap.org/ws/2004/08/addressing"
#define WSD_NS \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery"
#define WXT_NS \
	"http://schemas.xmlsoap.org/ws/2004/09/transfer"
#define WSD_ACT_HELLO \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello"	
#define WSD_ACT_BYE \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye"
#define WSD_ACT_PROBE \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
#define WSD_ACT_PROBEMATCH \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches"
#define WSD_ACT_RESOLVE \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve"
#define WSD_ACT_RESOLVEMATCH \
	"http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches"
#define WXT_ACT_GET \
	"http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
#define WXT_ACT_GETRESPONSE \
	"http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse"
#define WSD_TO_DISCOVERY \
	"urn:schemas-xmlsoap-org:ws:2005:04:discovery"
#define WSD_TO_ANONYMOUS \
	"http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

/*
 * macros
 */
#define RESET_BUFFER(buf, buflen) \
	if (buflen > 0) do { memset(buf, 0, buflen); buflen=0; } while(0)

#define COPY_STRING_TO_BUFFER(dst, dstlen, start, src, srclen) \
	do { \
		srclen = strlen(src); \
		if (((start + srclen) - dst) > dstlen) { \
			srclen = -1; \
			break; \
		} \
		strncpy(start, src, srclen); \
		start += srclen; \
	} while(0)

#define RESOLVE_TAG_AND_SAVE \
	do { \
		qn = xmlns_resolve_tag(mem_ctx, table, tag); \
		if (qn) { \
			(*qnames_len)++; \
			qnames[(*qnames_len)-1] = qn; \
		} \
	} while(0)

/*
 * type definitions
 */
struct wsd_req_rawinfo {
	char *action;
	char *msgid;
	struct {
		char *types;
	} probe;
	struct {
		char *endpoint;
	} resolve;
};


/* dump xmlns resolver table into a destination buffer */
static char *wsd_xmlns_resolv_table_to_string(char *dest, size_t size,
				struct xmlns_table *table)
{
	int i, j;
	char *p_dest = dest;
	char tmpbuf[16*1024];
	size_t tmpbuf_len;
	struct xmlns_entry *entry;
	struct xmlns_uri *uri;

	memset(dest, 0, size);

	if (!table) {
		return dest;
	}

	snprintf(tmpbuf, sizeof(tmpbuf),
		 "  table pointer: %p\n  # of entries: %lu\n"
		 "  bytes reserved for scope buffer: %lu\n"
		 "  current scope: %s\n", table, table->n_entries,
		 table->scope_bufsize, table->scope);
	COPY_STRING_TO_BUFFER(dest, size, p_dest, tmpbuf, tmpbuf_len);
	if (tmpbuf_len == -1) {
		return dest;
	}

	i = 0;
	entry = table->entries;
	while(entry) {
		i++;

		snprintf(tmpbuf, sizeof(tmpbuf),
			 "  entry #%d:\n    prefix: %s\n"
			 "    uri stack:\n", i, entry->prefix);
		COPY_STRING_TO_BUFFER(dest, size, p_dest, tmpbuf, tmpbuf_len);
		if (tmpbuf_len == -1) {
			return dest;
		}

		j = 0;
		uri = entry->uri_stack;
		while(uri) {
			j++;

			snprintf(tmpbuf, sizeof(tmpbuf), 
				 "      #%d: %s -> %s\n", j, uri->scope, 
				 uri->uri);
			COPY_STRING_TO_BUFFER(dest, size, p_dest, tmpbuf, 
					      tmpbuf_len);
			if (tmpbuf_len == -1) {
				return dest;
			}

			uri = uri->next;
		}

		entry = entry->next;
	}	

	return dest;
}

static char *wsd_escape_string(char *dest, size_t size, const char *str)
{
	char *tmp = dest;

	memset(dest, 0, size);
	
	while ((tmp-dest) < size && *str) {
		if (*str == '\x7F' || (*str >= 0 && *str <= 0x20)) {
			snprintf(tmp, size, "\\x%02X", *str);
			tmp += 4;
		} else {
			snprintf(tmp, size, "%c", *str);
		}
		str++;
	}

	return dest;
}

static void wsd_read_raw_data(TALLOC_CTX *mem_ctx, char **dst, const char *data)
{
	if (!data) {
		return;
	}

	if (*dst) {
		*dst = talloc_strdup_append_buffer(*dst, data);
	} else {
		*dst = talloc_strdup(mem_ctx, data);
	}

	return;
}

/* 
 * trim leading and tailing whitespaces from str
 */
static void wsd_trim_string(TALLOC_CTX *mem_ctx, char **dst, const char *str)
{
	char *start = NULL, *end = NULL;
	size_t str_len;
	int i;

	if (!str) {
		return;
	}

	str_len = strlen(str);

	/* find start of string */
	for(i=0; i<str_len; i++) {
		if (!isspace(str[i])) {
			start = (char *)&str[i];
			break;
		}
	}

	if (!start) {
		/* whole string is blank, return NULL */ 
		*dst = NULL;
		return;
	}

	/* find end of string */
	for(i=str_len-1; i>=0; i--) {
		if (!isspace(str[i])) {
			end = (char *)&str[i];
			break;
		}
	}

	/* create new string */
	*dst = talloc_strndup(mem_ctx, start, end - start + 1);

	return;
}

/* convert list of types to QName */	
static void wsd_read_probe_types(TALLOC_CTX *mem_ctx, 
				struct xmlns_table *table, const char *data, 
				struct xmlns_qname **qnames, size_t *qnames_len)
{
	char *new_s, *s1, *s2 = NULL;
	char tag[1024];
	struct xmlns_qname *qn;

	*qnames_len = 0;

	if (!data) {
		return;
	}

	/* trim leading and trailing whitespaces */
	wsd_trim_string(mem_ctx, &new_s, data);
	s1 = new_s;

	/* loop over string */
	while (s1 && *s1) {
		if (!s2 && !isspace(*s1)) {
			s2 = s1;
		} else if (s2 && isspace(*s1)) {
			memset(tag, 0, sizeof(tag));
			strncpy(tag, s2, s1-s2);
			RESOLVE_TAG_AND_SAVE;
			s2 = NULL;
		}
		s1++;
	}

	/* process loop leftovers */
	if (s2) {
		memset(tag, 0, sizeof(tag));
		strncpy(tag, s2, sizeof(tag));
		RESOLVE_TAG_AND_SAVE;
	}

	/* release resources */
	TALLOC_FREE(new_s);

	return;
}

struct wsd_req_info *wsd_req_parse(TALLOC_CTX *mem_ctx, DATA_BLOB xml)
{
	struct wsd_req_info *info;
	struct wsd_req_rawinfo *rawinfo;
	yxml_t *parser;
	struct xmlns_table *xmlns_table;
	struct xmlns_qname *qn_elem;
	bool xmlns_attr_ctx = false;
	char *xmlns_prefix;
	char content[32*1024];
	size_t content_len, data_len;
	char tmp_string[32*1024];
	int i;

	const struct xmlns_qname qn_envelope = {
		.namespace = SOAP12_NS,
		.localname = "Envelope",
	};

	const struct xmlns_qname qn_header = {
		.namespace = SOAP12_NS,
		.localname = "Header",
	};

	const struct xmlns_qname qn_body = {
		.namespace = SOAP12_NS,
		.localname = "Body",
	};

	const struct xmlns_qname qn_action = {
		.namespace = WSA_NS,
		.localname = "Action",
	};

	const struct xmlns_qname qn_endpointref = {
		.namespace = WSA_NS,
		.localname = "EndpointReference",
	};

	const struct xmlns_qname qn_address = {
		.namespace = WSA_NS,
		.localname = "Address",
	};

	const struct xmlns_qname qn_msgid = {
		.namespace = WSA_NS,
		.localname = "MessageID",
	};

	const struct xmlns_qname qn_probe = {
		.namespace = WSD_NS,
		.localname = "Probe",
	};

	const struct xmlns_qname qn_resolve = {
		.namespace = WSD_NS,
		.localname = "Resolve",
	};

	const struct xmlns_qname qn_types = {
		.namespace = WSD_NS,
		.localname = "Types",
	};

	/* initialize xml parser */
	parser = talloc_size(mem_ctx, sizeof(yxml_t) + XML_PARSE_BUFSIZE);
	yxml_init(parser, parser+1, XML_PARSE_BUFSIZE);
	if (!parser) {
		DEBUG(1, ("wsd: cannot initialize YXML parser\n"));
		return NULL;
	}

	/* initialize xmlns resolver table */
	xmlns_table = xmlns_init_resolver(mem_ctx);
	if (!xmlns_table) {
		DEBUG(1, ("wsd: cannot initialize XML namespace "
			  "resolver table\n"));
		return NULL;
	}

	/* initialize WSD info structures */
	info = talloc_zero(mem_ctx, struct wsd_req_info);
	if (!info) {
		DEBUG(1, ("wsd: cannot initialize WSD info structure\n"));
		return NULL;
	}

	rawinfo = talloc_zero(mem_ctx, struct wsd_req_rawinfo);
	if (!rawinfo) {
		DEBUG(1, ("wsd: cannot initialize WSD raw info structure\n"));
		return NULL;
	}

	/* loop over the whole xml */
	for (i = 0; i < xml.length; i++) {
		switch(yxml_parse(parser, xml.data[i])) {
		case YXML_ELEMSTART:
			/* set current xmlns scope */
			xmlns_push_scope(xmlns_table, parser->elem);
			DEBUG(15, ("wsd: xmlns scope %s pushed into resolver "
				   "table\n", parser->elem));

			/* try to resolve current element */
			TALLOC_FREE(qn_elem);
			qn_elem = xmlns_resolve_tag(xmlns_table, xmlns_table,
						    parser->elem);
			DEBUG(15, ("wsd: resolve %s to QName %s\n",
				   parser->elem, 
				   xmlns_qname_to_string(tmp_string,
							 sizeof(tmp_string),
							 qn_elem)));

			/* reset content buffer */
			RESET_BUFFER(content, content_len);

			break;

		case YXML_ELEMEND:
			/* get current element in scope */
			snprintf(tmp_string, sizeof(tmp_string), "%s",
				xmlns_current_elem(xmlns_table));

			/*
			 * within /Envelope/Body/Probe/Types?
			 * if so resolve list of types to QName
			 */
			if (xmlns_qname_in_scope(xmlns_table, &qn_envelope) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_body) && 
			    xmlns_qname_in_scope(xmlns_table, &qn_probe) &&
			    xmlns_qname_equals(qn_elem, &qn_types))
			{
				wsd_read_probe_types(info, xmlns_table,
						     rawinfo->probe.types,
						     info->probe.types,
						     &info->probe.types_length);
				DEBUG(15, ("wsd: read content of tag "
					   "/Envelope/Body/Probe/Types\n"));
			}

			/* reset memory space for current QName struct */
			TALLOC_FREE(qn_elem);

			/* set current xmlns scope */
			xmlns_pop_scope(xmlns_table);
			DEBUG(15, ("wsd: xmlns scope %s popped from resolver "
				   "table\n", tmp_string));

			break;

		case YXML_ATTRSTART:
			/* found xmlns attr? */
			if (strstr(parser->attr, "xmlns") != NULL) {
				xmlns_attr_ctx = true;
				RESET_BUFFER(content, content_len);

				xmlns_prefix = strstr(parser->attr, ":");
				if (xmlns_prefix) {
					xmlns_prefix++;
				}

				DEBUG(15, ("wsd: xmlns attribute found within "
					   "element %s\n", parser->elem));
			}

			break;

		case YXML_ATTREND:
			if (xmlns_attr_ctx) {
				/*
				 * add found namespace to xmlns resolver 
				 * table
				 */
				xmlns_add_prefix(xmlns_table, xmlns_prefix,
						 content);
				DEBUG(15, ("wsd: add xmlns prefix %s to "
					   "resolver table\n", xmlns_prefix));

				/*
				 * since xmlns resolver table has changed
				 * try to resolve current element again
				 */
				TALLOC_FREE(qn_elem);
				qn_elem = xmlns_resolve_tag(xmlns_table,
							    xmlns_table, 
							    parser->elem);

				DEBUG(15, ("wsd: resolve %s to QName %s\n",
				      parser->elem,
				      xmlns_qname_to_string(tmp_string,
							    sizeof(tmp_string),
							    qn_elem)));
			}

			break;

		case YXML_ATTRVAL:
			if (xmlns_attr_ctx) {
				data_len = strlen(parser->data);
				strncpy(content+content_len, parser->data,
					data_len);
				content_len += data_len;
			}

			break;

		case YXML_CONTENT:
			if (!qn_elem) {
				break;
			}

			/* within /Envelope/Header/Action? */
			if (xmlns_qname_in_scope(xmlns_table, &qn_envelope) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_header) &&
			    xmlns_qname_equals(qn_elem, &qn_action))
			{
				wsd_read_raw_data(rawinfo, &rawinfo->action,
						  parser->data);
				DEBUG(15, ("wsd: read content of tag "
					   "/Envelope/Header/Action\n"));
			}
			
			/* within /Envelope/Header/MessageID? */
			if (xmlns_qname_in_scope(xmlns_table, &qn_envelope) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_header) && 
			    xmlns_qname_equals(qn_elem, &qn_msgid))
			{
				wsd_read_raw_data(rawinfo, &rawinfo->msgid,
						  parser->data);
				DEBUG(15, ("wsd: read content of tag "
					   "/Envelope/Header/MessageID\n"));
			}

			/* within /Envelope/Body/Probe/Types? */
			if (xmlns_qname_in_scope(xmlns_table, &qn_envelope) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_body) && 
			    xmlns_qname_in_scope(xmlns_table, &qn_probe) &&
			    xmlns_qname_equals(qn_elem, &qn_types))
			{
				wsd_read_raw_data(rawinfo,
						  &rawinfo->probe.types,
						  parser->data);
				DEBUG(15, ("wsd: read content of tag "
					   "/Envelope/Body/Probe/Types\n"));
			}

			/*
			 * within
			 * /Envelope/Body/Resolve/EndpointReference/Address? 
			 */
			if (xmlns_qname_in_scope(xmlns_table, &qn_envelope) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_body) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_resolve) &&
			    xmlns_qname_in_scope(xmlns_table, &qn_endpointref) &&
			    xmlns_qname_equals(qn_elem, &qn_address))
			{
				wsd_read_raw_data(rawinfo,
						  &rawinfo->resolve.endpoint,
						  parser->data);
				DEBUG(15, ("wsd: read content of tag "
					   "/Envelope/Body/Resolve"
					   "/EndpointReference/Address\n"));
			}
	
			break;
		}
	}

	if (yxml_eof(parser) == YXML_OK) {
		DEBUG(15, ("wsd: well-formed xml parsed successfully\n"));
		wsd_trim_string(info, &info->action, rawinfo->action);
		wsd_trim_string(info, &info->msgid, rawinfo->msgid);
		wsd_trim_string(info, &info->resolve.endpoint,
				rawinfo->resolve.endpoint);
	} else {
		DEBUG(15, ("wsd: failed to parse xml\n"));
		TALLOC_FREE(info);
	}

	TALLOC_FREE(parser);
	TALLOC_FREE(xmlns_table);
	TALLOC_FREE(rawinfo);

	return info;
}

enum wsd_action wsd_action_id(struct wsd_req_info *info)
{
	if (!info || !info->action) {
		return WSD_ACTION_NONE;
	}

	if (strcmp(info->action, WSD_ACT_HELLO) == 0) {
		return WSD_ACTION_HELLO;
	}

	if (strcmp(info->action, WSD_ACT_BYE) == 0) {
		return WSD_ACTION_BYE;
	}

	if (strcmp(info->action, WSD_ACT_PROBE) == 0) {
		return WSD_ACTION_PROBE;
	}

	if (strcmp(info->action, WSD_ACT_PROBEMATCH) == 0) {
		return WSD_ACTION_PROBEMATCH;
	}

	if (strcmp(info->action, WSD_ACT_RESOLVE) == 0) {
		return WSD_ACTION_RESOLVE;
	}

	if (strcmp(info->action, WSD_ACT_RESOLVEMATCH) == 0) {
		return WSD_ACTION_RESOLVEMATCH;
	}

	if (strcmp(info->action, WXT_ACT_GET) == 0) {
		return WSD_ACTION_GET;
	}

	if (strcmp(info->action, WXT_ACT_GETRESPONSE) == 0) {
		return WSD_ACTION_GETRESPONSE;
	}

	return WSD_ACTION_NONE;
}

/*
 * wsd soap fault
 */
DATA_BLOB wsd_soap_fault(TALLOC_CTX *mem_ctx, int code, const char *reason,
				const char *detail)
{
	const char soap_fault_fmt[] =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<soap:Envelope "
		"xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
		"xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\">"
		"<soap:Header>"
		"<wsa:Action>"
		"http://schemas.xmlsoap.org/ws/2004/09/transfer/fault"
		"</wsa:Action>"
		"</soap:Header>"
		"<soap:Body>"
		"<soap:Fault>"
		"<soap:Code>"
		"<soap:Value>%d</soap:Value>"
		"<soap:Subcode>"
		"<soap:Value>%d</soap:Value>"
		"<soap:Subcode>"
		"<soap:Value>%d</soap:Value>"
		"</soap:Subcode>"
		"</soap:Subcode>"
		"</soap:Code>"
		"<soap:Reason>"
		"<soap:Text xml:lang=\"en\">%s</soap:Text>"
		"</soap:Reason>"
		"<soap:Detail>%s</soap:Detail>"
		"</soap:Fault>"
		"</soap:Body>"
		"</soap:Envelope>";
	char *s;

	s = talloc_asprintf(mem_ctx, soap_fault_fmt, code, 0, 0,
			    reason, detail);

	DEBUG(16, ("wsd: generated WSD SOAP fault\n"));
	DEBUGADD(16, ("%s\n", s));

	return data_blob_string_const(s);
}

/*
 * complete and generate the whole WSD SOAP message 
 */
static DATA_BLOB wsd_generate_soap_msg(TALLOC_CTX *mem_ctx,
				uint32_t instance_id, const char *sequence,
				uint64_t *msg_no, const char *to,
				const char *action, const char *relates,
				const char *body)
{
	const char soap_msg_templ[] =
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<soap:Envelope "
		"xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
		"xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
		"xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
		"xmlns:wsx=\"http://schemas.xmlsoap.org/ws/2004/09/mex\" "
		"xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\" "
		"xmlns:un0=\"http://schemas.microsoft.com/windows/pnpx/2005/10\" "
		"xmlns:pub=\"http://schemas.microsoft.com/windows/pub/2005/07\">"
		"<soap:Header>"
		"<wsa:To>%s</wsa:To>"
		"<wsa:Action>%s</wsa:Action>"
		"<wsa:MessageID>urn:uuid:%s</wsa:MessageID>"
		"<wsd:AppSequence InstanceId=\"%u\" SequenceId=\"urn:uuid:%s\" "
		"MessageNumber=\"%lu\" />"
		"%s"
		"</soap:Header>"
		"%s"
		"</soap:Envelope>";

	char *soap_relates, *msg_id, *msg;
	struct GUID uuid;

	/* generate message uuid for response */
	uuid = GUID_random();
	msg_id = GUID_string(mem_ctx, &uuid);

	if (relates) {
		soap_relates =
			talloc_asprintf(mem_ctx, 
					"<wsa:RelatesTo>%s</wsa:RelatesTo>", 
					relates);
	} else {
		soap_relates = talloc_strdup(mem_ctx, "");
	}

	/* increment message counter */
	(*msg_no)++;

	msg = talloc_asprintf(mem_ctx, soap_msg_templ, to, action, msg_id,
			      instance_id, sequence, *msg_no, soap_relates,
			      body);

	DEBUG(16, ("wsd: generated WSD SOAP message\n"));
	DEBUGADD(16, ("%s\n", msg));

	TALLOC_FREE(soap_relates);

	return data_blob_string_const(msg);
}

DATA_BLOB wsd_action_hello(TALLOC_CTX *mem_ctx, struct wsdd_server *wsdd)
{
	DATA_BLOB out;
	char *body;

	const char body_templ[] =
		"<soap:Body>"
		"<wsd:Hello>"
		"<wsa:EndpointReference>"
		"<wsa:Address>urn:uuid:%s</wsa:Address>"
		"</wsa:EndpointReference>"
		"<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
		"<wsd:MetadataVersion>2</wsd:MetadataVersion>"
		"</wsd:Hello>"
		"</soap:Body>";

	body = talloc_asprintf(mem_ctx, body_templ, wsdd->endpoint);
	if (!body) {
		return data_blob_null;
	}

	out = wsd_generate_soap_msg(mem_ctx, wsdd->instance_id, wsdd->sequence,
				    &wsdd->msg_no, WSD_TO_DISCOVERY,
				    WSD_ACT_HELLO, NULL, body);
	TALLOC_FREE(body);

	return out;
}

DATA_BLOB wsd_action_bye(TALLOC_CTX *mem_ctx, struct wsdd_server *wsdd)
{
	DATA_BLOB out;
	char *body;

	const char body_templ[] =
		"<soap:Body>"
		"<wsd:Bye>"
		"<wsa:EndpointReference>"
		"<wsa:Address>urn:uuid:%s</wsa:Address>"
		"</wsa:EndpointReference>"
		"<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
		"<wsd:MetadataVersion>2</wsd:MetadataVersion>"
		"</wsd:Bye>"
		"</soap:Body>";

	body = talloc_asprintf(mem_ctx, body_templ, wsdd->endpoint);
	if (!body) {
		return data_blob_null;
	}

	out = wsd_generate_soap_msg(mem_ctx, wsdd->instance_id, wsdd->sequence,
				    &wsdd->msg_no, WSD_TO_DISCOVERY,
				    WSD_ACT_BYE, NULL, body);
	TALLOC_FREE(body);

	return out;
}

DATA_BLOB wsd_action_probe(TALLOC_CTX *mem_ctx, struct wsdd_server *wsdd,
				struct wsd_req_info *req_info, const char *ip,
				const uint16_t port)
{
	DATA_BLOB out;
	char *body;

	const char body_templ[] =
		"<soap:Body>"
		"<wsd:ProbeMatches>"
		"<wsd:ProbeMatch>"
		"<wsa:EndpointReference>"
		"<wsa:Address>urn:uuid:%s</wsa:Address>"
		"</wsa:EndpointReference>"
		"<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
		"<wsd:XAddrs>http://%s:%u/%s</wsd:XAddrs>"
		"<wsd:MetadataVersion>2</wsd:MetadataVersion>"
		"</wsd:ProbeMatch>"
		"</wsd:ProbeMatches>"
		"</soap:Body>";

	body = talloc_asprintf(mem_ctx, body_templ, wsdd->endpoint, ip, port,
			       wsdd->endpoint);
	if (!body) {
		return data_blob_null;
	}

	out = wsd_generate_soap_msg(mem_ctx, wsdd->instance_id, wsdd->sequence,
				    &wsdd->msg_no, WSD_TO_ANONYMOUS, 
				    WSD_ACT_PROBEMATCH, req_info->msgid, body);
	TALLOC_FREE(body);

	return out;

}

DATA_BLOB wsd_action_resolve(TALLOC_CTX *mem_ctx, struct wsdd_server *wsdd,
				struct wsd_req_info *req_info, const char *ip,
				const uint16_t port)
{
	DATA_BLOB out;

	char *body;

	const char body_templ[] =
		"<soap:Body>"
		"<wsd:ResolveMatches>"
		"<wsd:ResolveMatch>"
		"<wsa:EndpointReference>"
		"<wsa:Address>urn:uuid:%s</wsa:Address>"
		"</wsa:EndpointReference>"
		"<wsd:Types>wsdp:Device pub:Computer</wsd:Types>"
		"<wsd:XAddrs>http://%s:%u/%s</wsd:XAddrs>"
		"<wsd:MetadataVersion>2</wsd:MetadataVersion>"
		"</wsd:ResolveMatch>"
		"</wsd:ResolveMatches>"
		"</soap:Body>";

	body = talloc_asprintf(mem_ctx, body_templ, wsdd->endpoint, ip, port,
			       wsdd->endpoint);
	if (!body) {
		return data_blob_null;
	}

	out = wsd_generate_soap_msg(mem_ctx, wsdd->instance_id, wsdd->sequence,
				    &wsdd->msg_no, WSD_TO_ANONYMOUS, 
				    WSD_ACT_RESOLVEMATCH, req_info->msgid,
				    body);
	TALLOC_FREE(body);

	return out;
}

DATA_BLOB wsd_action_get(TALLOC_CTX *mem_ctx, struct wsdd_server *wsdd,
				struct wsd_req_info *req_info)
{
	DATA_BLOB out;
	char *body;

	const char body_templ[] =
		"<soap:Body>"
		"<wsx:Metadata>"
		"<wsx:MetadataSection Dialect=\""
		"http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisDevice\">"
		"<wsdp:ThisDevice>"
		"<wsdp:FriendlyName>%s</wsdp:FriendlyName>"
		"<wsdp:FirmwareVersion>%s</wsdp:FirmwareVersion>"
		"<wsdp:SerialNumber>%s</wsdp:SerialNumber>"
		"</wsdp:ThisDevice>"
		"</wsx:MetadataSection>"
		"<wsx:MetadataSection Dialect=\""
		"http://schemas.xmlsoap.org/ws/2006/02/devprof/ThisModel\">"
		"<wsdp:ThisModel>"
		"<wsdp:Manufacturer>%s</wsdp:Manufacturer>"
		"<wsdp:ManufacturerUrl>%s</wsdp:ManufacturerUrl>"
		"<wsdp:ModelName>%s</wsdp:ModelName>"
		"<wsdp:ModelNumber>1</wsdp:ModelNumber>"
		"<wsdp:ModelUrl>%s</wsdp:ModelUrl>"
		"<wsdp:PresentationUrl>%s</wsdp:PresentationUrl>"
		"<un0:DeviceCategory>Computers</un0:DeviceCategory>"
		"</wsdp:ThisModel>"
		"</wsx:MetadataSection>"
		"<wsx:MetadataSection Dialect=\""
		"http://schemas.xmlsoap.org/ws/2006/02/devprof/Relationship\">"
		"<wsdp:Relationship Type=\""
		"http://schemas.xmlsoap.org/ws/2006/02/devprof/host\">"
		"<wsdp:Host>"
		"<wsa:EndpointReference>"
		"<wsa:Address>urn:uuid:%s</wsa:Address>"
		"</wsa:EndpointReference>"
		"<wsdp:Types>pub:Computer</wsdp:Types>"
		"<wsdp:ServiceId>urn:uuid:%s</wsdp:ServiceId>"
		"<pub:Computer>%s/Workgroup:%s</pub:Computer>"
		"</wsdp:Host>"
		"</wsdp:Relationship>"
		"</wsx:MetadataSection>"
		"</wsx:Metadata>"
		"</soap:Body>";

	body = talloc_asprintf(mem_ctx, body_templ,
				wsdd->devinfo->friendly_name,
				wsdd->devinfo->firmware,
				wsdd->devinfo->serial,
				wsdd->devinfo->manufacturer,
				wsdd->devinfo->url,
				wsdd->devinfo->model,
				wsdd->devinfo->url,
				wsdd->devinfo->url,
				wsdd->endpoint,
				wsdd->endpoint,
				wsdd->devinfo->name,
				wsdd->devinfo->workgroup);
	if (!body) {
		return data_blob_null;
	}

	out = wsd_generate_soap_msg(mem_ctx, wsdd->instance_id, wsdd->sequence,
				    &wsdd->msg_no, WSD_TO_ANONYMOUS,
				    WXT_ACT_GETRESPONSE, req_info->msgid, body);
	TALLOC_FREE(body);

	return out;
}

