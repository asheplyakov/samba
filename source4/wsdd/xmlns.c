/*
   Unix SMB/CIFS implementation.

   XML namespace parse helper functions

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
#include <string.h>
#include <talloc.h>

#include "xmlns.h"
#include "includes.h"

/* set new debug class */
#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_WSDD

#define FIND_PREFIX_ENTRY( list, prefix ) \
	while(list) { \
		if (!list->prefix || !prefix) { \
			if (list->prefix == prefix) break; \
		} else { \
			if (strcmp(list->prefix, prefix) == 0) break; \
		} \
		list = list->next; \
	}

struct xmlns_table *xmlns_init_resolver(TALLOC_CTX *mem_ctx)
{
	struct xmlns_table *table;
	
	table = talloc(mem_ctx, struct xmlns_table);
	if (table) {
		table->entries = NULL;
		table->n_entries = 0;
		table->scope_bufsize = 16*1024; /* initial buffer size 16K */
		table->scope = talloc_zero_size(table, table->scope_bufsize);
	}

	return table;
}

void xmlns_push_scope(struct xmlns_table *table, const char* tag)
{
	size_t scope_len = strlen(table->scope);
	size_t taglen = strlen(tag);

	if (scope_len+taglen+2 > table->scope_bufsize) {
		table->scope_bufsize = scope_len + taglen + 2;
		table->scope = talloc_realloc(table, table->scope, char, 
					      table->scope_bufsize);
	}

	table->scope[scope_len++] = '/';
	strncpy(table->scope+scope_len, tag, taglen);
	table->scope[scope_len+taglen] = '\0';

	return;
}

void xmlns_add_prefix(struct xmlns_table *table, const char *prefix,
				const char *uri)
{
	struct xmlns_entry *entry = table->entries;
	struct xmlns_uri *uri_scope;

	/* try to find entry with prefix */
	FIND_PREFIX_ENTRY(entry, prefix);

	/* entry not found so create a new one and insert into table */
	if (!entry) {
		entry = talloc_zero(table, struct xmlns_entry);
		entry->prefix = talloc_strdup(entry, prefix);
		entry->next = table->entries;
		table->entries = entry;
		table->n_entries++;
	}

	/* push xmlns scope into entry */
	uri_scope = talloc_zero(entry, struct xmlns_uri);
	uri_scope->scope = talloc_strdup(uri_scope, table->scope);
	uri_scope->uri = talloc_strdup(uri_scope, uri);
	uri_scope->next = entry->uri_stack;
	entry->uri_stack = uri_scope;

	return;
}

void xmlns_pop_scope(struct xmlns_table *table)
{
	struct xmlns_entry *entry, *next_entry;
	struct xmlns_uri *pop;

	if (table->n_entries == 0) {
		return;
	}
	
	/* clean up entries before popping current scope */
	entry = table->entries;
	while(entry) {
		/* save next entry before anything else */
		next_entry = entry->next;

		/* get scope to pop */
		pop = entry->uri_stack;

		/* is it the popped scope matching current scope? */
		if (strcmp(pop->scope, table->scope) == 0) {
			if (pop->next == NULL) {
				/* 
				 * remove whole entry from xmlns 
				 * resolver table
				 */
				if (entry->prev) {
					entry->prev->next = entry->next;
				}
				if (entry->next) {
					entry->next->prev = entry->prev;
				}
				if (table->entries == entry) {
					table->entries = entry->next;
				}
				table->n_entries--;
				TALLOC_FREE(entry);
			} else {
				/* pop current scope from entry */
				entry->uri_stack = pop->next;
				TALLOC_FREE(pop);
			}
		}

		/* loop over next entry */
		entry = next_entry;
	}

	/* remove last scope */
	(table->scope)[xmlns_index_last_elem(table)] = '\0';

	return;
}

static const char *xmlns_search_namespace(struct xmlns_table *table,
					const char *prefix)
{
	struct xmlns_entry *entry;
	const char *uri;

	if (table == NULL || table->entries == NULL) {
		return NULL;
	}

	entry = table->entries;
	FIND_PREFIX_ENTRY(entry, prefix);

	if (entry && entry->uri_stack && entry->uri_stack->uri) {
		uri = entry->uri_stack->uri;
	} else {
		uri = NULL;
	}

	return uri;
}

static void xmlns_resolve_tag_internal(struct xmlns_qname *qname,
				struct xmlns_table *table, const char *tag)
{
	char prefix[4*1024], *semicolon;

	if (!qname) {
		return;
	}

	semicolon = strstr(tag, ":");
	if (semicolon) {
		memset(prefix, 0, sizeof(prefix));
		strncpy(prefix, tag, semicolon-tag);
		qname->namespace = 
			(char *)xmlns_search_namespace(table, prefix);
	} else {
		qname->namespace = (char *)xmlns_search_namespace(table, NULL);
	}

	if (qname->namespace) {
		if (semicolon) {
			qname->localname = semicolon + 1;
		} else {
			qname->localname = (char *)tag;
		}
	} else {
		/* prefix can't be resolved to any URI => error, returns NULL */
		qname->namespace = NULL;
		qname->localname = NULL;
	}

	return;
}

struct xmlns_qname *xmlns_resolve_tag(TALLOC_CTX *mem_ctx,
				struct xmlns_table *table, const char *tag) 
{
	struct xmlns_qname *qname;

	qname = talloc(mem_ctx, struct xmlns_qname);
	if (!qname) {
		return NULL;
	}

	xmlns_resolve_tag_internal(qname, table, tag);
	if (!qname->namespace && !qname->localname) {
		/* tag can't be resolved */
		TALLOC_FREE(qname);
	} else {
		/* convert to talloc */
		qname->namespace = talloc_strdup(qname, qname->namespace);
		qname->localname = talloc_strdup(qname, qname->localname);
	}

	return qname;
}

bool xmlns_qname_equals(const struct xmlns_qname *qname1,
				const struct xmlns_qname *qname2)
{
	bool equals;

	if (qname1 == qname2) {
		return true;
	}

	if ((!qname1 && qname2) || (qname1 && !qname2)) {
		return false;
	}

	if (qname1->namespace == qname2->namespace &&
	    qname1->localname == qname2->localname)
	{
		return true;
	}

	if ((!qname1->namespace && qname2->namespace) || 
	    (qname1->namespace && !qname2->namespace))
	{
		return false;
	}

	if ((!qname1->localname && qname2->localname) ||
	    (qname1->localname && !qname2->localname))
	{
		return false;
	}

	equals = (strcmp(qname1->namespace, qname2->namespace) == 0 && 
		  strcasecmp(qname1->localname, qname2->localname) == 0);
	return equals;
}

extern inline int xmlns_index_last_elem(struct xmlns_table *table);
extern inline const char *xmlns_current_elem(struct xmlns_table *table);
extern inline struct xmlns_qname *xmlns_qname_current_elem(TALLOC_CTX *mem_ctx,
				struct xmlns_table *table);

bool xmlns_qname_in_scope(struct xmlns_table *table,
				const struct xmlns_qname *qname)
{
	char *p1 = table->scope, *p2, tag[4*1024];
	struct xmlns_qname qn1;

	do {
		p1 = strstr(p1, "/");
		p2 = strstr(p1+1, "/");
		if (p2) {
			strncpy(tag, p1+1, p2-p1-1);
			tag[p2-p1-1] = '\0';
		} else {
			strncpy(tag, xmlns_current_elem(table), sizeof(tag));
		}

		xmlns_resolve_tag_internal(&qn1, table, tag);
		if (xmlns_qname_equals(&qn1, qname)) {
			return true;
		}

		p1 = p2;
	} while(p1);

	return false;
}	

extern inline char *xmlns_qname_to_string(char *dest, size_t size,
			struct xmlns_qname *qn);
