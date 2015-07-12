/*
   Unix SMB/CIFS implementation.

   XML namespace parse helper functions (header)

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
#ifndef XMLNS_H
#define XMLNS_H

#include <string.h>
#include <stdbool.h>

struct xmlns_qname {
	char *namespace;
	char *localname;
};

struct xmlns_uri {
	struct xmlns_uri *next;
	char *scope;
	char *uri;
};

struct xmlns_entry {
	struct xmlns_entry *prev, *next;
	char *prefix;
	struct xmlns_uri *uri_stack;
};

struct xmlns_table {
	size_t n_entries;
	struct xmlns_entry *entries;
	size_t scope_bufsize;
	char *scope;
};

struct xmlns_table *xmlns_init_resolver(TALLOC_CTX *);
void xmlns_add_prefix(struct xmlns_table *, const char *, const char *);
void xmlns_push_scope(struct xmlns_table *, const char *);
void xmlns_pop_scope(struct xmlns_table *);
struct xmlns_qname *xmlns_resolve_tag(TALLOC_CTX *, struct xmlns_table *,
				      const char *);
bool xmlns_qname_equals(const struct xmlns_qname *, const struct xmlns_qname *);
bool xmlns_qname_in_scope(struct xmlns_table *, const struct xmlns_qname *);

inline int xmlns_index_last_elem(struct xmlns_table *table)
{
	int i;

	for (i=strlen(table->scope); i>0; i--) {
		if ((table->scope)[i] == '/') {
			break;
		}
	}

	return i;
}

inline const char *xmlns_current_elem(struct xmlns_table *table)
{
	return (const char *)(table->scope + xmlns_index_last_elem(table) + 1);
}

inline struct xmlns_qname *xmlns_qname_current_elem(TALLOC_CTX *mem_ctx,
						    struct xmlns_table *table)
{
	return xmlns_resolve_tag(mem_ctx, table, xmlns_current_elem(table));
}

inline char *xmlns_qname_to_string(char *dest, size_t size, struct xmlns_qname *qn)
{
	memset(dest, 0, size);
	if (qn) {
		snprintf(dest, size, "{%s}%s",qn->namespace,qn->localname);
	} else {
		snprintf(dest, size, "<not resolved>");
	}
    return dest;
}

#endif

