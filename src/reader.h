/*
  Copyright 2011-2017 David Robillard <http://drobilla.net>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THIS SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef SERD_READER_H
#define SERD_READER_H

#include "byte_source.h"
#include "node.h"
#include "stack.h"

#include "serd/serd.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef SERD_STACK_CHECK
#    define SERD_STACK_ASSERT_TOP(reader, ref) \
            assert(ref == reader->allocs[reader->n_allocs - 1]);
#else
#    define SERD_STACK_ASSERT_TOP(reader, ref)
#endif

#if defined(__GNUC__)
#    define SERD_LOG_FUNC(fmt, arg1) __attribute__((format(printf, fmt, arg1)))
#else
#    define SERD_LOG_FUNC(fmt, arg1)
#endif

typedef struct {
	SerdNode*           graph;
	SerdNode*           subject;
	SerdNode*           predicate;
	SerdNode*           object;
	SerdStatementFlags* flags;
} ReadContext;

struct SerdReaderImpl {
	SerdWorld*               world;
	const SerdSink*          sink;
	SerdLogFunc              log_func;
	void*                    error_handle;
	SerdNode*                rdf_first;
	SerdNode*                rdf_rest;
	SerdNode*                rdf_nil;
	SerdByteSource           source;
	SerdStack                stack;
	SerdSyntax               syntax;
	unsigned                 next_id;
	SerdStatus               status;
	uint8_t*                 buf;
	char*                    bprefix;
	size_t                   bprefix_len;
	bool                     strict; ///< True iff strict parsing
	bool                     seen_genid;
#ifdef SERD_STACK_CHECK
	SerdNode**               allocs; ///< Stack of push offsets
	size_t                   n_allocs; ///< Number of stack pushes
#endif
};

SERD_LOG_FUNC(3, 4)
SerdStatus r_err(SerdReader* reader, SerdStatus st, const char* fmt, ...);

SerdNode* push_node_padded(SerdReader*  reader,
                           size_t       maxlen,
                           SerdNodeType type,
                           const char*  str,
                           size_t       n_bytes);

SerdNode* push_node(SerdReader*  reader,
                    SerdNodeType type,
                    const char*  str,
                    size_t       n_bytes);

size_t    genid_size(SerdReader* reader);
SerdNode* blank_id(SerdReader* reader);
void      set_blank_id(SerdReader* reader, SerdNode* node, size_t buf_size);

SerdStatus emit_statement(SerdReader* reader, ReadContext ctx, SerdNode* o);

SerdStatus read_n3_statement(SerdReader* reader);
SerdStatus read_nquadsDoc(SerdReader* reader);
SerdStatus read_turtleTrigDoc(SerdReader* reader);

static inline uint8_t
peek_byte(SerdReader* reader)
{
	return serd_byte_source_peek(&reader->source);
}

static inline uint8_t
eat_byte(SerdReader* reader)
{
	const uint8_t    c  = peek_byte(reader);
	const SerdStatus st = serd_byte_source_advance(&reader->source);
	if (st) {
		reader->status = st;
	}
	return c;
}

static inline uint8_t
eat_byte_safe(SerdReader* reader, const uint8_t byte)
{
	(void)byte;

	const uint8_t c = eat_byte(reader);
	assert(c == byte);
	return c;
}

static inline uint8_t
eat_byte_check(SerdReader* reader, const uint8_t byte)
{
	const uint8_t c = peek_byte(reader);
	if (c != byte) {
		r_err(reader, SERD_ERR_BAD_SYNTAX,
		      "expected `%c', not `%c'\n", byte, c);
		return 0;
	}
	return eat_byte_safe(reader, byte);
}

static inline SerdStatus
eat_string(SerdReader* reader, const char* str, unsigned n)
{
	for (unsigned i = 0; i < n; ++i) {
		if (!eat_byte_check(reader, ((const uint8_t*)str)[i])) {
			return SERD_ERR_BAD_SYNTAX;
		}
	}
	return SERD_SUCCESS;
}

static inline SerdStatus
push_byte(SerdReader* reader, SerdNode* node, const uint8_t c)
{
	SERD_STACK_ASSERT_TOP(reader, node);
	uint8_t* const s = (uint8_t*)serd_stack_push(&reader->stack, 1);

	if (s) {
		++node->n_bytes;
		*(s - 1) = c;
		*s       = '\0';
	}

	return s ? SERD_SUCCESS : SERD_ERR_OVERFLOW;
}

static inline SerdStatus
push_bytes(SerdReader*    reader,
           SerdNode*      ref,
           const uint8_t* bytes,
           unsigned       len)
{
	const bool has_space = reader->stack.buf_size >= reader->stack.size + len;
	if (has_space) {
		for (unsigned i = 0; i < len; ++i) {
			push_byte(reader, ref, bytes[i]);
		}
	}
	return has_space ? SERD_SUCCESS : SERD_ERR_OVERFLOW;
}

#endif // SERD_READER_H
