/*
  Copyright 2011-2018 David Robillard <http://drobilla.net>

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

#ifndef SERD_BYTE_SOURCE_H
#define SERD_BYTE_SOURCE_H

#include "cursor.h"

#include "serd/serd.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int (*SerdStreamCloseFunc)(void*);

typedef struct {
	SerdReadFunc        read_func;    ///< Read function (e.g. fread)
	SerdStreamErrorFunc error_func;   ///< Error function (e.g. ferror)
	SerdStreamCloseFunc close_func;   ///< Function for closing stream
	void*               stream;       ///< Stream (e.g. FILE)
	size_t              page_size;    ///< Number of bytes to read at a time
	SerdNode*           name;         ///< Name of stream (referenced by cur)
	SerdCursor          cur;          ///< Cursor for error reporting
	uint8_t*            file_buf;     ///< Buffer iff reading pages from a file
	const uint8_t*      read_buf;     ///< Pointer to file_buf or read_byte
	size_t              read_head;    ///< Offset into read_buf
	uint8_t             read_byte;    ///< 1-byte 'buffer' used when not paging
	bool                from_stream;  ///< True iff reading from `stream`
	bool                prepared;     ///< True iff prepared for reading
	bool                eof;          ///< True iff end of file reached
} SerdByteSource;

SerdStatus
serd_byte_source_open_string(SerdByteSource* source,
                             const char*     utf8,
                             const SerdNode* name);

SerdStatus
serd_byte_source_open_source(SerdByteSource*     source,
                             SerdReadFunc        read_func,
                             SerdStreamErrorFunc error_func,
                             SerdStreamCloseFunc close_func,
                             void*               stream,
                             const SerdNode*     name,
                             size_t              page_size);

SerdStatus
serd_byte_source_close(SerdByteSource* source);

SerdStatus
serd_byte_source_prepare(SerdByteSource* source);

SerdStatus
serd_byte_source_page(SerdByteSource* source);

static inline uint8_t
serd_byte_source_peek(SerdByteSource* source)
{
	assert(source->prepared);
	return source->read_buf[source->read_head];
}

static inline SerdStatus
serd_byte_source_advance(SerdByteSource* source)
{
	SerdStatus st = SERD_SUCCESS;

	switch (serd_byte_source_peek(source)) {
	case '\0': break;
	case '\n': ++source->cur.line; source->cur.col = 0; break;
	default:   ++source->cur.col;
	}

	if (source->from_stream) {
		if (source->page_size > 1) {
			if (++source->read_head == source->page_size) {
				st = serd_byte_source_page(source);
			}
		} else {
			source->eof = false;
			if (!source->read_func(&source->read_byte, 1, 1, source->stream)) {
				source->eof = true;
				st = source->error_func(source->stream) ? SERD_ERR_UNKNOWN
				                                        : SERD_FAILURE;
			}
		}
	} else if (!source->eof) {
		++source->read_head; // Move to next character in string
	}

	return st ? st : source->eof ? SERD_FAILURE : SERD_SUCCESS;
}

#endif  // SERD_BYTE_SOURCE_H
