/*
 * arenax.h
 *
 * Copyright (C) 2012-2020 Aerospike, Inc.
 * Copyright (C) 2024 Kioxia Corporation.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#pragma once

//==========================================================
// Includes.
//

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "cf_mutex.h"
#include "log.h"
#include "xmem.h"


//==========================================================
// Typedefs & constants.
//

#ifndef CF_ARENAX_MAX_STAGES
#define CF_ARENAX_MAX_STAGES 256
#endif

#define CF_ARENAX_MIN_STAGE_SIZE (128L * 1024L * 1024L) // 128M

#ifndef CF_ARENAX_MAX_STAGE_SIZE
#define CF_ARENAX_MAX_STAGE_SIZE (1024L * 1024L * 1024L) // 1G
#endif

typedef uint64_t cf_arenax_handle;

// Must be in-sync with internal array ARENAX_ERR_STRINGS[]:
typedef enum {
	CF_ARENAX_OK = 0,
	CF_ARENAX_ERR_BAD_PARAM,
	CF_ARENAX_ERR_STAGE_CREATE,
	CF_ARENAX_ERR_STAGE_ATTACH,
	CF_ARENAX_ERR_STAGE_DETACH,
	CF_ARENAX_ERR_UNKNOWN
} cf_arenax_err;

//------------------------------------------------
// For enterprise separation only.
//

// Element is indexed by 28 bits.
#define ELEMENT_ID_NUM_BITS 28
#define ELEMENT_ID_MASK ((1UL << ELEMENT_ID_NUM_BITS) - 1) // 0xFFFffff

typedef struct cf_arenax_chunk_s {
	uint64_t base_h: 40;
} __attribute__((packed)) cf_arenax_chunk;

// DO NOT access this member data directly - use the API!
// Caution - changing this struct could break warm or cool restart.
typedef struct cf_arenax_s {
	// Configuration (passed in constructors).
	cf_xmem_type		xmem_type;
	const void*			xmem_type_cfg;
	key_t				key_base;
	uint32_t			element_size;
	uint32_t			stage_capacity; // derived
	uint32_t			unused_1;
	uint32_t			unused_2;
	size_t				stage_size;

	// Free-element list (non-chunked allocations).
	cf_arenax_handle	free_h;

	// Where to end-allocate.
	uint32_t			at_stage_id;
	uint32_t			at_element_id;

	// Thread safety.
	cf_mutex			lock;

	// Pad to maintain warm restart compatibility (lock was pthread mutex).
	uint8_t				pad[36];

	// Current stages.
	uint32_t			stage_count;
	uint8_t*			stages[CF_ARENAX_MAX_STAGES];

	// Flash index related members at end to avoid full warm restart converter.

	uint32_t			chunk_count; // is 1 for non-flash indexes
	uint64_t			alloc_sz; // stats only - size of all allocated chunks

	// Arena pool (free chunked allocations).
	size_t				pool_len;
	cf_arenax_chunk*	pool_buf;
	size_t				pool_i;
} cf_arenax;

COMPILER_ASSERT(sizeof(cf_arenax) == 152 + (8 * CF_ARENAX_MAX_STAGES));

typedef struct free_element_s {
	uint32_t			magic;
	uint8_t				pad[52]; // so next_h overwrites least critical member
	cf_arenax_handle	next_h;
} free_element;

#define FREE_MAGIC 0xff1234ff

typedef struct cf_arenax_puddle_s {
	uint64_t free_h: 40;
} __attribute__((packed)) cf_arenax_puddle;


//==========================================================
// Public API.
//

const char* cf_arenax_errstr(cf_arenax_err err);

void cf_arenax_init(cf_arenax* arena, cf_xmem_type xmem_type,
		const void* xmem_type_cfg, key_t key_base, uint32_t element_size,
		uint32_t chunk_count, size_t stage_size);

cf_arenax_handle cf_arenax_alloc(cf_arenax* arena, cf_arenax_puddle* puddle);
void cf_arenax_free(cf_arenax* arena, cf_arenax_handle h, cf_arenax_puddle* puddle);

bool cf_arenax_is_stage_address(cf_arenax* arena, const void* address);
void cf_arenax_access(const cf_arenax* arena, const void* address);

bool cf_arenax_want_prefetch(cf_arenax* arena);
void cf_arenax_reclaim(cf_arenax* arena, cf_arenax_puddle* puddles, uint32_t n_puddles);

// Convert cf_arenax_handle to memory address.
static inline void*
cf_arenax_resolve(const cf_arenax* arena, cf_arenax_handle h)
{
	void *address = arena->stages[h >> ELEMENT_ID_NUM_BITS] +
			((h & ELEMENT_ID_MASK) * arena->element_size);
	cf_arenax_access(arena, address);
	return address;
}


//==========================================================
// Private API - for enterprise separation only.
//

static inline void
cf_arenax_set_handle(cf_arenax_handle* h, uint32_t stage_id,
		uint32_t element_id)
{
	*h = ((uint64_t)stage_id << ELEMENT_ID_NUM_BITS) | element_id;
}

static inline void
cf_arenax_expand_handle(uint32_t* stage_id, uint32_t* element_id,
		cf_arenax_handle h)
{
	*stage_id = h >> ELEMENT_ID_NUM_BITS;
	*element_id = h & ELEMENT_ID_MASK;
}

cf_arenax_err cf_arenax_add_stage(cf_arenax* arena);

cf_arenax_handle cf_arenax_alloc_chunked(cf_arenax* arena, cf_arenax_puddle* puddle);
void cf_arenax_free_chunked(cf_arenax* arena, cf_arenax_handle h, cf_arenax_puddle* puddle);

struct pi_xlmem_cfg {
	uint64_t size_limit;
	void *mem;
	uint32_t latency_ns;
};
