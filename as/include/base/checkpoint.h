/*
 * checkpoint.h
 *
 * Copyright (C) 2024 Kioxia Corporation.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum checkpoint {
	prefetch_begin = 1,
	prefetch_end,
	io_submit_begin,
	io_submit_end,
	index_search_compare_begin, // as_index_sprig_search_lockless
	index_search_compare_end,
	index_insert_compare_begin, // as_index_sprig_get_insert_vlock
	index_insert_compare_end,
	prefetch_yield_begin,
	prefetch_yield_end,
	service_yield_begin,
	service_yield_end,
	io_yield_begin,
	io_yield_end,
	benchmark_begin,
	benchmark_end,
	checkpoint_max,
};

struct checkpoint_trace {
	uint64_t capacity;
	uint64_t len;
	struct {
		uint64_t id;
		uint64_t checkpoint;
		uint64_t timestamp;
	} buffer[];
};

void checkpoint_trace_init(void);

void checkpoint_trace_dump(FILE *stream);
void checkpoint_trace_reset(void);

#ifdef USE_CHECKPOINT
#undef USE_CHECKPOINT_REDUCED
void do_record_checkpoint(enum checkpoint checkpoint);
static inline void record_checkpoint(enum checkpoint checkpoint)
{
#ifdef USE_CHECKPOINT_REDUCED
	if (checkpoint < prefetch_yield_begin)
		return;
#endif
	return do_record_checkpoint(checkpoint);
}
#else
static inline void record_checkpoint(enum checkpoint checkpoint)
{
}
#endif
