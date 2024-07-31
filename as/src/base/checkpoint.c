/*
 * checkpoint.c
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
 
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_queue.h"

#include "base/cfg.h"
#include "base/checkpoint.h"

#ifdef USE_ARGOBOTS
#include "abt.h"
#endif

// copied from liburing/src/include/liburing/barrier.h

#include <stdatomic.h>

#define WRITE_ONCE(var, val)						\
	atomic_store_explicit((_Atomic __typeof__(var) *)&(var),	\
				(val), memory_order_relaxed)
#define READ_ONCE(var)							\
	atomic_load_explicit((_Atomic __typeof__(var) *)&(var),		\
				memory_order_relaxed)

#define smp_store_release(p, v)						\
	atomic_store_explicit((_Atomic __typeof__(*(p)) *)(p), (v),	\
				memory_order_release)
#define smp_load_acquire(p)						\
	atomic_load_explicit((_Atomic __typeof__(*(p)) *)(p),		\
				memory_order_acquire)

static cf_queue *checkpoint_trace_list;

void checkpoint_trace_init(void)
{
	cf_assert(checkpoint_trace_list == NULL, AS_SERVICE, "checkpoint_trace_list is initialized twice");
	checkpoint_trace_list = cf_queue_create(sizeof(struct checkpoint_trace *), true);
}

static const char *checkpoint_to_name[] = {
	[prefetch_begin] = "prefetch",
	[prefetch_end] = "prefetch",
	[prefetch_yield_begin] = "prefetch_yield",
	[prefetch_yield_end] = "prefetch_yield",
	[service_yield_begin] = "service_yield",
	[service_yield_end] = "service_yield",
	[io_submit_begin] = "io_submit",
	[io_submit_end] =  "io_submit",
	[io_yield_begin] =  "io_yield",
	[io_yield_end] = "io_yield",
	[index_search_compare_begin] = "index_search_compare",
	[index_search_compare_end] = "index_search_compare",
	[index_insert_compare_begin] = "index_insert_compare",
	[index_insert_compare_end] = "index_insert_compare",
	[benchmark_begin] = "benchmark",
	[benchmark_end] = "benchmark",
};

struct dump_data {
	bool empty;
	FILE *stream;
};

static int dump(void *buf, void *udata)
{
	struct checkpoint_trace *trace = *(struct checkpoint_trace **)buf;
	struct dump_data *data = udata;

	uint64_t len = smp_load_acquire(&trace->len);

	for (int i = 0; i < len; i++) {
		uint64_t checkpoint = trace->buffer[i].checkpoint;

		cf_assert(checkpoint != 0 && checkpoint < checkpoint_max, AS_SERVICE,
				"invalid checkpoint code %ld", checkpoint);

		if (i == 0 && !data->empty) {
			fprintf(data->stream, ",\n");
		}
		data->empty = false;

		fprintf(data->stream, "  {\n");
		fprintf(data->stream, "    \"name\" : \"%s\",\n", checkpoint_to_name[checkpoint]);
		fprintf(data->stream, "    \"ph\" : \"%s\",\n", (checkpoint % 2) ? "B" : "E");
		fprintf(data->stream, "    \"pid\" : %lld,\n", (unsigned long long)trace);
		fprintf(data->stream, "    \"tid\" : %ld,\n", trace->buffer[i].id);
		fprintf(data->stream, "    \"ts\" : %ld\n", trace->buffer[i].timestamp);
		fprintf(data->stream, "  }");

		if (i < len - 1) {
			fprintf(data->stream, ",\n");
		}
	}

	return 0;
}

void checkpoint_trace_dump(FILE *stream)
{
	struct dump_data dump_data = {
		.empty = true,
		.stream = stream,
	};

	fprintf(stream, "[\n");
	cf_queue_reduce(checkpoint_trace_list, dump, &dump_data);
	fprintf(stream, "\n]\n");
}

static int reset(void *buf, void *udata)
{
	struct checkpoint_trace *trace = *(struct checkpoint_trace **)buf;

	WRITE_ONCE(trace->len, 0);

	return 0;
}

void checkpoint_trace_reset(void)
{
	cf_queue_reduce(checkpoint_trace_list, reset, NULL);
}

#ifdef USE_CHECKPOINT

static __thread struct checkpoint_trace *trace;

#undef USE_CHECKPOINT_BENCHMARK

void do_record_checkpoint(enum checkpoint checkpoint)
{
#ifdef USE_CHECKPOINT_BENCHMARK
	int toggle = 0;
benchmark:
	checkpoint = benchmark_begin + toggle;
#endif
	if (!trace) {
		trace = cf_malloc(sizeof(*trace) + sizeof(trace->buffer[0]) * g_config.checkpoint_capacity);
		trace->capacity = g_config.checkpoint_capacity;
		WRITE_ONCE(trace->len, 0);
		memset(trace->buffer, 0, sizeof(trace->buffer[0]) * trace->capacity);
		cf_assert(checkpoint_trace_list != NULL, AS_SERVICE, "checkpoint_trace_list is not yet initialized");
		cf_queue_push(checkpoint_trace_list, &trace);
	}

	uint64_t len = smp_load_acquire(&trace->len);

	if (len < trace->capacity) {
#ifdef USE_ARGOBOTS
		ABT_unit_id id;

		if (ABT_thread_self_id(&id) == ABT_SUCCESS) {
			trace->buffer[len].id = (uint64_t)id;
		} else {
			trace->buffer[len].id = 0;
		}
#endif
		trace->buffer[len].checkpoint = checkpoint;
		trace->buffer[len].timestamp = cf_getns();
		smp_store_release(&trace->len, len + 1);
	}
#ifdef USE_CHECKPOINT_BENCHMARK
	if (len < trace->capacity) {
		toggle ^= 1;
		goto benchmark;
	}
#endif
}

#endif
