/*
 * drv_common.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include "storage/drv_common.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#ifdef USE_ARGOBOTS
#include <liburing.h>
#include "abt.h"
#endif

#include "base/checkpoint.h"
#include "base/datamodel.h"
#include "base/index.h"
#include "storage/flat.h"


//==========================================================
// Public API - shared code between storage engines.
//

bool
drv_is_set_evictable(const as_namespace* ns, const as_flat_opt_meta* opt_meta)
{
	if (! opt_meta->set_name) {
		return true;
	}

	as_set *p_set;

	if (cf_vmapx_get_by_name_w_len(ns->p_sets_vmap, opt_meta->set_name,
			opt_meta->set_name_len, (void**)&p_set) != CF_VMAPX_OK) {
		return true;
	}

	return ! p_set->eviction_disabled;
}

void
drv_apply_opt_meta(as_record* r, as_namespace* ns,
		const as_flat_opt_meta* opt_meta)
{
	// Set record's set-id. (If it already has one, assume they're the same.)
	if (as_index_get_set_id(r) == INVALID_SET_ID && opt_meta->set_name) {
		as_index_set_set_w_len(r, ns, opt_meta->set_name,
				opt_meta->set_name_len, false);
	}

	// Store or drop the key according to the props we read.
	as_record_finalize_key(r, ns, opt_meta->key, opt_meta->key_size);
}

#ifdef USE_ARGOBOTS

static __thread struct io_uring *ring;

static struct io_uring *alloc_ring(void)
{
	struct io_uring *ring;
	int ret;

	ring = cf_malloc(sizeof(*ring));
	if (!ring) {
		return NULL;
	}

	ret = io_uring_queue_init(g_config.n_io_uring_setup_entries, ring,
			g_config.io_uring_setup_iopoll ? IORING_SETUP_IOPOLL : 0);
	if (ret) {
		cf_free(ring);
		return NULL;
	}

	return ring;
}

struct io_data {
	bool read;
	int fd;
	void *buf;
	size_t size;
	off_t offset;
	int error;
};

static bool
prw_all(bool read, int fd, void* buf, size_t size, off_t offset)
{
	struct io_uring_sqe *sqe;
	struct io_data data = {
		.read = read,
		.fd = fd,
		.buf = buf,
		.size = size,
		.offset = offset,
	};

	if (!ring) {
		ring = alloc_ring();
		cf_assert(ring, AS_DRV_SSD, "unable to allocate io_uring queue");
	}

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		cf_crash(AS_DRV_SSD, "no sqe available");
		return false;
	}

	if (data.read)
		io_uring_prep_read(sqe, data.fd, data.buf, data.size, data.offset);
	else
		io_uring_prep_write(sqe, data.fd, data.buf, data.size, data.offset);

	io_uring_sqe_set_data(sqe, &data);
	record_checkpoint(io_submit_begin);
	io_uring_submit(ring);
	record_checkpoint(io_submit_end);

	do {
		struct io_uring_cqe *cqe;
		int ret;

		ret = io_uring_peek_cqe(ring, &cqe);
		if (ret == -EAGAIN) {
			ABT_thread self;

			record_checkpoint(io_yield_begin);
			if (ABT_thread_self(&self) == ABT_SUCCESS) {
				ABT_thread_yield();
			}
			record_checkpoint(io_yield_end);
		} else if (ret < 0) {
			cf_crash(AS_DRV_SSD, "io_uring_peek_cqe returns unexpected error");
			return false;
		} else {
			struct io_data *data = io_uring_cqe_get_data(cqe);

			if (cqe->res < 0) {
				cf_crash(AS_DRV_SSD, "read/write returns error");
				data->error = cqe->res;
				io_uring_cqe_seen(ring, cqe);
			} else {
				cf_assert(data->size >= cqe->res, AS_DRV_SSD, "read/write returned too large value");
				data->buf += cqe->res;
				data->size -= cqe->res;
				data->offset += cqe->res;
				/* Short read/write */
				if (data->size > 0) {
					sqe = io_uring_get_sqe(ring);
					cf_assert(sqe, AS_DRV_SSD, "no sqe available on short read/write");

					if (data->read)
						io_uring_prep_read(sqe, data->fd, data->buf, data->size, data->offset);
					else
						io_uring_prep_write(sqe, data->fd, data->buf, data->size, data->offset);

					io_uring_sqe_set_data(sqe, data);
					io_uring_submit(ring);
					io_uring_cqe_seen(ring, cqe);
				} else {
					io_uring_cqe_seen(ring, cqe);
				}
			}
		}
	} while (!data.error && (data.size > 0));

	return data.error ? false : true;
}

bool
pread_all(int fd, void* buf, size_t size, off_t offset)
{
	return prw_all(true, fd, buf, size, offset);
}

bool
pwrite_all(int fd, const void* buf, size_t size, off_t offset)
{
	return prw_all(false, fd, (void *)buf, size, offset);
}

#else

bool
pread_all(int fd, void* buf, size_t size, off_t offset)
{
	ssize_t result;

	while ((result = pread(fd, buf, size, offset)) != (ssize_t)size) {
		if (result < 0) {
			return false; // let the caller log errors
		}

		if (result == 0) { // should only happen if caller passed 0 size
			errno = EINVAL;
			return false;
		}

		buf += result;
		offset += result;
		size -= result;
	}

	return true;
}

bool
pwrite_all(int fd, const void* buf, size_t size, off_t offset)
{
	ssize_t result;

	while ((result = pwrite(fd, buf, size, offset)) != (ssize_t)size) {
		if (result < 0) {
			return false; // let the caller log errors
		}

		if (result == 0) { // should only happen if caller passed 0 size
			errno = EINVAL;
			return false;
		}

		buf += result;
		offset += result;
		size -= result;
	}

	return true;
}

#endif
