/*
 * service.c
 *
 * Copyright (C) 2018-2020 Aerospike, Inc.
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

#include "base/service.h"

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <zlib.h>

#include "aerospike/as_atomic.h"
#include "citrusleaf/alloc.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_queue.h"

#include "cf_mutex.h"
#include "cf_thread.h"
#include "epoll_queue.h"
#include "hardware.h"
#include "log.h"
#include "socket.h"
#include "tls.h"

#include "base/batch.h"
#include "base/cfg.h"
#include "base/checkpoint.h"
#include "base/datamodel.h"
#include "base/proto.h"
#include "base/security.h"
#include "base/stats.h"
#include "base/thr_info.h"
#include "base/thr_tsvc.h"
#include "base/transaction.h"
#include "fabric/partition.h"

#ifdef USE_ARGOBOTS
#include "storage/drv_ssd.h"
#include "aerospike/as_monitor.h"
#include "abt.h"
#endif

#include "warnings.h"


//==========================================================
// Typedefs & constants.
//

#define N_EVENTS 1024

#define XDR_WRITE_BUFFER_SIZE (5 * 1024 * 1024)
#define XDR_READ_BUFFER_SIZE (15 * 1024 * 1024)

typedef struct thread_ctx_s {
	cf_topo_cpu_index i_cpu;
	cf_mutex* lock;
	cf_poll poll;
	cf_epoll_queue trans_q;
	uint32_t sid;
	uint64_t n_busy_polling;
} thread_ctx __attribute__((__aligned__(64)));


//==========================================================
// Globals.
//

as_service_access g_access = {
	.service = { .addrs = { .n_addrs = 0 }, .port = 0 },
	.alt_service = { .addrs = { .n_addrs = 0 }, .port = 0 },
	.tls_service = { .addrs = { .n_addrs = 0 }, .port = 0 },
	.alt_tls_service = { .addrs = { .n_addrs = 0 }, .port = 0 }
};

cf_serv_cfg g_service_bind = { .n_cfgs = 0 };
cf_tls_info* g_service_tls;

static cf_sockets g_sockets;

static cf_mutex g_thread_locks[MAX_SERVICE_THREADS];
static thread_ctx* g_thread_ctxs[MAX_SERVICE_THREADS];

static cf_mutex g_reaper_lock = CF_MUTEX_INIT;
static uint32_t g_n_slots;
static as_file_handle** g_file_handles;
static cf_queue g_free_slots;


//==========================================================
// Forward declarations.
//

// Setup.
static void create_service_thread(uint32_t sid);
static void add_localhost(cf_serv_cfg* serv_cfg, cf_sock_owner owner);

// Accept client connections.
static void* run_accept(void* udata);

// Assign connections to threads.
static void assign_socket(as_file_handle* fd_h);
static uint32_t select_sid(void);
static uint32_t select_sid_pinned(cf_topo_cpu_index i_cpu);
static uint32_t select_sid_adq(cf_topo_napi_id id);
static uint32_t select_sid_keyd(const cf_digest* keyd);
static void schedule_redistribution(void);

// Demarshal requests.
static void* run_service(void* udata);
static void stop_service(thread_ctx* ctx);
static void service_release_file_handle(as_file_handle* fd_h);
static bool process_readable(as_file_handle* fd_h);
static void start_transaction(as_file_handle* fd_h);
static void config_xdr_socket(cf_socket* sock);

// Reap idle and bad connections.
static void start_reaper(void);
static void* run_reaper(void* udata);

// Transaction queue.
static bool start_internal_transaction(thread_ctx* ctx);


//==========================================================
// Inlines & macros.
//

static inline void
rearm(as_file_handle* fd_h, uint32_t events)
{
	cf_poll_modify_socket(fd_h->poll, &fd_h->sock,
			events | EPOLLONESHOT | EPOLLRDHUP, fd_h);
}

#ifdef USE_ARGOBOTS

static as_monitor run_service_monitor;

static void run_service_thread(void *udata)
{
	thread_ctx *ctx = udata;
	uint32_t sid = ctx->sid;

	as_monitor_wait(&run_service_monitor);

	cf_detail(AS_SERVICE, "starting sid %u ctx %p", sid, ctx);

	if (as_config_is_cpu_pinned()) {
		ctx->i_cpu = (cf_topo_cpu_index)(sid % cf_topo_count_cpus());
	}

	ctx->lock = &g_thread_locks[sid];
	cf_poll_create(&ctx->poll);
	cf_epoll_queue_init(&ctx->trans_q, AS_TRANSACTION_HEAD_SIZE, 64);
	ctx->n_busy_polling = 0;

	cf_mutex_lock(&g_thread_locks[sid]);

	g_thread_ctxs[sid] = ctx;

	cf_mutex_unlock(&g_thread_locks[sid]);

	run_service(ctx);
}

static void run_defrag_thread(void *udata)
{
	drv_ssd *ssd = udata;

	as_monitor_wait(&ssd->run_defrag_monitor);
	run_defrag(ssd);
}

static void *run_threads(void *arg __attribute__((unused)))
{
	ABT_xstream *service_xstreams = cf_malloc(sizeof(ABT_xstream) * g_config.n_service_xstreams);
	ABT_xstream *defrag_xstreams = cf_malloc(sizeof(ABT_xstream) * g_config.n_defrag_xstreams);
	ABT_pool *service_pools = cf_malloc(sizeof(ABT_pool) * g_config.n_service_xstreams);
	ABT_pool *defrag_pools = cf_malloc(sizeof(ABT_pool) * g_config.n_defrag_xstreams);
	ABT_thread *service_threads = cf_malloc(sizeof(ABT_thread) * g_config.n_service_threads);
	uint32_t n_defrag_threads = 0;
	ABT_thread *defrag_threads = NULL;

	ABT_init(0, NULL);

	for (uint32_t i = 0; i < g_config.n_service_xstreams; i++) {
		if (i == 0) {
			ABT_xstream_self(&service_xstreams[0]);
		} else {
			ABT_xstream_create(ABT_SCHED_NULL, &service_xstreams[i]);
		}
		ABT_xstream_get_main_pools(service_xstreams[i], 1, &service_pools[i]);
	}

	for (uint32_t i = 0; i < g_config.n_defrag_xstreams; i++) {
		ABT_xstream_create(ABT_SCHED_NULL, &defrag_xstreams[i]);
		ABT_xstream_get_main_pools(defrag_xstreams[i], 1, &defrag_pools[i]);
	}

	ABT_thread_attr attr;
	ABT_thread_attr_create(&attr);
	ABT_thread_attr_set_stacksize(attr, 4 * 1024 * 1024);

	for (uint32_t sid = 0; sid < g_config.n_service_threads; sid++) {
		uint32_t pool_id = sid % g_config.n_service_xstreams;
		thread_ctx* ctx = cf_malloc(sizeof(thread_ctx));

		ctx->sid = sid;
		ABT_thread_create(service_pools[pool_id], run_service_thread, ctx, attr, &service_threads[sid]);
	}

	if (g_config.n_defrag_xstreams != 0) {
		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_namespace *ns = g_config.namespaces[ns_ix];

			if (ns->storage_type == AS_STORAGE_ENGINE_SSD) {
				drv_ssds *ssds = (drv_ssds*)ns->storage_private;

				n_defrag_threads += (uint32_t)ssds->n_ssds * g_config.n_defrag_threads_per_device;
			}
		}

		defrag_threads = cf_malloc(sizeof(ABT_thread) * n_defrag_threads);

		uint32_t defrag_thread_idx = 0;

		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			as_namespace *ns = g_config.namespaces[ns_ix];

			if (ns->storage_type != AS_STORAGE_ENGINE_SSD) {
				continue;
			}

			drv_ssds *ssds = (drv_ssds*)ns->storage_private;

			for (int i = 0; i < ssds->n_ssds; i++) {
				drv_ssd *ssd = &ssds->ssds[i];

				for (uint32_t j = 0; j < g_config.n_defrag_threads_per_device; j++) {
					uint32_t pool_id = defrag_thread_idx % g_config.n_defrag_xstreams;

					ABT_thread_create(defrag_pools[pool_id], run_defrag_thread, ssd, attr, &defrag_threads[defrag_thread_idx]);
					defrag_thread_idx++;
				}
			}
		}
		cf_assert(defrag_thread_idx == n_defrag_threads, AS_SERVICE, "unexpected");
	}

	ABT_thread_attr_free(&attr);

	for (uint32_t i = 0; i < g_config.n_service_threads; i++) {
		ABT_thread_free(&service_threads[i]);
	}

	for (uint32_t i = 0; i < n_defrag_threads; i++) {
		ABT_thread_free(&defrag_threads[i]);
	}

	for (uint32_t i = 1; i < g_config.n_service_xstreams; i++) {
		ABT_xstream_join(service_xstreams[i]);
		ABT_xstream_free(&service_xstreams[i]);
	}

	for (uint32_t i = 0; i < g_config.n_defrag_xstreams; i++) {
		ABT_xstream_join(defrag_xstreams[i]);
		ABT_xstream_free(&defrag_xstreams[i]);
	}

	ABT_finalize();
	free(service_xstreams);
	free(defrag_xstreams);
	free(service_pools);
	free(defrag_pools);
	free(service_threads);
	free(defrag_threads);

	return NULL;
}

void as_abt_init(void)
{
	as_monitor_init(&run_service_monitor);
	as_monitor_begin(&run_service_monitor);

	cf_thread_create_detached(run_threads, NULL);
}

static void create_service_threads(void)
{
	as_monitor_notify(&run_service_monitor);
}

static void service_yield(void)
{
	record_checkpoint(service_yield_begin);
	ABT_thread_yield();
	record_checkpoint(service_yield_end);
}

static void service_suspend(thread_ctx* ctx)
{
	uint32_t first_sid = ctx->sid;

	do {
		if (ctx->n_busy_polling < g_config.n_service_busy_polling_threshold) {
			return;
		}
		ctx = g_thread_ctxs[(ctx->sid + g_config.n_service_xstreams) % g_config.n_service_threads];
		if (!ctx) {
			return;
		}
	} while (first_sid != ctx->sid);

	cf_crash(AS_SERVICE, "service_suspend() not implemented");
}

#else

void as_abt_init(void)
{
}

static void create_service_threads(void)
{
	for (uint32_t i = 0; i < g_config.n_service_threads; i++) {
		create_service_thread(i);
	}
}

static void service_yield(void)
{
}

static void service_suspend(thread_ctx* ctx)
{
}

#endif


//==========================================================
// Public API.
//

void
as_service_init(void)
{
	// Create epoll instances and service threads.

	cf_info(AS_SERVICE, "starting %u service threads",
			g_config.n_service_threads);

	for (uint32_t i = 0; i < MAX_SERVICE_THREADS; i++) {
		cf_mutex_init(&g_thread_locks[i]);
	}

	create_service_threads();
}

void
as_service_start(void)
{
	start_reaper();

	// Create listening sockets.

	if (! g_config.service_localhost_disabled) {
		add_localhost(&g_service_bind, CF_SOCK_OWNER_SERVICE);
		add_localhost(&g_service_bind, CF_SOCK_OWNER_SERVICE_TLS);
	}

	if (cf_socket_init_server(&g_service_bind, &g_sockets) < 0) {
		cf_crash(AS_SERVICE, "couldn't initialize service socket");
	}

	cf_socket_show_server(AS_SERVICE, "client", &g_sockets);

	// Create accept thread.

	cf_info(AS_SERVICE, "starting accept thread");

	cf_thread_create_detached(run_accept, NULL);
}

void
as_service_set_threads(uint32_t n_threads)
{
	uint32_t old_n_threads = g_config.n_service_threads;

	if (n_threads > old_n_threads) {
		for (uint32_t sid = old_n_threads; sid < n_threads; sid++) {
			create_service_thread(sid);
		}

		g_config.n_service_threads = n_threads;

		schedule_redistribution();
	}
	else if (n_threads < old_n_threads) {
		g_config.n_service_threads = n_threads;

		for (uint32_t sid = n_threads; sid < old_n_threads; sid++) {
			cf_mutex_lock(&g_thread_locks[sid]);

			thread_ctx* ctx = g_thread_ctxs[sid];

			cf_detail(AS_SERVICE, "sending terminator sid %u ctx %p", sid, ctx);

			as_transaction tr;
			as_transaction_init_head(&tr, NULL, NULL);

			cf_epoll_queue_push(&ctx->trans_q, &tr);
			g_thread_ctxs[sid] = NULL;

			cf_mutex_unlock(&g_thread_locks[sid]);
		}
	}
}

bool
as_service_set_proto_fd_max(uint32_t val)
{
	struct rlimit rl;

	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		cf_crash(AS_SERVICE, "getrlimit() failed: %s", cf_strerror(errno));
	}

	if (val > (uint32_t)rl.rlim_cur) {
		cf_warning(AS_SERVICE, "can't set proto-fd-max %u > system limit %lu",
				val, rl.rlim_cur);
		return false;
	}

	if (val <= g_n_slots) {
		g_config.n_proto_fd_max = val;
		return true; // never shrink slots
	}

	size_t old_sz = g_n_slots * sizeof(as_file_handle*);
	size_t new_sz = val * sizeof(as_file_handle*);

	cf_mutex_lock(&g_reaper_lock);

	g_file_handles = cf_realloc(g_file_handles, new_sz);
	memset((uint8_t*)g_file_handles + old_sz, 0, new_sz - old_sz);

	for (uint32_t i = g_n_slots; i < val; i++) {
		cf_queue_push(&g_free_slots, &i);
	}

	g_n_slots = val;

	cf_mutex_unlock(&g_reaper_lock);

	g_config.n_proto_fd_max = val; // set *after* expanding slots

	return true;
}

void
as_service_rearm(as_file_handle* fd_h)
{
	if (fd_h->move_me) {
		cf_poll_delete_socket(fd_h->poll, &fd_h->sock);
		assign_socket(fd_h); // rearms (EPOLLIN)

		fd_h->move_me = false;
		return;
	}

	rearm(fd_h, EPOLLIN);
}

void
as_service_enqueue_internal(as_transaction* tr)
{
	while (true) {
		uint32_t sid = as_config_is_cpu_pinned() ?
				select_sid_pinned(cf_topo_current_cpu()) : select_sid();

		cf_mutex_lock(&g_thread_locks[sid]);

		thread_ctx* ctx = g_thread_ctxs[sid];

		if (ctx != NULL) {
			cf_epoll_queue_push(&ctx->trans_q, tr);
			cf_mutex_unlock(&g_thread_locks[sid]);
			break;
		}

		cf_mutex_unlock(&g_thread_locks[sid]);
	}
}

void
as_service_enqueue_internal_keyd(as_transaction* tr)
{
	while (true) {
		uint32_t sid = select_sid_keyd(&tr->keyd);

		cf_mutex_lock(&g_thread_locks[sid]);

		thread_ctx* ctx = g_thread_ctxs[sid];

		if (ctx != NULL) {
			cf_epoll_queue_push(&ctx->trans_q, tr);
			cf_mutex_unlock(&g_thread_locks[sid]);
			break;
		}

		cf_mutex_unlock(&g_thread_locks[sid]);
	}
}


//==========================================================
// Local helpers - setup.
//

void
create_service_thread(uint32_t sid)
{
	thread_ctx* ctx = cf_malloc(sizeof(thread_ctx));

	cf_detail(AS_SERVICE, "starting sid %u ctx %p", sid, ctx);

	if (as_config_is_cpu_pinned()) {
		ctx->i_cpu = (cf_topo_cpu_index)(sid % cf_topo_count_cpus());
	}

	ctx->lock = &g_thread_locks[sid];
	cf_poll_create(&ctx->poll);
	cf_epoll_queue_init(&ctx->trans_q, AS_TRANSACTION_HEAD_SIZE, 64);
	ctx->sid = sid;
	ctx->n_busy_polling = 0;

	cf_thread_create_transient(run_service, ctx);

	cf_mutex_lock(&g_thread_locks[sid]);

	g_thread_ctxs[sid] = ctx;

	cf_mutex_unlock(&g_thread_locks[sid]);
}

static void
add_localhost(cf_serv_cfg* serv_cfg, cf_sock_owner owner)
{
	// Localhost will only be added to the addresses, if we're not yet listening
	// on wildcard ("any") or localhost.

	cf_ip_port port = 0;

	for (uint32_t i = 0; i < serv_cfg->n_cfgs; i++) {
		if (serv_cfg->cfgs[i].owner != owner) {
			continue;
		}

		port = serv_cfg->cfgs[i].port;

		if (cf_ip_addr_is_any(&serv_cfg->cfgs[i].addr) ||
				cf_ip_addr_is_local(&serv_cfg->cfgs[i].addr)) {
			return;
		}
	}

	if (port == 0) {
		return;
	}

	cf_sock_cfg sock_cfg;

	cf_sock_cfg_init(&sock_cfg, owner);
	sock_cfg.port = port;
	cf_ip_addr_set_local(&sock_cfg.addr);

	if (cf_serv_cfg_add_sock_cfg(serv_cfg, &sock_cfg) < 0) {
		cf_crash(AS_SERVICE, "couldn't add localhost listening address");
	}
}


//==========================================================
// Local helpers - accept client connections.
//

static void*
run_accept(void* udata)
{
	(void)udata;

	cf_poll poll;
	cf_poll_create(&poll);

	cf_poll_add_sockets(poll, &g_sockets, EPOLLIN);

	while (true) {
		cf_poll_event events[N_EVENTS];
		int32_t n_events = cf_poll_wait(poll, events, N_EVENTS, -1);

		cf_assert(n_events >= 0, AS_SERVICE, "unexpected EINTR");

		for (uint32_t i = 0; i < (uint32_t)n_events; i++) {
			cf_socket* ssock = events[i].data;
			cf_socket csock;
			cf_sock_addr caddr;

			if (cf_socket_accept(ssock, &csock, &caddr) < 0) {
				if (errno == EMFILE || errno == ENFILE) {
					cf_ticker_warning(AS_SERVICE, "out of file descriptors");
					continue;
				}

				cf_crash(AS_SERVICE, "accept() failed: %d (%s)", errno,
						cf_strerror(errno));
			}

			cf_sock_cfg* cfg = ssock->cfg;

			// Ensure that proto_connections_closed is read first.
			uint64_t n_closed =
					as_load_uint64(&g_stats.proto_connections_closed);
			// TODO - ARM TSO plugin - will need barrier.
			uint64_t n_opened =
					as_load_uint64(&g_stats.proto_connections_opened);

			if (n_opened - n_closed >= g_config.n_proto_fd_max) {
				cf_ticker_warning(AS_SERVICE,
						"refusing client connection - proto-fd-max %u",
						g_config.n_proto_fd_max);

				cf_socket_close(&csock);
				cf_socket_term(&csock);
				continue;
			}

			cf_socket_keep_alive(&csock, 60, 60, 2);

			if (cfg->owner == CF_SOCK_OWNER_SERVICE_TLS) {
				tls_socket_prepare_server(g_service_tls, &csock);
			}

			as_file_handle* fd_h = cf_rc_alloc(sizeof(as_file_handle));
			// Ref for epoll instance.

			fd_h->poll_data_type = CF_POLL_DATA_CLIENT_IO;

			cf_sock_addr_to_string_safe(&caddr, fd_h->client,
					sizeof(fd_h->client));
			cf_socket_copy(&csock, &fd_h->sock);

			fd_h->last_used = cf_getns();
			fd_h->in_transaction = 0;
			fd_h->move_me = false;
			fd_h->reap_me = false;
			fd_h->is_xdr = false;
			fd_h->proto = NULL;
			fd_h->proto_unread = sizeof(as_proto);
			fd_h->security_filter = as_security_filter_create();

			cf_rc_reserve(fd_h); // ref for reaper

			cf_mutex_lock(&g_reaper_lock);

			uint32_t slot;

			if (cf_queue_pop(&g_free_slots, &slot, CF_QUEUE_NOWAIT) !=
					CF_QUEUE_OK) {
				cf_crash(AS_SERVICE, "cannot get free slot");
			}

			g_file_handles[slot] = fd_h;

			cf_mutex_unlock(&g_reaper_lock);

			assign_socket(fd_h); // arms (EPOLLIN)

			as_incr_uint64(&g_stats.proto_connections_opened);
		}
	}

	return NULL;
}


//==========================================================
// Local helpers - assign client connections to threads.
//

static void
assign_socket(as_file_handle* fd_h)
{
	while (true) {
		uint32_t sid;

		switch (g_config.auto_pin) {
		case CF_TOPO_AUTO_PIN_NONE:
			sid = select_sid();
			break;
		case CF_TOPO_AUTO_PIN_CPU:
		case CF_TOPO_AUTO_PIN_NUMA:
			sid = select_sid_pinned(cf_topo_socket_cpu(&fd_h->sock));
			break;
		case CF_TOPO_AUTO_PIN_ADQ:
			sid = select_sid_adq(cf_topo_socket_napi_id(&fd_h->sock));
			break;
		default:
			cf_crash(AS_SERVICE, "bad auto-pin %d", g_config.auto_pin);
			return;
		}

		cf_mutex_lock(&g_thread_locks[sid]);

		thread_ctx* ctx = g_thread_ctxs[sid];

		if (ctx != NULL) {
			fd_h->poll = ctx->poll;

			cf_poll_add_socket(fd_h->poll, &fd_h->sock,
					EPOLLIN | EPOLLONESHOT | EPOLLRDHUP, fd_h);

			cf_mutex_unlock(&g_thread_locks[sid]);
			break;
		}

		cf_mutex_unlock(&g_thread_locks[sid]);
	}
}

static uint32_t
select_sid(void)
{
	static uint32_t rr = 0;

	return rr++ % g_config.n_service_threads;
}

static uint32_t
select_sid_pinned(cf_topo_cpu_index i_cpu)
{
	static uint32_t rr[CPU_SETSIZE] = { 0 };

	uint16_t n_cpus = cf_topo_count_cpus();
	uint32_t threads_per_cpu = g_config.n_service_threads / n_cpus;

	uint32_t thread_ix = rr[i_cpu]++ % threads_per_cpu;

	return (thread_ix * n_cpus) + i_cpu;
}

static uint32_t
select_sid_adq(cf_topo_napi_id id)
{
	return id == 0 ? select_sid() : id % g_config.n_service_threads;
}

static uint32_t
select_sid_keyd(const cf_digest* keyd)
{
	return as_partition_getid(keyd) % g_config.n_service_threads;
}

static void
schedule_redistribution(void)
{
	cf_mutex_lock(&g_reaper_lock);

	uint32_t n_remaining = g_n_slots - cf_queue_sz(&g_free_slots);

	for (uint32_t i = 0; n_remaining != 0; i++) {
		as_file_handle* fd_h = g_file_handles[i];

		if (fd_h != NULL) {
			fd_h->move_me = true;
			n_remaining--;
		}
	}

	cf_mutex_unlock(&g_reaper_lock);
}


//==========================================================
// Local helpers - demarshal client requests.
//

static void*
run_service(void* udata)
{
	thread_ctx* ctx = (thread_ctx*)udata;

	cf_detail(AS_SERVICE, "running ctx %p", ctx);

	if (as_config_is_cpu_pinned()) {
		cf_topo_pin_to_cpu(ctx->i_cpu);
	}

	cf_poll poll = ctx->poll;
	cf_epoll_queue* trans_q = &ctx->trans_q;

	cf_poll_add_fd(poll, trans_q->event_fd, EPOLLIN, trans_q);
	as_xdr_init_poll(poll);

	while (true) {
		cf_poll_event events[N_EVENTS];
#ifdef USE_ARGOBOTS
		int timeout = 0;
#else
		int timeout = -1;
#endif
		int32_t n_events = cf_poll_wait(poll, events, N_EVENTS, timeout);
		if (n_events == 0) {
			ctx->n_busy_polling++;
			service_suspend(ctx);
			service_yield();
			continue;
		}
		ctx->n_busy_polling = 0;

		uint64_t events_ns = cf_getns();

		for (uint32_t i = 0; i < (uint32_t)n_events; i++) {
			uint32_t mask = events[i].events;
			void* data = events[i].data;

			uint8_t type = *(uint8_t*)data;

			if (type == CF_POLL_DATA_EPOLL_QUEUE) {
				cf_assert(mask == EPOLLIN, AS_SERVICE,
						"unexpected event: 0x%0x", mask);

				if (start_internal_transaction(ctx)) {
					continue;
				}

				stop_service(ctx);

				return NULL;
			}

			if (type == CF_POLL_DATA_XDR_IO) {
				as_xdr_io_event(mask, data);
				continue;
			}

			if (type == CF_POLL_DATA_XDR_TIMER) {
				as_xdr_timer_event(events, n_events, i);
				continue;
			}
			// else - type == CF_POLL_DATA_CLIENT_IO

			as_file_handle* fd_h = data;

			if ((mask & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) != 0) {
				service_release_file_handle(fd_h);
				continue;
			}

			if (tls_socket_needs_handshake(&fd_h->sock)) {
				int32_t tls_ev = tls_socket_accept(&fd_h->sock);

				if (tls_ev == EPOLLERR) {
					service_release_file_handle(fd_h);
					continue;
				}

				if (tls_ev == 0) {
					tls_socket_must_not_have_data(&fd_h->sock,
							"service handshake");
					tls_ev = EPOLLIN;
				}

				rearm(fd_h, (uint32_t)tls_ev);
				continue;
			}

			if (fd_h->proto == NULL && fd_h->proto_unread == sizeof(as_proto)) {
				// Overload last_used for request start time. Note - latency
				// will include unrelated events ahead of this one in this loop.
				fd_h->last_used = events_ns;
			}

			if (! process_readable(fd_h)) {
				service_release_file_handle(fd_h);
				continue;
			}

			tls_socket_must_not_have_data(&fd_h->sock, "full client read");

			if (fd_h->proto_unread != 0) {
				rearm(fd_h, EPOLLIN);
				continue;
			}

			// Note that epoll cannot trigger again for this file handle during
			// the transaction. We'll rearm at the end of the transaction.
			start_transaction(fd_h);
		}

		service_yield();
	}

	return NULL;
}

static void
stop_service(thread_ctx* ctx)
{
	cf_detail(AS_SERVICE, "stopping ctx %p", ctx);

	as_xdr_shutdown_poll();
	as_xdr_cleanup_tl_stats();

	while (true) {
		bool any_in_transaction = false;

		cf_mutex_lock(&g_reaper_lock);

		uint32_t n_remaining = g_n_slots - cf_queue_sz(&g_free_slots);

		for (uint32_t i = 0; n_remaining != 0; i++) {
			as_file_handle* fd_h = g_file_handles[i];

			if (fd_h == NULL) {
				continue;
			}

			n_remaining--;

			// Ignore, if another thread's or INVALID_POLL.
			if (! cf_poll_equal(fd_h->poll, ctx->poll)) {
				continue;
			}

			// Don't transfer during TLS handshake - might need EPOLLOUT.
			if (tls_socket_needs_handshake(&fd_h->sock)) {
				service_release_file_handle(fd_h);
				continue;
			}

			if (fd_h->in_transaction != 0) {
				any_in_transaction = true;
				continue;
			}

			cf_poll_delete_socket(fd_h->poll, &fd_h->sock);
			assign_socket(fd_h); // keeps armed (EPOLLIN)
		}

		cf_mutex_unlock(&g_reaper_lock);

		if (! any_in_transaction) {
			break;
		}

		sleep(1);
	}

	cf_poll_destroy(ctx->poll);
	cf_epoll_queue_destroy(&ctx->trans_q);

	cf_detail(AS_SERVICE, "stopped ctx %p", ctx);

	cf_free(ctx);
}

static void
service_release_file_handle(as_file_handle* fd_h)
{
	cf_poll_delete_socket(fd_h->poll, &fd_h->sock);
	fd_h->poll = INVALID_POLL;
	fd_h->reap_me = true;
	as_release_file_handle(fd_h);
}

static bool
process_readable(as_file_handle* fd_h)
{
	uint8_t* end = fd_h->proto == NULL ?
			(uint8_t*)&fd_h->proto_hdr + sizeof(as_proto) : // header
			fd_h->proto->body + fd_h->proto->sz; // body

	while (true) {
		int32_t sz = cf_socket_recv(&fd_h->sock, end - fd_h->proto_unread,
				fd_h->proto_unread, 0);

		if (sz < 0) {
			return errno == EAGAIN || errno == EWOULDBLOCK;
		}

		if (sz == 0) {
			return false;
		}

		fd_h->proto_unread -= (uint64_t)sz;

		if (fd_h->proto_unread != 0) {
			continue; // drain socket (and OpenSSL's internal buffer) dry
		}

		if (fd_h->proto != NULL) {
			return true; // done with entire request
		}
		// else - switch from header to body.

		// Check for a TLS ClientHello arriving at a non-TLS socket. Heuristic:
		//   - tls[0] == ContentType.handshake (22)
		//   - tls[1] == ProtocolVersion.major (3)
		//   - tls[5] == HandshakeType.client_hello (1)

		uint8_t* tls = (uint8_t*)&fd_h->proto_hdr;

		if (tls[0] == 22 && tls[1] == 3 && tls[5] == 1) {
			cf_warning(AS_SERVICE, "ignoring TLS connection from %s",
					fd_h->client);
			return false;
		}

		// For backward compatibility, allow version 0 with security messages.
		if (fd_h->proto_hdr.version != PROTO_VERSION &&
				! (fd_h->proto_hdr.version == 0 &&
						fd_h->proto_hdr.type == PROTO_TYPE_SECURITY)) {
			cf_warning(AS_SERVICE, "unsupported proto version %d from %s",
					fd_h->proto_hdr.version, fd_h->client);
			return false;
		}

		if (! as_proto_is_valid_type(&fd_h->proto_hdr)) {
			cf_warning(AS_SERVICE, "unsupported proto type %d from %s",
					fd_h->proto_hdr.type, fd_h->client);
			return false;
		}

		as_proto_swap(&fd_h->proto_hdr);

		if (fd_h->proto_hdr.sz > PROTO_SIZE_MAX) {
			cf_warning(AS_SERVICE, "invalid proto size %lu from %s",
					(uint64_t)fd_h->proto_hdr.sz, fd_h->client);
			return false;
		}

		fd_h->proto = cf_malloc(sizeof(as_proto) + fd_h->proto_hdr.sz);
		memcpy(fd_h->proto, &fd_h->proto_hdr, sizeof(as_proto));

		fd_h->proto_unread = fd_h->proto->sz;
		end = fd_h->proto->body + fd_h->proto->sz;
	}
}

static void
start_transaction(as_file_handle* fd_h)
{
	// as_end_of_transaction() rearms then decrements, so this may be > 1.
	as_incr_uint32(&fd_h->in_transaction);

	uint64_t start_ns = fd_h->last_used;
	as_proto* proto = fd_h->proto;

	fd_h->proto = NULL;
	fd_h->proto_unread = sizeof(as_proto);

	if (proto->type == PROTO_TYPE_INFO) {
		as_info_transaction it = {
			.fd_h = fd_h,
			.proto = proto,
			.start_time = start_ns
		};

		as_info(&it);
		return;
	}

	as_transaction tr;
	as_transaction_init_head(&tr, NULL, (cl_msg*)proto);

	tr.origin = FROM_CLIENT;
	tr.from.proto_fd_h = fd_h;
	tr.start_time = start_ns;

	if (proto->type == PROTO_TYPE_SECURITY) {
		as_security_transact(&tr);
		return;
	}

	if (proto->type == PROTO_TYPE_AS_MSG_COMPRESSED) {
		uint32_t result = as_proto_uncompress((as_comp_proto*)proto,
				(as_proto**)&tr.msgp);

		if (result != AS_OK) {
			as_transaction_demarshal_error(&tr, result);
			return;
		}

		cf_free(proto);
	}

	if (as_transaction_is_xdr(&tr) && ! fd_h->is_xdr) {
		config_xdr_socket(&fd_h->sock);
		fd_h->is_xdr = true;
	}

	if (tr.msgp->msg.info1 & AS_MSG_INFO1_BATCH) {
		as_batch_queue_task(&tr);
		return;
	}

	if (! as_transaction_prepare(&tr, true)) {
		as_transaction_demarshal_error(&tr, AS_ERR_PARAMETER);
		return;
	}

	as_tsvc_process_transaction(&tr);
}

static void
config_xdr_socket(cf_socket* sock)
{
	cf_socket_set_receive_buffer(sock, XDR_READ_BUFFER_SIZE);
	cf_socket_set_send_buffer(sock, XDR_WRITE_BUFFER_SIZE);
	cf_socket_set_window(sock, XDR_READ_BUFFER_SIZE);
	cf_socket_enable_nagle(sock);
}


//==========================================================
// Local helpers - reap idle and bad connections.
//

static void
start_reaper(void)
{
	g_n_slots = g_config.n_proto_fd_max;
	g_file_handles = cf_calloc(g_n_slots, sizeof(as_file_handle*));

	cf_queue_init(&g_free_slots, sizeof(uint32_t), g_n_slots, false);

	for (uint32_t i = 0; i < g_n_slots; i++) {
		cf_queue_push(&g_free_slots, &i);
	}

	cf_info(AS_SERVICE, "starting reaper thread");

	cf_thread_create_detached(run_reaper, NULL);
}

static void*
run_reaper(void* udata)
{
	(void)udata;

	while (true) {
		sleep(1);

		bool security_refresh = as_security_should_refresh();

		uint64_t kill_ns = (uint64_t)g_config.proto_fd_idle_ms * 1000000;
		uint64_t now_ns = cf_getns();

		cf_mutex_lock(&g_reaper_lock);

		uint32_t n_remaining = g_n_slots - cf_queue_sz(&g_free_slots);

		for (uint32_t i = 0; n_remaining != 0; i++) {
			as_file_handle* fd_h = g_file_handles[i];

			if (fd_h == NULL) {
				continue;
			}

			n_remaining--;

			if (security_refresh) {
				as_security_refresh(fd_h);
			}

			// reap_me overrides in_transaction.
			if (fd_h->reap_me) {
				g_file_handles[i] = NULL;
				cf_queue_push_head(&g_free_slots, &i);
				as_release_file_handle(fd_h);
				continue;
			}

			if (fd_h->in_transaction != 0) {
				continue;
			}

			if (kill_ns != 0 && fd_h->last_used + kill_ns < now_ns) {
				cf_socket_shutdown(&fd_h->sock); // will trigger epoll errors

				g_file_handles[i] = NULL;
				cf_queue_push_head(&g_free_slots, &i);
				as_release_file_handle(fd_h);

				g_stats.reaper_count++;
			}
		}

		cf_mutex_unlock(&g_reaper_lock);
	}

	return NULL;
}


//==========================================================
// Local helpers - transaction queue.
//

static bool
start_internal_transaction(thread_ctx* ctx)
{
	as_transaction tr;

	cf_mutex_lock(ctx->lock);

	if (! cf_epoll_queue_pop(&ctx->trans_q, &tr)) {
		cf_crash(AS_SERVICE, "unable to pop from transaction queue");
	}

	cf_mutex_unlock(ctx->lock);

	if (tr.msgp == NULL) {
		return false;
	}

	as_tsvc_process_transaction(&tr);

	return true;
}
