/*
 * QEMU coroutines
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Stefan Hajnoczi    <stefanha@linux.vnet.ibm.com>
 *  Kevin Wolf         <kwolf@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include <pthread.h>
#include "coroutine_int.h"

enum {
	/* Maximum free pool size prevents holding too many freed coroutines */
	POOL_MAX_SIZE = 64,
};

/** Free list to speed up creation */
static pthread_mutex_t pool_lock;
static QSLIST_HEAD(, Coroutine) pool = QSLIST_HEAD_INITIALIZER(pool);
static unsigned int pool_size;

static void error_exit(int err, const char *msg) {
	fprintf(stderr, "qemu: %s: %s\n", msg, strerror(err));
	abort();
}

static void qemu_mutex_lock(pthread_mutex_t *mutex) {
	int err;

	err = pthread_mutex_lock(mutex);
	if (err)
		error_exit(err, __func__);
}

static void qemu_mutex_unlock(pthread_mutex_t *mutex) {
	int err;

	err = pthread_mutex_unlock(mutex);
	if (err)
		error_exit(err, __func__);
}

static void qemu_mutex_init(pthread_mutex_t *mutex) {
	int err;
	pthread_mutexattr_t mutexattr;

	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
	err = pthread_mutex_init(mutex, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
	if (err)
		error_exit(err, __func__);
}

static void qemu_mutex_destroy(pthread_mutex_t *mutex) {
	int err;

	err = pthread_mutex_destroy(mutex);
	if (err)
		error_exit(err, __func__);
}

Coroutine *qemu_coroutine_create(CoroutineEntry *entry) {
	Coroutine *co = NULL;

	if (CONFIG_COROUTINE_POOL) {
		qemu_mutex_lock(&pool_lock);
		co = QSLIST_FIRST(&pool);
		if (co) {
			QSLIST_REMOVE_HEAD(&pool, pool_next);
			pool_size--;
		}
		qemu_mutex_unlock(&pool_lock);
	}

	if (!co) {
		co = qemu_coroutine_new();
#ifdef _DEBUG
		printf("qemu_coroutine_new %p\n", co);
#endif
	}
#ifdef _DEBUG
	else {
		printf("reuse qemu_coroutine %p\n", co);
	}
#endif

	co->entry = entry;
	QTAILQ_INIT(&co->co_queue_wakeup);
	return co;
}

static void coroutine_delete(Coroutine *co) {
	if (CONFIG_COROUTINE_POOL) {
		qemu_mutex_lock(&pool_lock);
		if (pool_size < POOL_MAX_SIZE) {
			QSLIST_INSERT_HEAD(&pool, co, pool_next);
			co->caller = NULL;
			pool_size++;
			qemu_mutex_unlock(&pool_lock);
			return;
		}
		qemu_mutex_unlock(&pool_lock);
	}

	qemu_coroutine_delete(co);
}

static void __attribute__((constructor)) coroutine_pool_init(void) {
	qemu_mutex_init(&pool_lock);
}

static void __attribute__((destructor)) coroutine_pool_cleanup(void) {
	Coroutine *co;
	Coroutine *tmp;

	QSLIST_FOREACH_SAFE(co, &pool, pool_next, tmp)
	{
		QSLIST_REMOVE_HEAD(&pool, pool_next);
		qemu_coroutine_delete(co);
	}

	qemu_mutex_destroy(&pool_lock);
}

/**
 * qemu_co_queue_run_restart:
 *
 * Enter each coroutine that was previously marked for restart by
 * qemu_co_queue_next() or qemu_co_queue_restart_all().  This function is
 * invoked by the core coroutine code when the current coroutine yields or
 * terminates.
 */
void qemu_co_queue_run_restart(Coroutine *co) {
	Coroutine *next;

	//trace_qemu_co_queue_run_restart(co);
	while ((next = QTAILQ_FIRST(&co->co_queue_wakeup))) {
		QTAILQ_REMOVE(&co->co_queue_wakeup, next, co_queue_next);
		qemu_coroutine_enter(next, NULL);
	}
}

static void coroutine_swap(Coroutine *from, Coroutine *to) {
	CoroutineAction ret;

	ret = qemu_coroutine_switch(from, to, COROUTINE_YIELD);

	qemu_co_queue_run_restart(to);

	switch (ret) {
	case COROUTINE_YIELD:
		return;
	case COROUTINE_TERMINATE:
		//trace_qemu_coroutine_terminate(to);
		coroutine_delete(to);
		return;
	default:
		abort();
	}
}

void qemu_coroutine_enter(Coroutine *co, void *opaque) {
#ifdef _DEBUG
	printf("qemu_coroutine_enter %p\n", co);
#endif
	Coroutine *self = qemu_coroutine_self();

	//trace_qemu_coroutine_enter(self, co, opaque);

	if (co->caller) {
		fprintf(stderr, "Co-routine re-entered recursively\n");
		abort();
	}

	co->caller = self;
	co->entry_arg = opaque;
	coroutine_swap(self, co);
}

void coroutine_fn qemu_coroutine_yield(void) {
	Coroutine *self = qemu_coroutine_self();
#ifdef _DEBUG
	printf("qemu_coroutine_yield %p\n", self);
#endif
	Coroutine *to = self->caller;

	//trace_qemu_coroutine_yield(self, to);

	if (!to) {
		fprintf(stderr, "Co-routine is yielding to no one\n");
		abort();
	}

	self->caller = NULL;
	coroutine_swap(self, to);
}
