#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_futex
#define SYS_futex 202
#endif
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif

enum { THREADS = 8 };
static _Atomic int ready;
static _Atomic int total;
static _Atomic int tids[THREADS];
static _Thread_local unsigned tls_value;

static int futex_wait_private(_Atomic int *word, int expected) {
    return (int)syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, expected, 0, 0, 0);
}

static int futex_wake_private(_Atomic int *word, int count) {
    return (int)syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, count, 0, 0, 0);
}

static void *worker(void *arg) {
    int index = (int)(uintptr_t)arg;
    tls_value = (unsigned)(0x1000 + index);
    tids[index] = (int)syscall(SYS_gettid);
    if (tls_value != (unsigned)(0x1000 + index))
        return (void *)1;
    atomic_fetch_add_explicit(&total, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&ready, 1, memory_order_release);
    futex_wake_private(&ready, THREADS);
    return 0;
}

int main(void) {
    pthread_t threads[THREADS];
    int pid = (int)getpid();
    for (int i = 0; i < THREADS; ++i) {
        if (pthread_create(&threads[i], 0, worker, (void *)(uintptr_t)i) != 0)
            return 2;
    }
    while (atomic_load_explicit(&ready, memory_order_acquire) != THREADS)
        futex_wait_private(&ready, atomic_load_explicit(&ready, memory_order_relaxed));
    for (int i = 0; i < THREADS; ++i) {
        void *result = 0;
        if (pthread_join(threads[i], &result) != 0 || result != 0)
            return 3;
        if (tids[i] <= 0 || tids[i] == pid)
            return 4;
        for (int j = 0; j < i; ++j)
            if (tids[i] == tids[j])
                return 5;
    }
    if (atomic_load(&total) != THREADS || getpid() != pid)
        return 6;
    const char message[] = "pthread-test ok: 8 threads, futex, tls, tid\n";
    if (write(STDOUT_FILENO, message, sizeof(message) - 1) != (ssize_t)(sizeof(message) - 1))
        return 7;
    return 0;
}
