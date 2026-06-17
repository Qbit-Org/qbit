/*
 * Copyright (c) 2026-present The qbit core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or https://opensource.org/license/mit.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libbitcoinpqc/bitcoinpqc.h"

#define DEFAULT_THREADS 4u
#define DEFAULT_ITERATIONS 2u
#define KEYGEN_RANDOM_BYTES 128u
#define MESSAGE_BYTES 96u

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int started;
    const uint8_t *shared_public_key;
    const uint8_t *shared_secret_key;
    size_t shared_public_key_size;
    size_t shared_secret_key_size;
    size_t iterations;
    double deadline_seconds;
    int use_deadline;
} harness_shared_t;

typedef struct {
    harness_shared_t *shared;
    size_t thread_index;
    size_t completed_iterations;
    int failed;
    char error[256];
} worker_state_t;

static double monotonic_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static void fill_deterministic(uint8_t *out, size_t len, size_t thread_index, size_t iteration, uint64_t domain)
{
    uint64_t x = 0x9e3779b97f4a7c15ULL ^
                 ((uint64_t)(thread_index + 1u) * 0xbf58476d1ce4e5b9ULL) ^
                 ((uint64_t)(iteration + 1u) * 0x94d049bb133111ebULL) ^
                 domain;
    for (size_t i = 0; i < len; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out[i] = (uint8_t)((x * 0x2545f4914f6cdd1dULL) >> 56);
    }
}

static void set_worker_error(worker_state_t *worker, const char *context, bitcoin_pqc_error_t err)
{
    worker->failed = 1;
    snprintf(worker->error, sizeof(worker->error), "%s failed with error %d", context, (int)err);
}

static int sign_verify_once(
    worker_state_t *worker,
    const uint8_t *public_key,
    size_t public_key_size,
    const uint8_t *secret_key,
    size_t secret_key_size,
    size_t iteration,
    uint64_t domain)
{
    uint8_t message[MESSAGE_BYTES];
    fill_deterministic(message, sizeof(message), worker->thread_index, iteration, domain);
    const size_t message_size = (iteration % (MESSAGE_BYTES + 1u));
    const uint8_t *message_ptr = message_size == 0 ? NULL : message;

    bitcoin_pqc_signature_t signature = {0};
    bitcoin_pqc_sign_stats_t stats;
    bitcoin_pqc_error_t err = bitcoin_pqc_sign_with_stats(
        secret_key,
        secret_key_size,
        message_ptr,
        message_size,
        &signature,
        &stats);
    if (err != BITCOIN_PQC_OK) {
        set_worker_error(worker, "bitcoin_pqc_sign_with_stats", err);
        return -1;
    }

    if (signature.signature == NULL || signature.signature_size != bitcoin_pqc_signature_size()) {
        worker->failed = 1;
        snprintf(worker->error, sizeof(worker->error), "signature output has unexpected shape");
        bitcoin_pqc_signature_free(&signature);
        return -1;
    }

    err = bitcoin_pqc_verify(
        public_key,
        public_key_size,
        message_ptr,
        message_size,
        signature.signature,
        signature.signature_size);
    if (err != BITCOIN_PQC_OK) {
        set_worker_error(worker, "bitcoin_pqc_verify(valid)", err);
        bitcoin_pqc_signature_free(&signature);
        return -1;
    }

    signature.signature[signature.signature_size - 1u] ^= 0x01u;
    err = bitcoin_pqc_verify(
        public_key,
        public_key_size,
        message_ptr,
        message_size,
        signature.signature,
        signature.signature_size);
    if (err == BITCOIN_PQC_OK) {
        worker->failed = 1;
        snprintf(worker->error, sizeof(worker->error), "bitcoin_pqc_verify accepted a mutated signature");
        bitcoin_pqc_signature_free(&signature);
        return -1;
    }

    bitcoin_pqc_signature_free(&signature);
    return 0;
}

static int local_keypair_round(worker_state_t *worker, size_t iteration)
{
    uint8_t random_data[KEYGEN_RANDOM_BYTES];
    fill_deterministic(random_data, sizeof(random_data), worker->thread_index, iteration, 0x6b657967656eULL);

    bitcoin_pqc_keypair_t keypair = {0};
    bitcoin_pqc_error_t err = bitcoin_pqc_keygen(&keypair, random_data, sizeof(random_data));
    if (err != BITCOIN_PQC_OK) {
        set_worker_error(worker, "bitcoin_pqc_keygen", err);
        return -1;
    }

    err = bitcoin_pqc_secret_key_validate(keypair.secret_key, keypair.secret_key_size);
    if (err != BITCOIN_PQC_OK) {
        set_worker_error(worker, "bitcoin_pqc_secret_key_validate(local)", err);
        bitcoin_pqc_keypair_free(&keypair);
        return -1;
    }

    int result = sign_verify_once(
        worker,
        keypair.public_key,
        keypair.public_key_size,
        keypair.secret_key,
        keypair.secret_key_size,
        iteration,
        0x6c6f63616c736967ULL);
    bitcoin_pqc_keypair_free(&keypair);
    return result;
}

static void *worker_main(void *arg)
{
    worker_state_t *worker = (worker_state_t *)arg;
    harness_shared_t *shared = worker->shared;

    pthread_mutex_lock(&shared->mutex);
    while (!shared->started) {
        pthread_cond_wait(&shared->cond, &shared->mutex);
    }
    pthread_mutex_unlock(&shared->mutex);

    for (size_t iteration = 0;; ++iteration) {
        if (shared->use_deadline) {
            if (iteration > 0 && monotonic_seconds() >= shared->deadline_seconds) {
                break;
            }
        } else if (iteration >= shared->iterations) {
            break;
        }

        bitcoin_pqc_error_t err = bitcoin_pqc_secret_key_validate(
            shared->shared_secret_key,
            shared->shared_secret_key_size);
        if (err != BITCOIN_PQC_OK) {
            set_worker_error(worker, "bitcoin_pqc_secret_key_validate(shared)", err);
            break;
        }

        if (sign_verify_once(
                worker,
                shared->shared_public_key,
                shared->shared_public_key_size,
                shared->shared_secret_key,
                shared->shared_secret_key_size,
                iteration,
                0x7368617265647369ULL) != 0) {
            break;
        }

        if (local_keypair_round(worker, iteration) != 0) {
            break;
        }

        worker->completed_iterations = iteration + 1u;
    }

    return NULL;
}

static int parse_size_arg(const char *value, size_t *out)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -1;
    }
    *out = (size_t)parsed;
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--threads N] [--iterations N] [--seconds N]\n"
            "\n"
            "Runs concurrent libbitcoinpqc keygen/sign/verify/validate operations.\n"
            "--seconds takes precedence over --iterations when nonzero.\n",
            program);
}

int main(int argc, char **argv)
{
    size_t threads = DEFAULT_THREADS;
    size_t iterations = DEFAULT_ITERATIONS;
    size_t seconds = 0;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            if (parse_size_arg(argv[++i], &threads) != 0 || threads == 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            if (parse_size_arg(argv[++i], &iterations) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            if (parse_size_arg(argv[++i], &seconds) != 0) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (threads > 256u) {
        fprintf(stderr, "thread count is too large: %zu\n", threads);
        return 2;
    }
    if (seconds == 0 && iterations == 0) {
        iterations = 1;
    }

    uint8_t shared_seed[KEYGEN_RANDOM_BYTES];
    fill_deterministic(shared_seed, sizeof(shared_seed), 0, 0, 0x7368617265646bULL);

    bitcoin_pqc_keypair_t shared_keypair = {0};
    bitcoin_pqc_error_t err = bitcoin_pqc_keygen(&shared_keypair, shared_seed, sizeof(shared_seed));
    if (err != BITCOIN_PQC_OK) {
        fprintf(stderr, "shared bitcoin_pqc_keygen failed with error %d\n", (int)err);
        return 1;
    }

    harness_shared_t shared;
    memset(&shared, 0, sizeof(shared));
    pthread_mutex_init(&shared.mutex, NULL);
    pthread_cond_init(&shared.cond, NULL);
    shared.shared_public_key = (const uint8_t *)shared_keypair.public_key;
    shared.shared_secret_key = (const uint8_t *)shared_keypair.secret_key;
    shared.shared_public_key_size = shared_keypair.public_key_size;
    shared.shared_secret_key_size = shared_keypair.secret_key_size;
    shared.iterations = iterations;
    shared.use_deadline = seconds != 0;
    shared.deadline_seconds = shared.use_deadline ? monotonic_seconds() + (double)seconds : 0.0;

    pthread_t *thread_ids = calloc(threads, sizeof(*thread_ids));
    worker_state_t *workers = calloc(threads, sizeof(*workers));
    if (thread_ids == NULL || workers == NULL) {
        fprintf(stderr, "failed to allocate worker state\n");
        free(thread_ids);
        free(workers);
        bitcoin_pqc_keypair_free(&shared_keypair);
        return 1;
    }

    printf("libbitcoinpqc concurrency harness: threads=%zu iterations=%zu seconds=%zu\n",
           threads,
           iterations,
           seconds);
    fflush(stdout);

    int create_failed = 0;
    for (size_t i = 0; i < threads; ++i) {
        workers[i].shared = &shared;
        workers[i].thread_index = i;
        int rc = pthread_create(&thread_ids[i], NULL, worker_main, &workers[i]);
        if (rc != 0) {
            fprintf(stderr, "pthread_create failed for worker %zu: %d\n", i, rc);
            threads = i;
            create_failed = 1;
            break;
        }
    }

    if (threads == 0) {
        fprintf(stderr, "no worker threads were created; cannot provide TSAN coverage\n");
        free(thread_ids);
        free(workers);
        pthread_cond_destroy(&shared.cond);
        pthread_mutex_destroy(&shared.mutex);
        bitcoin_pqc_keypair_free(&shared_keypair);
        return 1;
    }

    pthread_mutex_lock(&shared.mutex);
    shared.started = 1;
    pthread_cond_broadcast(&shared.cond);
    pthread_mutex_unlock(&shared.mutex);

    int failed = 0;
    size_t total_iterations = 0;
    for (size_t i = 0; i < threads; ++i) {
        pthread_join(thread_ids[i], NULL);
        total_iterations += workers[i].completed_iterations;
        if (workers[i].failed) {
            failed = 1;
            fprintf(stderr, "worker %zu failed after %zu iterations: %s\n",
                    i,
                    workers[i].completed_iterations,
                    workers[i].error);
        }
    }

    printf("libbitcoinpqc concurrency harness completed_iterations=%zu\n", total_iterations);

    free(thread_ids);
    free(workers);
    pthread_cond_destroy(&shared.cond);
    pthread_mutex_destroy(&shared.mutex);
    bitcoin_pqc_keypair_free(&shared_keypair);

    if (create_failed) {
        return 1;
    }
    if (failed) {
        return 1;
    }
    if (total_iterations == 0) {
        fprintf(stderr, "no worker iterations completed; cannot provide TSAN coverage\n");
        return 1;
    }

    printf("PASS\n");
    return 0;
}
