#include <string.h>

#include "sign_stats.h"

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define SPX_SIGN_STATS_THREAD_LOCAL _Thread_local
#elif defined(_MSC_VER)
#define SPX_SIGN_STATS_THREAD_LOCAL __declspec(thread)
#elif defined(__GNUC__) || defined(__clang__)
#define SPX_SIGN_STATS_THREAD_LOCAL __thread
#else
#error "Thread-local storage is required for signing stats isolation on this compiler."
#endif

static SPX_SIGN_STATS_THREAD_LOCAL bitcoin_pqc_sign_stats_t *g_sign_stats = 0;

void bitcoin_pqc_sign_stats_begin(bitcoin_pqc_sign_stats_t *stats)
{
    if (stats) {
        memset(stats, 0, sizeof(*stats));
        stats->forsc_max_attempts = (uint32_t)BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS;
        stats->wotsc_max_attempts = (uint32_t)BITCOINPQC_WOTSC_MAX_COUNTER + 1u;
        stats->cap_exceeded = BITCOIN_PQC_SIGN_LIMIT_NONE;
    }
    g_sign_stats = stats;
}

void bitcoin_pqc_sign_stats_end(void)
{
    g_sign_stats = 0;
}

bitcoin_pqc_sign_stats_t *bitcoin_pqc_sign_stats_current(void)
{
    return g_sign_stats;
}

void bitcoin_pqc_sign_stats_record_forsc_attempts(uint32_t attempts)
{
    bitcoin_pqc_sign_stats_t *stats = bitcoin_pqc_sign_stats_current();
    if (stats) {
        stats->forsc_attempts = attempts;
    }
}

void bitcoin_pqc_sign_stats_record_forsc_cap(void)
{
    bitcoin_pqc_sign_stats_t *stats = bitcoin_pqc_sign_stats_current();
    if (stats) {
        stats->cap_exceeded |= BITCOIN_PQC_SIGN_LIMIT_FORSC;
    }
}

void bitcoin_pqc_sign_stats_record_wotsc_attempts(uint32_t attempts)
{
    bitcoin_pqc_sign_stats_t *stats = bitcoin_pqc_sign_stats_current();
    uint32_t layer;

    if (!stats) {
        return;
    }

    layer = stats->wotsc_layer_count;
    if (layer < BITCOIN_PQC_SIGN_WOTSC_LAYERS) {
        stats->wotsc_attempts[layer] = attempts;
    }
    stats->wotsc_layer_count = layer + 1u;
    if (attempts > stats->wotsc_max_observed_attempts) {
        stats->wotsc_max_observed_attempts = attempts;
    }
}

void bitcoin_pqc_sign_stats_record_wotsc_cap(void)
{
    bitcoin_pqc_sign_stats_t *stats = bitcoin_pqc_sign_stats_current();
    if (stats) {
        stats->cap_exceeded |= BITCOIN_PQC_SIGN_LIMIT_WOTSC;
    }
}
