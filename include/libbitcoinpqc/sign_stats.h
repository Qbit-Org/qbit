#ifndef BITCOIN_PQC_SIGN_STATS_H
#define BITCOIN_PQC_SIGN_STATS_H

#include <stdint.h>

/*
 * Current qbit bounded30 profile has SPX_D=5 WOTS+C layers. Keep this fixed in
 * the public stats ABI for the single-profile release surface.
 */
#define BITCOIN_PQC_SIGN_WOTSC_LAYERS 5u

#define BITCOIN_PQC_SIGN_LIMIT_NONE 0u
#define BITCOIN_PQC_SIGN_LIMIT_FORSC 1u
#define BITCOIN_PQC_SIGN_LIMIT_WOTSC 2u

typedef struct {
    uint32_t forsc_attempts;
    uint32_t forsc_max_attempts;
    uint32_t wotsc_attempts[BITCOIN_PQC_SIGN_WOTSC_LAYERS];
    uint32_t wotsc_layer_count;
    uint32_t wotsc_max_attempts;
    uint32_t wotsc_max_observed_attempts;
    uint32_t cap_exceeded;
} bitcoin_pqc_sign_stats_t;

#endif /* BITCOIN_PQC_SIGN_STATS_H */
