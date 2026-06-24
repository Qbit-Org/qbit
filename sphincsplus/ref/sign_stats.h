#ifndef SPX_SIGN_STATS_H
#define SPX_SIGN_STATS_H

#include <stdint.h>

#include "libbitcoinpqc/sign_stats.h"

#ifndef BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS
#define BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS 1835008u
#endif

#ifndef BITCOINPQC_WOTSC_MAX_COUNTER
#define BITCOINPQC_WOTSC_MAX_COUNTER 0xFFFFu
#endif

#if BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS < 1
#error "BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS must be at least 1"
#endif

#if BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS > 0xFFFFFFFFu
#error "BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS must fit in uint32_t"
#endif

#if BITCOINPQC_WOTSC_MAX_COUNTER > 0xFFFFu
#error "BITCOINPQC_WOTSC_MAX_COUNTER must fit in the two-byte WOTS+C counter"
#endif

#define BITCOINPQC_SIGN_LIMIT_EXCEEDED (-100)

void bitcoin_pqc_sign_stats_begin(bitcoin_pqc_sign_stats_t *stats);
void bitcoin_pqc_sign_stats_end(void);
bitcoin_pqc_sign_stats_t *bitcoin_pqc_sign_stats_current(void);
void bitcoin_pqc_sign_stats_record_forsc_attempts(uint32_t attempts);
void bitcoin_pqc_sign_stats_record_forsc_cap(void);
void bitcoin_pqc_sign_stats_record_wotsc_attempts(uint32_t attempts);
void bitcoin_pqc_sign_stats_record_wotsc_cap(void);

#endif /* SPX_SIGN_STATS_H */
