#ifndef LIBBITCOINPQC_SECURE_ZERO_H
#define LIBBITCOINPQC_SECURE_ZERO_H

#include <stddef.h>

static inline void bitcoin_pqc_secure_zero(void *ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len > 0) {
        *p++ = 0;
        len--;
    }
}

#endif /* LIBBITCOINPQC_SECURE_ZERO_H */
