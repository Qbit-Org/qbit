#ifndef SPX_OPT_FLAGS_H
#define SPX_OPT_FLAGS_H

#include <stdlib.h>
#include <string.h>

#if defined(SPX_PRODUCTION_BUILD) && defined(SPX_ENABLE_TEST_BENCH_ENV_KNOBS)
#error "SPX_PRODUCTION_BUILD cannot be combined with SPX_ENABLE_TEST_BENCH_ENV_KNOBS"
#endif

#if defined(SPX_ENABLE_TEST_BENCH_ENV_KNOBS)
#define SPX_RUNTIME_ENV_KNOBS_ENABLED 1
#else
#define SPX_RUNTIME_ENV_KNOBS_ENABLED 0
#endif

#if defined(__clang__) || defined(__GNUC__)
#define SPX_OPT_ATOMIC_LOAD(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define SPX_OPT_ATOMIC_STORE(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELAXED)
#else
#define SPX_OPT_ATOMIC_LOAD(ptr) (*(ptr))
#define SPX_OPT_ATOMIC_STORE(ptr, value) (*(ptr) = (value))
#endif

static inline int spx_env_flag(const char *name)
{
#if !SPX_RUNTIME_ENV_KNOBS_ENABLED
    (void)name;
    return 0;
#else
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    if (strcmp(value, "1") == 0 ||
        strcmp(value, "true") == 0 ||
        strcmp(value, "TRUE") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "YES") == 0 ||
        strcmp(value, "on") == 0 ||
        strcmp(value, "ON") == 0) {
        return 1;
    }

    return 0;
#endif
}

static inline int spx_opt_profile_is(const char *profile)
{
#if !SPX_RUNTIME_ENV_KNOBS_ENABLED
    (void)profile;
    return 0;
#else
    const char *configured = getenv("SPX_OPT_PROFILE");
    if (configured == NULL || configured[0] == '\0') {
        return 0;
    }
    return strcmp(configured, profile) == 0;
#endif
}

static inline int spx_opt_disable_sha_accel(void)
{
    static int cached = -1;
    int value = SPX_OPT_ATOMIC_LOAD(&cached);

    if (value < 0) {
        value = 0;
        if (spx_env_flag("SPX_DISABLE_SHA_ACCEL") ||
            spx_opt_profile_is("scalar")) {
            value = 1;
        }
        SPX_OPT_ATOMIC_STORE(&cached, value);
    }

    return value;
}

static inline int spx_opt_disable_simd(void)
{
    static int cached = -1;
    int value = SPX_OPT_ATOMIC_LOAD(&cached);

    if (value < 0) {
        value = 0;
        if (spx_env_flag("SPX_DISABLE_SIMD") ||
            spx_opt_profile_is("scalar")) {
            value = 1;
        }
        SPX_OPT_ATOMIC_STORE(&cached, value);
    }

    return value;
}

enum {
    SPX_SHA_BACKEND_AUTO = 0,
    SPX_SHA_BACKEND_SCALAR = 1,
    SPX_SHA_BACKEND_ARM = 2,
    SPX_SHA_BACKEND_X86 = 3,
    SPX_SHA_BACKEND_COMMONCRYPTO = 4
};

static inline int spx_opt_sha_backend_mode(void)
{
#if defined(SPX_PRODUCTION_BUILD)
    return SPX_SHA_BACKEND_SCALAR;
#elif !SPX_RUNTIME_ENV_KNOBS_ENABLED
    return SPX_SHA_BACKEND_AUTO;
#else
    static int cached = -1;
    int value = SPX_OPT_ATOMIC_LOAD(&cached);
    const char *configured;

    if (value >= 0) {
        return value;
    }

    value = SPX_SHA_BACKEND_AUTO;
    configured = getenv("SPX_SHA_BACKEND");
    if (configured != NULL && configured[0] != '\0') {
        if (strcmp(configured, "scalar") == 0 ||
            strcmp(configured, "ref") == 0) {
            value = SPX_SHA_BACKEND_SCALAR;
        } else if (strcmp(configured, "arm") == 0 ||
                   strcmp(configured, "armv8") == 0 ||
                   strcmp(configured, "armv8_sha256") == 0) {
            value = SPX_SHA_BACKEND_ARM;
        } else if (strcmp(configured, "x86") == 0 ||
                   strcmp(configured, "x86_ni") == 0 ||
                   strcmp(configured, "shani") == 0) {
            value = SPX_SHA_BACKEND_X86;
        } else if (strcmp(configured, "commoncrypto") == 0 ||
                   strcmp(configured, "cc") == 0) {
            value = SPX_SHA_BACKEND_COMMONCRYPTO;
        } else if (strcmp(configured, "auto") == 0) {
            value = SPX_SHA_BACKEND_AUTO;
        }
    }

    SPX_OPT_ATOMIC_STORE(&cached, value);
    return value;
#endif
}

#endif
