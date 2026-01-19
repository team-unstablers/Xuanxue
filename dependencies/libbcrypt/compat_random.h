/*
 * compat_random.h - Platform-safe random bytes generation
 *
 * Provides a wrapper for getentropy(2) that works across platforms:
 * - iOS: Uses Security.framework's SecRandomCopyBytes
 * - macOS, Linux: Uses native getentropy from sys/random.h
 */
#ifndef COMPAT_RANDOM_H
#define COMPAT_RANDOM_H

#include <stddef.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if defined(__APPLE__) && TARGET_OS_IPHONE
/* iOS: Use Security.framework */
#include <Security/SecRandom.h>

static inline int compat_getentropy(void *buf, size_t buflen) {
    if (SecRandomCopyBytes(kSecRandomDefault, buflen, buf) == errSecSuccess) {
        return 0;
    }
    return -1;
}

#else
/* macOS, Linux, etc: Use native getentropy */
#include <sys/random.h>

static inline int compat_getentropy(void *buf, size_t buflen) {
    return getentropy(buf, buflen);
}

#endif

#endif /* COMPAT_RANDOM_H */
