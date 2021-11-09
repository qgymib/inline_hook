#ifndef __TEST_COMMON_H__
#define __TEST_COMMON_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "test.h"
#include "inlinehook.h"
#include <stdio.h>

#if defined(__GNUC__) || defined(__clang__)
#   define DISABLE_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(_MSC_VER)
#   define DISABLE_OPTIMIZE	__pragma(optimize("", off))
#else
#   define DISABLE_OPTIMIZE
#endif

#ifdef __cplusplus
}
#endif
#endif
