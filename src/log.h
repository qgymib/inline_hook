#ifndef __INLINE_HOOK_LOG_H__
#define __INLINE_HOOK_LOG_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "defs.h"

#if defined(INLINE_HOOK_DEBUG)
#   define LOG(fmt, ...)   printf("[%s:%d] " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#   define LOG(fmt, ...)   do {} while (0)
#endif

/**
 * @brief Dump hex data
 * @param[in] data	The data pointer
 * @param[in] size	The data size
 * @param[in] width	The amount of bytes one line contains
 */
API_LOCAL void dump_hex(const void* data, size_t size, size_t width);

#ifdef __cplusplus
}
#endif
#endif
