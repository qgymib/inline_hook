#ifndef __INLINE_HOOK_DEFS_H__
#define __INLINE_HOOK_DEFS_H__
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#	define API_LOCAL	__attribute__((visibility("hidden")))
#else
#	define API_LOCAL
#endif

#ifdef __cplusplus
}
#endif
#endif
