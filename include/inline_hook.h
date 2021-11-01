#ifndef __INLINE_HOOK_H__
#define __INLINE_HOOK_H__
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inject function
 * @param[out] origin   Inject Context, also can be called as original function.
 *                      If failure, this value is set to NULL.
 * @param[in] target    The function to be inject
 * @param[in] detour    The function to replace orignal function
 * @return              Inject result
 */
int inline_hook_inject(void** origin, void* target, void* detour);

/**
 * @brief Uninject function
 * @param[in,out] tump The context to be uninject. This value will be set to NULL.
 */
void inline_hook_uninject(void** origin);

#ifdef __cplusplus
}
#endif
#endif

