#ifndef __INLINE_HOOK_H__
#define __INLINE_HOOK_H__
#ifdef __cplusplus
extern "C" {
#endif

enum inlink_hook_errno
{
    INLINK_HOOK_SUCCESS     = 0,    /**< Success */
    INLINK_HOOK_UNKNOWN     = -1,   /**< Unknown error */
    INLINK_HOOK_NOMEM       = -2,   /**< Not enough space/cannot allocate memory */
    INLINK_HOOK_SMALLFUNC   = -3,   /**< Function is too small to inject inline hook opcode */
    INLINK_HOOK_NOFUNCSIZE  = -4,   /**< Can not get function size, may be stripped? */
};

/**
 * @brief Inject function
 * @param[out] origin       Inject Context, also can be called as original function.
 *                          If failure, this value is set to NULL.
 * @param[in] target        The function to be inject
 * @param[in] detour        The function to replace original function
 * @return                  Inject result
 */
int inline_hook_inject(void** origin, void* target, void* detour);

/**
 * @brief Uninject function
 * @param[in,out] origin    The context to be uninject. This value will be set to NULL.
 */
void inline_hook_uninject(void** origin);

/**
 * @brief Dump information into buffer
 * @param[out] buffer       Buffer to store information
 * @param[in] size          Buffer size
 * @param[in] origin        Inject context
 * @return                  The number of characters printed should have written.
 */
int inline_hook_dump(char* buffer, unsigned size, const void* origin);

#ifdef __cplusplus
}
#endif
#endif
