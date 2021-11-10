#ifndef __UHOOK_H__
#define __UHOOK_H__
#ifdef __cplusplus
extern "C" {
#endif

enum uhook_errno
{
    UHOOK_SUCCESS       = 0,    /**< Success */
    UHOOK_UNKNOWN       = -1,   /**< Unknown error */
    UHOOK_NOMEM         = -2,   /**< Not enough space/cannot allocate memory */
    UHOOK_SMALLFUNC     = -3,   /**< Function is too small to inject inline hook opcode */
    UHOOK_NOFUNCSIZE    = -4,   /**< Can not get function size, may be stripped? */
};

typedef struct uhook_token
{
    void*   fn_call;    /**< Original function, cast to original protocol to call it. */
    void*   token;      /**< Inject token */
}uhook_token_t;

/**
 * @brief Inject function
 * @param[out] origin       Inject Context, also can be called as original function.
 *                          If failure, this value is set to NULL.
 * @param[in] target        The function to be inject
 * @param[in] detour        The function to replace original function
 * @return                  Inject result
 */
int uhook_inject(uhook_token_t* token, void* target, void* detour);

/**
 * @brief Uninject function
 * @param[in,out] origin    The context to be uninject. This value will be set to NULL.
 */
void uhook_uninject(uhook_token_t* token);

#ifdef __cplusplus
}
#endif
#endif
