#include "common.h"
#include "springboard.hpp"

typedef int (*hook_fn)(int, int);

static int _hook_del(int a, int b)
{
    return a - b;
}

static uhook_token_t s_token;

DISABLE_OPTIMIZE
TEST(inline_hook, shared)
{
    ASSERT_EQ_D32(springboard_add_c(1, 2), 3);

    ASSERT_EQ_D32(uhook_inject(&s_token, (void*)springboard_add_c, (void*)_hook_del), 0);
    ASSERT_NE_PTR(s_token.fcall, NULL);

    ASSERT_EQ_D32(springboard_add_c(1, 2), -1);
    ASSERT_EQ_D32(((hook_fn)s_token.fcall)(1, 2), 3);

    uhook_uninject(&s_token);
    ASSERT_EQ_D32(springboard_add_c(1, 2), 3);
}
