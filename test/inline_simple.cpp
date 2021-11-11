#include "common.hpp"

typedef int(*fn_sig)(int, int);

static int add(int a, int b)
{
    return a + b;
}

static int del(int a, int b)
{
    return a - b;
}

DISABLE_OPTIMIZE
TEST(inline_hook, simple)
{
    ASSERT_EQ_D32(add(1, 2), 3);

    uhook_token_t token;
    ASSERT_EQ_D32(uhook_inject(&token, (void*)add, (void*)del), 0);
    ASSERT_NE_PTR(token.fcall, NULL);

    ASSERT_EQ_D32(add(1, 2), -1);
    ASSERT_EQ_D32(((fn_sig)token.fcall)(1, 2), 3);

    uhook_uninject(&token);
    ASSERT_EQ_D32(add(1, 2), 3);
}
