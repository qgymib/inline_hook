#include <cstring>
#include "common.hpp"
#include "springboard.hpp"

typedef size_t (*hook_fn)(const char*);

static size_t _hook_strlen(const char* str)
{
    return (size_t)-1;
}

static uhook_token_t s_token;

DISABLE_OPTIMIZE
TEST(inline_hook, shared)
{
    const char* str = "hello world";

    ASSERT_EQ_SIZE(springboard_strlen_c(str), strlen(str));

    ASSERT_EQ_D32(uhook_inject(&s_token, (void*)springboard_strlen_c, (void*)_hook_strlen), 0);
    ASSERT_NE_PTR(s_token.fcall, NULL);

    ASSERT_EQ_SIZE(springboard_strlen_c(str), (size_t)-1);
    ASSERT_EQ_SIZE(((hook_fn)s_token.fcall)(str), strlen(str));

    uhook_uninject(&s_token);
    ASSERT_EQ_SIZE(springboard_strlen_c(str), strlen(str));
}
