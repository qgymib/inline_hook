#include "common.hpp"
#include "springboard.hpp"
#include <cstring>

static uhook_token_t s_token;

static size_t _hook_strlen(const char* str)
{
    return (size_t)-1;
}

DISABLE_OPTIMIZE
TEST(pltgot, dependency)
{
    const char* str = "hello world";
    const size_t str_len = strlen(str);

    ASSERT_EQ_SIZE(springboard_strlen_c(str), str_len);

    ASSERT_EQ_D32(uhook_inject_got(&s_token, "springboard_strlen_c", (void*)_hook_strlen), 0);
    ASSERT_NE_PTR(s_token.fcall, NULL);

    ASSERT_EQ_SIZE(springboard_strlen_c(str), (size_t)-1);

    uhook_uninject(&s_token);
    ASSERT_EQ_SIZE(springboard_strlen_c(str), str_len);
}
