#include "common.hpp"
#include <cstring>

#include "separation.hpp"
#include <dlfcn.h>

extern "C" void uhook_dump_phdr(void);

static uhook_token_t s_token;

static size_t _hook_strlen(const char* str)
{
    return (size_t)-1;
}

DISABLE_OPTIMIZE
TEST(pltgot, separation)
{
    const char* str = "hello world";
    const size_t str_len = strlen(str);

    void* shared_hanle = dlopen("libseparation.so", RTLD_LAZY);
    ASSERT_NE_PTR(shared_hanle, NULL);

    separation_strlen_fn fn_addr = (separation_strlen_fn)dlsym(shared_hanle, "separation_strlen_c");
    ASSERT_NE_PTR(fn_addr, NULL);

    ASSERT_EQ_SIZE(fn_addr(str), str_len);

    uhook_dump_phdr();

    ASSERT_EQ_D32(uhook_inject_got(&s_token, "separation_strlen_c", (void*)_hook_strlen), 0);
    ASSERT_NE_PTR(s_token.fcall, NULL);

    ASSERT_EQ_SIZE(fn_addr(str), (size_t)-1);
    ASSERT_EQ_SIZE(((separation_strlen_fn)s_token.fcall)(str), str_len);

    uhook_uninject(&s_token);
    ASSERT_EQ_SIZE(fn_addr(str), str_len);

    ASSERT_EQ_D32(dlclose(shared_hanle), 0);
}
