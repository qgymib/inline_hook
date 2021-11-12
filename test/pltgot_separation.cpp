#include "common.hpp"
#include <cstring>

#include "separation.hpp"
#include <dlfcn.h>

static uhook_token_t s_token;

static size_t _hook_strlen(const char* str)
{
    return (size_t)-1;
}

DISABLE_OPTIMIZE
TEST(pltgot, separation)
{
    void* shared_hanle = dlopen("libseparation.so", RTLD_LAZY);
    ASSERT_NE_PTR(shared_hanle, NULL);

    separation_strlen_fn fn_addr = (separation_strlen_fn)dlsym(shared_hanle, "separation_strlen_c");
    ASSERT_NE_PTR(fn_addr, NULL);

    ASSERT_LT_D32(uhook_inject_got(&s_token, "separation_strlen_c", (void*)_hook_strlen), 0);

    ASSERT_EQ_D32(dlclose(shared_hanle), 0);
}
