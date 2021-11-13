#include "common.hpp"
#include <cstdlib>
#include <cstring>

static uhook_token_t s_token;

typedef void* (*fn_malloc)(size_t);

static void* s_expect_retval = (void*)0x01;

static void* my_malloc(size_t size)
{
    return s_expect_retval;
}

DISABLE_OPTIMIZE
TEST(pltgot, malloc)
{
    common::print_file("/proc/self/maps");
    uhook_dump_phdr("*libc.so.6");

    ASSERT_EQ_D32(uhook_inject_got(&s_token, "malloc", (void*)my_malloc), 0);
    ASSERT_NE_PTR(s_token.fcall, NULL);

    ASSERT_EQ_PTR(malloc(sizeof(void*)), s_expect_retval);

    {
        void* ptr = ((fn_malloc)s_token.fcall)(sizeof(void*));
        ASSERT_NE_PTR(ptr, NULL);
        free(ptr);
    }

    uhook_uninject(&s_token);

    {
        void* ptr = malloc(sizeof(void*));
        ASSERT_NE_PTR(ptr, NULL);
        free(ptr);
    }
}
