#ifndef __TEST_H__
#define __TEST_H__
#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#	define _CRTDBG_MAP_ALLOC
#	include <stdlib.h>
#	include <crtdbg.h>
#	include <windows.h>
#	define TEST_BREAK_POINT()		DebugBreak()
#	define TEST_SETUP	\
        _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);\
        _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);\
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);\
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);\
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);\
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR)
#	define TEST_TEARDOWN	\
        _CrtDumpMemoryLeaks()
#	define TEST_SSCANF(str, fmt, ...)	\
        sscanf_s(str, fmt, ##__VA_ARGS__)
#else
#	include <stdlib.h>
#	if !defined(__native_client__) \
        && (defined(__clang__) || defined(__GNUC__)) && (defined(__x86_64__) || defined(__i386__))
#		define TEST_BREAK_POINT()	asm("int3")
#	else
#		define TEST_BREAK_POINT()	*(volatile int*)NULL = 1
#	endif
#	define TEST_SETUP				(void)0
#	define TEST_TEARDOWN			(void)0
#	define TEST_SSCANF(str, fmt, ...)	\
        sscanf(str, fmt, ##__VA_ARGS__)
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>

#define TEST_EXPAND(x)				x
#define TEST_JOIN(a, b)				TEST_JOIN2(a, b)
#define TEST_JOIN2(a, b)			a##b

#ifdef _MSC_VER // Microsoft compilers
#	define TEST_ARG_COUNT(...)  INTERNAL_EXPAND_ARGS_PRIVATE(INTERNAL_ARGS_AUGMENTER(__VA_ARGS__))
#	define INTERNAL_ARGS_AUGMENTER(...) unused, __VA_ARGS__
#	define INTERNAL_EXPAND(x) x
#	define INTERNAL_EXPAND_ARGS_PRIVATE(...) INTERNAL_EXPAND(INTERNAL_GET_ARG_COUNT_PRIVATE(__VA_ARGS__, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))
#	define INTERNAL_GET_ARG_COUNT_PRIVATE(_1_, _2_, _3_, _4_, _5_, _6_, _7_, _8_, _9_, _10_, _11_, _12_, _13_, _14_, _15_, _16_, count, ...) count
#else // Non-Microsoft compilers
#	define TEST_ARG_COUNT(...) INTERNAL_GET_ARG_COUNT_PRIVATE(0, ## __VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#	define INTERNAL_GET_ARG_COUNT_PRIVATE(_0, _1_, _2_, _3_, _4_, _5_, _6_, _7_, _8_, _9_, _10_, _11_, _12_, _13_, _14_, _15_, _16_, count, ...) count
#endif

#define ASSERT_FAILURE(fmt, ...)	\
    do {\
        fprintf(stderr, "Assertion failed in %s on line %d:" fmt "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__);\
        fflush(stderr);\
        if (__test_ctx.mask.break_on_failure){\
            TEST_BREAK_POINT();\
        }\
        longjmp(__test_jmp, EXIT_FAILURE);\
    } while (0)

#define ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, u_fmt, ...)	\
    do {\
        TYPE _l = (TYPE)(a); TYPE _r = (TYPE)(b);\
        if (CMP(_l, _r)) {\
            break;\
        }\
        fprintf(stderr, "%s:%d:failure:" u_fmt "\n"\
            "            expected:    `%s' %s `%s'\n"\
            "              actual:    " FMT " vs " FMT "\n",\
            __FILE__, __LINE__, ##__VA_ARGS__, #a, #OP, #b, _l, _r);\
        fflush(stderr);\
        if (__test_ctx.mask.break_on_failure){\
            TEST_BREAK_POINT();\
        }\
        longjmp(__test_jmp, EXIT_FAILURE);\
    } while(0)

#define ASSERT_EQ_STR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const char*, "%s", ==, !strcmp, a, b, ##__VA_ARGS__)
#define ASSERT_NE_STR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const char*, "%s", !=,  strcmp, a, b, ##__VA_ARGS__)

#define ASSERT_EQ_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", ==, _ASSERT_INTERNAL_HELPER_EQ, a, b, ##__VA_ARGS__)
#define ASSERT_NE_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", !=, _ASSERT_INTERNAL_HELPER_NE, a, b, ##__VA_ARGS__)
#define ASSERT_LT_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", <, _ASSERT_INTERNAL_HELPER_LT, a, b, ##__VA_ARGS__)
#define ASSERT_GT_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", >, _ASSERT_INTERNAL_HELPER_GT, a, b, ##__VA_ARGS__)
#define ASSERT_LE_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", <=, _ASSERT_INTERNAL_HELPER_LE, a, b, ##__VA_ARGS__)
#define ASSERT_GE_PTR(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(const void*, "%p", >=, _ASSERT_INTERNAL_HELPER_GE, a, b, ##__VA_ARGS__)

#define ASSERT_EQ_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32, ==, _ASSERT_INTERNAL_HELPER_EQ, a, b, ##__VA_ARGS__)
#define ASSERT_NE_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32, !=, _ASSERT_INTERNAL_HELPER_NE, a, b, ##__VA_ARGS__)
#define ASSERT_LT_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32,  <, _ASSERT_INTERNAL_HELPER_LT, a, b, ##__VA_ARGS__)
#define ASSERT_GT_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32,  >, _ASSERT_INTERNAL_HELPER_GT, a, b, ##__VA_ARGS__)
#define ASSERT_LE_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32, <=, _ASSERT_INTERNAL_HELPER_LE, a, b, ##__VA_ARGS__)
#define ASSERT_GE_D32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int32_t, "%" PRId32, >=, _ASSERT_INTERNAL_HELPER_GE, a, b, ##__VA_ARGS__)

#define ASSERT_EQ_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32, ==, _ASSERT_INTERNAL_HELPER_EQ, a, b, ##__VA_ARGS__)
#define ASSERT_NE_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32, !=, _ASSERT_INTERNAL_HELPER_NE, a, b, ##__VA_ARGS__)
#define ASSERT_LT_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32,  <, _ASSERT_INTERNAL_HELPER_LT, a, b, ##__VA_ARGS__)
#define ASSERT_GT_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32,  >, _ASSERT_INTERNAL_HELPER_GT, a, b, ##__VA_ARGS__)
#define ASSERT_LE_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32, <=, _ASSERT_INTERNAL_HELPER_LE, a, b, ##__VA_ARGS__)
#define ASSERT_GE_U32(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint32_t, "%" PRIu32, >=, _ASSERT_INTERNAL_HELPER_GE, a, b, ##__VA_ARGS__)

#define ASSERT_EQ_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64, ==, _ASSERT_INTERNAL_HELPER_EQ, a, b, ##__VA_ARGS__)
#define ASSERT_NE_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64, !=, _ASSERT_INTERNAL_HELPER_NE, a, b, ##__VA_ARGS__)
#define ASSERT_LT_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64,  <, _ASSERT_INTERNAL_HELPER_LT, a, b, ##__VA_ARGS__)
#define ASSERT_GT_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64,  >, _ASSERT_INTERNAL_HELPER_GT, a, b, ##__VA_ARGS__)
#define ASSERT_LE_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64, <=, _ASSERT_INTERNAL_HELPER_LE, a, b, ##__VA_ARGS__)
#define ASSERT_GE_D64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(int64_t, "%" PRId64, >=, _ASSERT_INTERNAL_HELPER_GE, a, b, ##__VA_ARGS__)

#define ASSERT_EQ_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64, ==, _ASSERT_INTERNAL_HELPER_EQ, a, b, ##__VA_ARGS__)
#define ASSERT_NE_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64, !=, _ASSERT_INTERNAL_HELPER_NE, a, b, ##__VA_ARGS__)
#define ASSERT_LT_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64,  <, _ASSERT_INTERNAL_HELPER_LT, a, b, ##__VA_ARGS__)
#define ASSERT_GT_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64,  >, _ASSERT_INTERNAL_HELPER_GT, a, b, ##__VA_ARGS__)
#define ASSERT_LE_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64, <=, _ASSERT_INTERNAL_HELPER_LE, a, b, ##__VA_ARGS__)
#define ASSERT_GE_U64(a, b, ...)	ASSERT_TEMPLATE_VA(__VA_ARGS__)(uint64_t, "%" PRIu64, >=, _ASSERT_INTERNAL_HELPER_GE, a, b, ##__VA_ARGS__)

#define ASSERT_TEMPLATE_VA(...)									TEST_JOIN(ASSERT_TEMPLATE_VA_, TEST_ARG_COUNT(__VA_ARGS__))
#define ASSERT_TEMPLATE_VA_0(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_1(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_2(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_3(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_4(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_5(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_6(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_7(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_8(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))
#define ASSERT_TEMPLATE_VA_9(TYPE, FMT, OP, CMP, a, b, ...)		TEST_EXPAND(ASSERT_TEMPLATE(TYPE, FMT, OP, CMP, a, b, __VA_ARGS__))

#define _ASSERT_INTERNAL_HELPER_EQ(a, b)						((a) == (b))
#define _ASSERT_INTERNAL_HELPER_NE(a, b)						((a) != (b))
#define _ASSERT_INTERNAL_HELPER_LT(a, b)						((a) < (b))
#define _ASSERT_INTERNAL_HELPER_LE(a, b)						((a) <= (b))
#define _ASSERT_INTERNAL_HELPER_GT(a, b)						((a) > (b))
#define _ASSERT_INTERNAL_HELPER_GE(a, b)						((a) >= (b))

#define TEST(name)	\
    static void run_test_##name(void);\
    test_global_ctx_t	__test_ctx = { 0, NULL, EXIT_SUCCESS, { 0 } };\
    jmp_buf				__test_jmp;\
    int main(int argc, char* argv[]) {\
        __test_ctx.argc = argc; __test_ctx.argv = argv;\
        {\
            int i, v;\
            for (i = 0; i < argc; i++) {\
                if (TEST_SSCANF(argv[i], "--test_break_on_failure=%d", &v) == 1) {\
                    __test_ctx.mask.break_on_failure = !!v;\
                }\
            }\
        }\
        TEST_SETUP;\
        if ((__test_ctx.exit_code = setjmp(__test_jmp)) == 0) {\
            run_test_##name();\
        }\
        TEST_TEARDOWN;\
        return __test_ctx.exit_code;\
    }\
    static void run_test_##name(void)

#define TEST_ARGC			(__test_ctx.argc)
#define TEST_ARGV			(__test_ctx.argv)
#define TEST_EXIT_CODE		(__test_ctx.exit_code)

typedef struct test_global_ctx
{
    int				argc;
    char**			argv;
    int				exit_code;
    struct
    {
        unsigned	break_on_failure : 1;
    }mask;
}test_global_ctx_t;

extern test_global_ctx_t	__test_ctx;
extern jmp_buf				__test_jmp;

#ifdef __cplusplus
}
#endif
#endif