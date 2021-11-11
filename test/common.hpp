#ifndef __TEST_COMMON_HPP__
#define __TEST_COMMON_HPP__
#ifdef __cplusplus
extern "C" {
#endif

#include "cunittest.h"
#include "uhook.h"
#include <stdio.h>

#if defined(__GNUC__) || defined(__clang__)
#   define DISABLE_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(_MSC_VER)
#   define DISABLE_OPTIMIZE __pragma(optimize("", off))
#else
#   define DISABLE_OPTIMIZE
#endif

#ifdef __cplusplus
}
#endif

class common
{
public:
    static void print_file(const char* file)
    {
        FILE* p_file = fopen(file, "rb");
        if (p_file == NULL)
        {
            return;
        }

        char buffer[1024];
        while (!feof(p_file))
        {
            size_t read_size = fread(buffer, 1, sizeof(buffer) - 1, p_file);
            buffer[read_size] = '\0';
            printf("%s", buffer);
        }

        fclose(p_file);
    }
};



#endif
