#ifndef __SEPARATION__HPP__
#define __SEPARATION__HPP__

#include <cstddef>

typedef size_t(*separation_strlen_fn)(const char*);

extern "C" size_t separation_strlen_c(const char* str);

#endif
