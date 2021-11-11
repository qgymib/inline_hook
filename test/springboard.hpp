#ifndef __TEST_SPRING_BOARD_HPP__
#define __TEST_SPRING_BOARD_HPP__

#include <cstddef>

typedef size_t(*springboard_strlen_fn)(const char*);

extern "C" size_t springboard_strlen_c(const char* str);

#endif
