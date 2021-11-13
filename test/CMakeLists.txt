add_library(springboard SHARED "springboard.cpp")
add_library(separation SHARED "separation.cpp")

add_executable(unittest
    "main.c"
    "inline_callback.cpp"
    "inline_loop.cpp"
    "inline_shared.cpp"
    "inline_simple.cpp"
    "pltgot_malloc.cpp"
    "pltgot_separation.cpp"
    "pltgot_shared.cpp")
target_link_libraries(unittest PRIVATE cutest uhook springboard dl)
add_test(UnitTest unittest)
