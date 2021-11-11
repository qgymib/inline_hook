add_library(springboard SHARED "springboard.cpp")

add_executable(unittest
    "main.c"
    "inline_callback.cpp"
    "inline_loop.cpp"
    "inline_shared.cpp"
    "inline_simple.cpp")
target_link_libraries(unittest PRIVATE cutest uhook springboard)
add_test(UnitTest unittest)
