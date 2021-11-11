add_executable(unittest
    "main.c"
    "inline_callback.cpp"
    "inline_loop.cpp"
    "inline_simple.cpp")
target_link_libraries(unittest PRIVATE cunittest uhook)
add_test(UnitTest unittest)
