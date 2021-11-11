add_executable(unittest
    "main.c"
    "test_callback.cpp"
    "test_loop.cpp"
    "test_simple.cpp")
target_link_libraries(unittest PRIVATE cunittest uhook)
add_test(UnitTest unittest)
