function(ADD_TEST_CASE name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE ${PROJECT_NAME})
    add_test(${name} ${name})
endfunction()

ADD_TEST_CASE(test_simple)
