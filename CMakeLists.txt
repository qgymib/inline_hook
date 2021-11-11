cmake_minimum_required(VERSION 3.3)
project(uhook)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

add_library(${PROJECT_NAME}
    "src/os/os.c"
    "src/log.c"
    "src/once.c"
    "src/uhook.c")

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else ()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror)
endif ()

# arch specific
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    target_sources(${PROJECT_NAME} PRIVATE
            "src/arch/x86_64.c")
    add_subdirectory("third_party/zydis")
    target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l")
    target_sources(${PROJECT_NAME} PRIVATE
            "src/arch/arm.c")
endif()

# os specific
if (UNIX)
    target_sources(${PROJECT_NAME} PRIVATE
            "src/os/elfparser.c"
            "src/os/elf.c")
endif ()

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory("third_party/cunittest")
    add_subdirectory(test)
endif()
