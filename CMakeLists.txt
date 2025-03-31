cmake_minimum_required(VERSION 3.15)
project(keystroke_defense_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(THREADS_PREFER_PTHREAD_FLAG OFF)
endif()

find_package(Threads REQUIRED)

add_executable(keystroke_defense_client WIN32
    main.cpp
)

target_link_libraries(keystroke_defense_client PRIVATE
    setupapi
    hid
    crypt32
    Threads::Threads
)

set_target_properties(keystroke_defense_client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
