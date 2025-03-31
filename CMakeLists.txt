cmake_minimum_required(VERSION 3.10)
project(keystroke_defense_client)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include JSON header
include_directories(${CMAKE_SOURCE_DIR}/external)

# Executable
add_executable(keystroke_defense_client main.cpp)

# Link Windows + pthread libraries
target_link_libraries(keystroke_defense_client
    setupapi
    hid
    crypt32
    user32
    gdi32
    advapi32
    pthread
)
