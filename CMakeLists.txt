cmake_minimum_required(VERSION 3.16)
project(Sentinel)

# -----------------------------------------------------------------------
# Sentinel Security — CMake build for HashLink/C → native macOS binary
#
# Prerequisites:
#   brew install hashlink
#   haxe build-hlc.hxml   (generates build/hlc/sentinel.c first)
#
# Build:
#   mkdir -p build/hlc && cd build/hlc
#   cmake ../.. -G Ninja   (or -G "Unix Makefiles")
#   ninja   (or make)
#   ./sentinel
# -----------------------------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0")

# Find HashLink installation (via Homebrew typically)
find_library(HL_LIB hl PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)
find_path(HL_INCLUDE hl.h PATHS /opt/homebrew/include /usr/local/include REQUIRED)

# HashLink/C emitted sources
file(GLOB HL_C_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/*.c")

add_executable(sentinel
    ${HL_C_SOURCES}
)

target_include_directories(sentinel PRIVATE
    ${HL_INCLUDE}
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(sentinel PRIVATE
    ${HL_LIB}
)

# macOS frameworks for notifications and security
target_link_libraries(sentinel PRIVATE
    "-framework Foundation"
    "-framework Security"
    "-framework CoreFoundation"
)

# Optimization flags for release build
target_compile_options(sentinel PRIVATE
    $<$<CONFIG:Release>:-O3 -flto>
    $<$<CONFIG:Debug>:-g -fsanitize=address>
)

# Code sign the output (requires Apple Developer account)
# Uncomment and set your team ID:
# add_custom_command(TARGET sentinel POST_BUILD
#     COMMAND codesign --force --sign "Developer ID Application: Your Name (TEAMID)"
#             --entitlements "${CMAKE_SOURCE_DIR}/sentinel.entitlements"
#             $<TARGET_FILE:sentinel>
#     COMMENT "Code signing Sentinel..."
# )

message(STATUS "HashLink: ${HL_LIB}")
message(STATUS "HL include: ${HL_INCLUDE}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
