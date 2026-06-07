# ==============================================================================
# YaNet — A Peer-to-Peer Virtual Network
# CMakeLists.txt — Build Configuration
# ==============================================================================

cmake_minimum_required(VERSION 3.16)
project(YaNet VERSION 0.1.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ==============================================================================
# Platform Detection
# ==============================================================================

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-DSODIUM_STATIC)
endif()

# ==============================================================================
# libsodium
# ==============================================================================

if(WIN32)
    set(SODIUM_ROOT "${CMAKE_SOURCE_DIR}/ext/libsodium/libsodium")
    set(SODIUM_INCLUDE_DIR "${SODIUM_ROOT}/include")

    # Auto-detect MSVC toolset version
    if(MSVC_VERSION GREATER_EQUAL 1930)
        set(SODIUM_TOOLSET "v143")
    elseif(MSVC_VERSION GREATER_EQUAL 1920)
        set(SODIUM_TOOLSET "v142")
    else()
        set(SODIUM_TOOLSET "v142")
    endif()

    # Select architecture
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(SODIUM_ARCH "x64")
    else()
        set(SODIUM_ARCH "Win32")
    endif()

    set(SODIUM_LIB_DIR "${SODIUM_ROOT}/${SODIUM_ARCH}/Release/${SODIUM_TOOLSET}/static")
    set(SODIUM_LIBRARY "${SODIUM_LIB_DIR}/libsodium.lib")

    message(STATUS "libsodium include: ${SODIUM_INCLUDE_DIR}")
    message(STATUS "libsodium library: ${SODIUM_LIBRARY}")

    # Verify libsodium exists
    if(NOT EXISTS "${SODIUM_LIBRARY}")
        message(FATAL_ERROR "libsodium not found at ${SODIUM_LIBRARY}. "
            "Please download and extract to ext/libsodium/")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    set(SODIUM_INCLUDE_DIR ${SODIUM_INCLUDE_DIRS})
    set(SODIUM_LIBRARY ${SODIUM_LIBRARIES})
endif()

# ==============================================================================
# Core Library (shared across executables)
# ==============================================================================

add_library(yanet_core STATIC
    src/core/identity.cpp
    src/core/crypto.cpp
    src/core/transport.cpp
    src/core/packet.cpp
    src/core/peer.cpp
)

target_include_directories(yanet_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIR}
)

target_link_libraries(yanet_core PUBLIC
    ${SODIUM_LIBRARY}
)

if(WIN32)
    target_link_libraries(yanet_core PUBLIC ws2_32 advapi32)
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(yanet_core PRIVATE /W4 /WX-)
else()
    target_compile_options(yanet_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ==============================================================================
# Main Executable — yanet.exe
# ==============================================================================

add_executable(yanet src/main.cpp)
target_link_libraries(yanet PRIVATE yanet_core)

# ==============================================================================
# Tests (optional, build with -DBUILD_TESTS=ON)
# ==============================================================================

option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    enable_testing()

    # Test: Identity
    add_executable(test_identity tests/test_identity.cpp)
    target_link_libraries(test_identity PRIVATE yanet_core)
    add_test(NAME IdentityTest COMMAND test_identity)

    # Test: Crypto
    add_executable(test_crypto tests/test_crypto.cpp)
    target_link_libraries(test_crypto PRIVATE yanet_core)
    add_test(NAME CryptoTest COMMAND test_crypto)

    # Test: Packet
    add_executable(test_packet tests/test_packet.cpp)
    target_link_libraries(test_packet PRIVATE yanet_core)
    add_test(NAME PacketTest COMMAND test_packet)
endif()

# ==============================================================================
# Install
# ==============================================================================

install(TARGETS yanet DESTINATION bin)
install(DIRECTORY include/yanet DESTINATION include)
