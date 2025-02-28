cmake_minimum_required(VERSION 3.16)
project(safekeeping VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(SAFEKEEPING_BUILD_TESTS "Build the tests" ON)

# Create the library target
add_library(safekeeping STATIC)

# Add include directory
target_include_directories(safekeeping
    PUBLIC include
    PRIVATE src
)

# Source files for all implementations
target_sources(safekeeping PRIVATE
    src/SafeKeeping.cpp
    src/FileImplStorage.h
    include/safekeeping/SafeKeeping.h
    )

# Platform-specific detection
if(WIN32)
    message(STATUS "Building for Windows: Enabling Windows Credential Manager")
    target_sources(safekeeping PRIVATE src/WinImplStorage.h)
    target_compile_definitions(safekeeping PRIVATE USE_WIN_SECRET_STORAGE)
    target_link_libraries(safekeeping PRIVATE Advapi32)
elseif(APPLE)
    message(STATUS "Building for macOS: Enabling Keychain Services ")
    target_sources(safekeeping PRIVATE src/MacImplStorage.h)
    target_compile_definitions(safekeeping PRIVATE USE_MAC_SECRET_STORAGE)
    target_link_libraries(safekeeping
        PRIVATE
            "-framework Security"
            "-framework CoreFoundation"
    )

elseif(UNIX)
    find_package(PkgConfig REQUIRED)

    # Check for libsecret (GNOME Keyring)
    pkg_check_modules(SECRET REQUIRED libsecret-1)
    if(SECRET_FOUND)
        message(STATUS "Building for Linux: Enabling libsecret (GNOME Keyring)")
        target_sources(safekeeping PRIVATE src/LibSecretImplStorage.h)
        target_compile_definitions(safekeeping PRIVATE USE_LIBSECRET_STORAGE)
        target_include_directories(safekeeping PRIVATE ${SECRET_INCLUDE_DIRS})
        target_link_libraries(safekeeping PRIVATE ${SECRET_LIBRARIES})
    endif()
endif()

# Install headers
install(FILES
    include/safekeeping/safekeeping.h
    DESTINATION include/safekeeping
)

# Install library
install(TARGETS safekeeping LIBRARY DESTINATION lib)

if (SAFEKEEPING_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
