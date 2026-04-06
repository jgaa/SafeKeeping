cmake_minimum_required(VERSION 3.20)
project(safekeeping VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SAFEKEEPING_BUILD_TESTS "Build the tests" ON)

find_package(SQLite3 REQUIRED)

find_package(SQLite3 REQUIRED)

if(NOT TARGET SQLite3::SQLite3 AND TARGET SQLite::SQLite3)
    add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
endif()

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium libsodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium was not found")
endif()

add_library(safekeeping STATIC
    src/SafeKeeping.cpp
    include/safekeeping/SafeKeeping.h
)

target_include_directories(safekeeping
    PUBLIC
        include
    PRIVATE
        src
        ${SODIUM_INCLUDE_DIR}
)

target_link_libraries(safekeeping
    PRIVATE
        ${SODIUM_LIBRARY}
        SQLite3::SQLite3
)

if(WIN32)
    target_link_libraries(safekeeping PRIVATE Advapi32)
elseif(APPLE)
    target_link_libraries(
        safekeeping
        PRIVATE
            "-framework Security"
            "-framework CoreFoundation"
    )
elseif(UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SECRET REQUIRED IMPORTED_TARGET libsecret-1)
    pkg_check_modules(DBUS REQUIRED IMPORTED_TARGET dbus-1)
    target_link_libraries(safekeeping PRIVATE PkgConfig::SECRET PkgConfig::DBUS)
endif()

install(FILES
    include/safekeeping/SafeKeeping.h
    DESTINATION include/safekeeping
)

install(TARGETS safekeeping
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

if(SAFEKEEPING_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
