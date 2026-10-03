cmake_minimum_required(VERSION 3.20)
project(safekeeping VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SAFEKEEPING_BUILD_TESTS "Build the tests" ON)
option(SAFEKEEPING_ENABLE_KWALLET "Enable the Linux KWallet system-vault backend" ON)

set(SAFEKEEPING_SOURCES
    include/safekeeping/SafeKeeping.h
)

if(ANDROID)
    list(APPEND SAFEKEEPING_SOURCES src/SafeKeepingAndroid.cpp)
    set(SAFEKEEPING_BUILD_TESTS OFF CACHE BOOL "Build the tests" FORCE)
else()
    list(APPEND SAFEKEEPING_SOURCES src/SafeKeeping.cpp)

    find_package(SQLite3 REQUIRED)

    if(NOT TARGET SQLite3::SQLite3 AND TARGET SQLite::SQLite3)
        add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
    endif()

    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)

    if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "libsodium was not found")
    endif()
endif()

add_library(safekeeping STATIC
    ${SAFEKEEPING_SOURCES}
)

target_include_directories(safekeeping
    PUBLIC
        include
    PRIVATE
        src
)

if(NOT ANDROID)
    target_include_directories(safekeeping PRIVATE ${SODIUM_INCLUDE_DIR})
    target_link_libraries(
        safekeeping
        PRIVATE
            ${SODIUM_LIBRARY}
            SQLite3::SQLite3
    )
endif()

if(WIN32)
    target_link_libraries(safekeeping PRIVATE Advapi32)
elseif(APPLE)
    target_link_libraries(
        safekeeping
        PRIVATE
            "-framework Security"
            "-framework CoreFoundation"
    )
elseif(UNIX AND NOT ANDROID)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SECRET REQUIRED IMPORTED_TARGET libsecret-1)
    target_link_libraries(safekeeping PRIVATE PkgConfig::SECRET)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND SAFEKEEPING_ENABLE_KWALLET)
        find_package(Qt6 QUIET COMPONENTS Core)
        if(Qt6Core_FOUND)
            find_package(KF6Wallet QUIET CONFIG)
        endif()

        if(Qt6Core_FOUND AND KF6Wallet_FOUND AND TARGET KF6::Wallet)
            target_link_libraries(safekeeping PRIVATE KF6::Wallet)
            target_compile_definitions(safekeeping PRIVATE SAFEKEEPING_ENABLE_KWALLET=1)
            message(NOTICE "Compiling with KWallet backend available when the KDE desktop is used")
        else()
            message(WARNING "SAFEKEEPING_ENABLE_KWALLET is ON, but Qt6/KF6Wallet development files were not found. Building without KWallet support.")
        endif()
    endif()
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
