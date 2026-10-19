cmake_minimum_required(VERSION 3.20)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(test_reboot test-reboot.cpp)
target_link_libraries(test_reboot PRIVATE safekeeping GTest::GTest GTest::Main Threads::Threads)
if(SAFEKEEPING_ENABLE_KWALLET)
    target_compile_definitions(test_reboot PRIVATE SAFEKEEPING_ENABLE_KWALLET=1)
endif()

add_test(NAME TestReboot COMMAND test_reboot)

include(GoogleTest)
gtest_discover_tests(test_reboot)

# Fault injection at the SQLite boundary verifies read-back handling without
# exposing fault controls in the production library.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(test_reboot PRIVATE SAFEKEEPING_WRAP_SQLITE_STEP=1)
    target_link_options(test_reboot PRIVATE -Wl,--wrap=sqlite3_step)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TARGET KF6::Wallet)
    find_package(Qt6 QUIET COMPONENTS Test DBus)
    find_program(DBUS_RUN_SESSION dbus-run-session)
    if(TARGET Qt6::Test AND TARGET Qt6::DBus AND DBUS_RUN_SESSION)
        add_executable(test_kwallet test-kwallet.cpp)
        set_target_properties(test_kwallet PROPERTIES AUTOMOC ON)
        target_link_libraries(test_kwallet PRIVATE safekeeping Qt6::Test Qt6::DBus)
        add_test(NAME KWalletPrivateBus COMMAND ${DBUS_RUN_SESSION} -- $<TARGET_FILE:test_kwallet>)
        set_tests_properties(KWalletPrivateBus PROPERTIES ENVIRONMENT "SAFEKEEPING_PRIVATE_TEST_BUS=1")
    endif()
endif()
