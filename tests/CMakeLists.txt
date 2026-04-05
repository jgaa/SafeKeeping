cmake_minimum_required(VERSION 3.20)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(test_reboot test-reboot.cpp)
target_link_libraries(test_reboot PRIVATE safekeeping GTest::GTest GTest::Main Threads::Threads)

add_test(NAME TestReboot COMMAND test_reboot)

include(GoogleTest)
gtest_discover_tests(test_reboot)
