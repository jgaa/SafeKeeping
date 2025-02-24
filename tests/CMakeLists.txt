cmake_minimum_required(VERSION 3.10)
project(SafeKeepingTests)

# Enable testing
enable_testing()

# Find Google Test
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Add the test executable
add_executable(test_vault test-vault.cpp)

# Link Google Test 
target_link_libraries(test_vault PRIVATE safekeeping GTest::GTest GTest::Main Threads::Threads)

# Add the test to CTest
add_test(NAME TestVault COMMAND test_vault)


## ========

# Add the test executable
add_executable(test_filestorage test-filestorage.cpp)

# Link Google Test
target_link_libraries(test_filestorage PRIVATE safekeeping GTest::GTest GTest::Main Threads::Threads)

# Add the test to CTest
add_test(NAME TestFileStorage COMMAND test-filestorage)


include(GoogleTest)
gtest_discover_tests(test_vault)
gtest_discover_tests(test_filestorage)