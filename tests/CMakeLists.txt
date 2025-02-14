cmake_minimum_required(VERSION 3.10)
project(SafeKeepingTests)

# Enable testing
enable_testing()

# Find Google Test
find_package(GTest REQUIRED)

# Add the test executable
add_executable(test-vault test-vault.cpp)

# Link Google Test and pthread
target_link_libraries(test-vault PRIVATE safekeeping GTest::GTest GTest::Main pthread)

# Add the test to CTest
add_test(NAME TestVault COMMAND test-vault)


## ========

# Add the test executable
add_executable(test-filestorage test-filestorage.cpp)

# Link Google Test and pthread
target_link_libraries(test-filestorage PRIVATE safekeeping GTest::GTest GTest::Main pthread)

# Add the test to CTest
add_test(NAME TestFileStorage COMMAND test-filestorage)
