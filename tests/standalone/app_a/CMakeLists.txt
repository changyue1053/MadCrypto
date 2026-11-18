cmake_minimum_required(VERSION 3.16)
project(MadCryptoAppA C)
find_package(MadCrypto CONFIG REQUIRED)
find_package(MadCrypto CONFIG REQUIRED) # repeated same package is idempotent
add_executable(app_a main.c)
target_compile_options(app_a PRIVATE -Wall -Wextra -Werror)
target_link_libraries(app_a PRIVATE MadCrypto::MadCrypto)
enable_testing()
add_test(NAME independent_app_a COMMAND app_a)
