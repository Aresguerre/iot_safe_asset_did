cmake_minimum_required(VERSION 3.9)


# project(crypt)
# add_subdirectory($ENV{MIDDLEWARE})
# add_executable(crypt crypto.c)
# target_include_directories(crypt PUBLIC "$ENV{MIDDLEWARE}/driver/inc")
# target_link_directories(crypt PUBLIC "$ENV{MIDDLEWARE}/driver/lib/armv7l")
# target_link_libraries(crypt driver)

project(cryptosafe)
add_subdirectory($ENV{MIDDLEWARE})
ADD_LIBRARY(cryptosafe SHARED crypto.c)
target_include_directories(cryptosafe PUBLIC "$ENV{MIDDLEWARE}/driver/inc")
target_link_directories(cryptosafe PUBLIC "$ENV{MIDDLEWARE}/driver/lib/armv7l")
target_link_libraries(cryptosafe driver)