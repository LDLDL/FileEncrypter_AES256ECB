cmake_minimum_required(VERSION 3.16)
project(FileEncrypter)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

include_directories(${GTK3_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS})

add_executable(FileEncrypter FileEncrypter.cpp sha256.cpp sha256.h pbkdf2.cpp pbkdf2.h aes256.cpp aes256.h file.cpp file.h)

target_link_libraries(FileEncrypter ${GTK3_LINK_LIBRARIES})