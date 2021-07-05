cmake_minimum_required(VERSION 3.12)

project(tiny-cpp-blockchain CXX C)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include_directories(
	src
	deps/src/sha2
)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-DSHA2_USE_INTTYPES_H)
add_definitions(-DLITTLE_ENDIAN=1234)
add_definitions(-DBYTE_ORDER=1234)

set(SRC_FILES
	src/main.cpp
	deps/src/sha2/sha2.c
)

set(HEADER_FILES
)

add_executable(tiny-cpp-blockchain
	${SRC_FILES}
	${HEADER_FILES}
)

set_property(TARGET tiny-cpp-blockchain PROPERTY CXX_STANDARD 20)
set_property(TARGET tiny-cpp-blockchain PROPERTY CXX_STANDARD_REQUIRED ON)
