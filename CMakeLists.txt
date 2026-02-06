cmake_minimum_required(VERSION 3.10)
project(dagger C)

set(CMAKE_C_STANDARD 11)

include(FetchContent)

FetchContent_Declare(
        sha256
        GIT_REPOSITORY https://github.com/B-Con/crypto-algorithms.git
        GIT_TAG master
)
FetchContent_MakeAvailable(sha256)

FetchContent_Declare(
        uthash
        GIT_REPOSITORY https://github.com/troydhanson/uthash.git
        GIT_TAG master
)
FetchContent_MakeAvailable(uthash)

add_library(dagger
        src/ring_slab.c
        src/arena.c
        src/merkle_dag.c
        ${sha256_SOURCE_DIR}/sha256.c
        src/dag_serial.c
        src/dag_serial.h
        src/gossip.c
)

target_include_directories(dagger PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${sha256_SOURCE_DIR}
        ${uthash_SOURCE_DIR}/src
)

#