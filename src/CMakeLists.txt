set(dilithium_PRIVATE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(dilithium_PUBLIC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_library(dilithium STATIC ${CMAKE_CURRENT_SOURCE_DIR}/sign.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/packing.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/polyvec.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/poly.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/ntt.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/reduce.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/rounding.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/fips202.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/symmetric-shake.c 
                             ${CMAKE_CURRENT_SOURCE_DIR}/randombytes.c)

target_include_directories(dilithium    PRIVATE ${dilithium_PRIVATE_INCLUDE_DIR}
                                        PUBLIC ${dilithium_PUBLIC_INCLUDE_DIR})