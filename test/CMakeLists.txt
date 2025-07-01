# basic
add_executable(test_dilithium ${CMAKE_CURRENT_SOURCE_DIR}/test_dilithium.c)
target_link_libraries(test_dilithium dilithium)

# sign and verify
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/pem)
add_executable(test_sign ${CMAKE_CURRENT_SOURCE_DIR}/test_sign.c)
target_link_libraries(test_sign dilithium)

# openssl + liboqs
add_executable(test_pem ${CMAKE_CURRENT_SOURCE_DIR}/pem/test_pem.c)
target_link_libraries(test_pem dilithium)

# bench
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/benchmark)
add_executable(test_sign_bench  ${CMAKE_CURRENT_SOURCE_DIR}/benchmark/speed_print.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/benchmark/test_sign_bench.c)
target_link_libraries(test_sign_bench dilithium)