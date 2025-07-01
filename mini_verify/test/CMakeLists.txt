# openssl + liboqs
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_pem ${CMAKE_CURRENT_SOURCE_DIR}/test_pem.c)
target_link_libraries(test_pem dilithium)