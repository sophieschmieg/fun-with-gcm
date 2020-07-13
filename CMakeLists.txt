cmake_minimum_required(VERSION 3.5)
project(FunWithGCM CXX)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(third_party/tink)
add_library(gf2_128_polyval gf2_128_polyval.cc)
add_executable(fun_with_gcm_siv fun_with_gcm_siv.cc)
target_link_libraries(fun_with_gcm_siv tink::static)
target_link_libraries(fun_with_gcm_siv gf2_128_polyval)
