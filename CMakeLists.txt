cmake_minimum_required(VERSION 2.8.12.2)
project(sa_sdk_cpp)

add_compile_options(-std=c++98)
set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

# add_library(sensors_analytics_sdk_shared SHARED src/sensors_analytics_sdk.cpp)
add_library(sensors_analytics_sdk_static STATIC src/sensors_analytics_sdk.cpp src/sensors_network.cpp src/sensors_utils.cpp)

# target_link_libraries(sensors_analytics_sdk_shared curl z)
target_link_libraries(sensors_analytics_sdk_static curl z)

add_executable(demo demo.cpp)
target_link_libraries(demo curl z sensors_analytics_sdk_static)
