cmake_minimum_required(VERSION 3.10.2)
project(sa_sdk_cpp)

set(CMAKE_CXX_STANDARD 11)

include_directories(include)

# add_library(sensors_analytics_sdk_shared SHARED src/sensors_analytics_sdk.cpp)
add_library(sensors_analytics_sdk_static STATIC src/sensors_analytics_sdk.cpp)

# target_link_libraries(sensors_analytics_sdk_shared curl z)
target_link_libraries(sensors_analytics_sdk_static curl z)

add_executable(demo demo.cpp)
target_link_libraries(demo curl z sensors_analytics_sdk_static)
